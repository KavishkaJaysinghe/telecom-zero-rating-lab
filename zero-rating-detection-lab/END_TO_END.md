# End-to-End Process — Zero-Rating Bypass Detection Lab

**A complete trace of what happens, in what order, from the moment a request is generated to the moment a charging verdict is written to disk.**

> **LAB / EDUCATIONAL.** Simplified reference model built from public 3GPP concepts. Not any operator's production system. Every address is loopback or RFC 5737 documentation space; the demo emits zero DNS queries and zero external packets. See [README.md](README.md) for scope, standards context, responsible-use terms, and how to report real-world abuse.

This document is the *process* companion to the README. The README explains **why** the design is what it is; this explains **what executes, in what order**. Every log line quoted here is copied verbatim from a real run, not illustrative.

---

## Table of contents

1. [Cast of components](#1-cast-of-components)
2. [The pipeline at a glance](#2-the-pipeline-at-a-glance)
3. [Stage-by-stage walkthrough](#3-stage-by-stage-walkthrough)
4. [Life of a flow: all five scenarios traced](#4-life-of-a-flow-all-five-scenarios-traced)
5. [Hook timing reference](#5-hook-timing-reference)
6. [Decision matrix](#6-decision-matrix)
7. [The evidence trail](#7-the-evidence-trail)
8. [Full run transcript, in order](#8-full-run-transcript-in-order)
9. [Reproduction checklist](#9-reproduction-checklist)

---

## 1. Cast of components

| Component | Process | Role in the pipeline |
| --------- | ------- | -------------------- |
| `local_test_server.py` | own process, 4 threads | The origin. Serves a fixed 64 KiB payload on two loopback addresses. Models "the internet". |
| `attacker_client.py` | own process, short-lived | The subscriber's device. Generates honest and spoofed requests. Models the UE. |
| `classifier_naive.py` | mitmdump addon | Phase 1 classifier + meter. Models a PCEF that trusts claimed hostnames. |
| `detector.py` | mitmdump addon | Phase 2 classifier + meter + enforcement. Models a PCEF that cross-validates. |
| `charging.py` | imported by both | The Gy-style credit meter. Identical code in both phases, so only classification differs. |
| `dns_fixtures.json` | read by detector | Offline resolver. Ground truth for "where does this hostname really live". |
| `demo_report.py` | own process, at the end | Reads the evidence files, renders the before/after summary. |

Two loopback addresses carry the entire demonstration:

```
  127.0.0.2  = the GENUINE zero-rated service    (dns_fixtures maps zoom.us here)
  127.0.0.1  = ordinary chargeable content       (where the spoofing client really goes)
```

That split is what makes "claimed zoom.us, actually reached 127.0.0.1" a real, checkable mismatch without a single packet leaving the machine.

---

## 2. The pipeline at a glance

```
 [1] GENERATE          attacker_client.py
      |                 builds a request where the CLAIMED identity and the
      |                 ACTUAL destination are set independently
      v
 [2] INTERCEPT         mitmdump (proxy)
      |                 hands the flow to whichever addon is loaded
      v
 [3] EXTRACT CLAIM     Host: header (plaintext)  /  TLS SNI (encrypted)
      |
      v
 [4] FIND REAL DEST    server_conn.peername -> server_conn.address -> request.host
      |                 (never the Host header - that IS the claim)
      v
 [5] POLICY LOOKUP     is the claimed host on the zero-rating whitelist?
      |
      +---- no  -----> charge at standard rate. Done. No validation needed.
      |
      v yes
 [6] CROSS-VALIDATE    detector.py only
      |                 resolve(claimed_host) -> set of legitimate IPs
      |                 is the real destination in that set?
      |
      +---- yes -----> [7a] ZERO-RATE   charge 0
      +---- no  -----> [7b] ENFORCE     log finding + drop flow
      |
      v
 [8] METER             charging.py: decrement balance, track rating-groups,
      |                 emit CCR-I / CCR-U / CCR-T lifecycle events
      v
 [9] EMIT EVIDENCE     JSON Lines -> logs/*.jsonl  +  meter report -> logs/*.json
      |
      v
[10] REPORT            demo_report.py reads the evidence, renders before/after
```

Stage 6 is the entire difference between the two phases. `classifier_naive.py` jumps straight from [5] to [7a] — it never asks where the packets are going.

---

## 3. Stage-by-stage walkthrough

### Stage 0 — Bootstrap (`run_demo.sh` / `run_demo.ps1`)

1. Resolve the interpreter, preferring `.venv/` (Windows `Scripts/`, POSIX `bin/`).
2. Read the topology from `lab_config.py` — the shell never hardcodes a port.
3. Wipe `logs/` so each run produces clean evidence.
4. **Pre-flight the ports.** Attempt to bind all five listeners. If any is busy, name it and print the override env vars. The defaults are `18080/18443/18081` precisely because `8080`/`8443`/`8081` collide with a running web server on many developer machines.
5. Start `local_test_server.py`; wait for the listeners to accept connections before sending any traffic.

On first run the origin mints a throwaway self-signed certificate into `certs/`, with SANs covering the loopback IPs and the zero-rated hostnames so that a client presenting a spoofed SNI still completes a handshake.

### Stage 1 — Traffic generation (`attacker_client.py`)

Every target passes `assert_loopback()` before a socket opens. It refuses anything outside `127.0.0.0/8` and has no override flag.

The harness uses **raw sockets**, not `requests` or `urllib`, for one reason: those libraries derive the `Host` header and the SNI *from the URL*. That coupling is exactly what an attacker breaks, so reproducing the attack requires setting the two fields independently.

**Plaintext spoof** — absolute-form request line carries the true destination, the `Host` header carries the lie:

```http
GET http://127.0.0.1:18080/content HTTP/1.1
Host: zoom.us
```

**TLS spoof** — CONNECT to the true destination, then choose the SNI freely:

```python
sock.sendall(b"CONNECT 127.0.0.1:18443 HTTP/1.1\r\n...")
tls_sock = ctx.wrap_socket(sock, server_hostname="zoom.us")   # <-- the SNI
```

### Stage 2 — Interception

`mitmdump` runs with `--set connection_strategy=eager`, so the upstream connection is established before the request hook fires and the real destination is known at decision time.

The proxy is a **lab observation device**. On a real gateway the destination is simply the IP header's destination field, with no request-line indirection to reason about — the mismatch is even easier to see there, not harder.

### Stage 3 — Extract the claimed identity

| Flow type | Source | Where |
| --------- | ------ | ----- |
| Plaintext | `request.host_header` | `detector.py` → `request()` |
| Encrypted | `client_conn.sni`, captured at ClientHello | `detector.py` → `tls_clienthello()` |

Both are client-supplied and unauthenticated. mitmproxy's own API docs warn that `Request.pretty_host` may not reflect the actual destination in adversarial environments, because the `Host` header can be spoofed.

### Stage 4 — Determine the real destination

`detector._real_ip()` tries three sources, most authoritative first:

1. `server_conn.peername` — the true socket peer. Definitive.
2. `server_conn.address` — what mitmproxy was asked to reach. Set for CONNECT tunnels.
3. `request.host` / `request.port` — the request-line authority.

**The critical distinction:** `request.host` is the routing target; `request.host_header` and `pretty_host` are the *claim*. Confusing the two makes the detector compare the claim against itself and pass everything.

This was a real bug during development. It caused the legitimate zero-rated flow to be misflagged *and* dropped the HTTP spoof's confidence from HIGH to MEDIUM — a single wrong field degraded both directions at once.

### Stage 5 — Policy lookup

`lab_config.is_zero_rated()` checks the whitelist, with optional subdomain matching (`ZERO_RATE_MATCH_SUBDOMAINS`, on by default — operators do this, and it widens the spoofing surface).

**A claim that is not zero-rated skips validation entirely.** There is no incentive to spoof a hostname that gets billed normally, so the expensive path stays off the overwhelming majority of traffic. This is visible in the evidence: the `legit-charged` flow produces **no** `dns_resolution` event.

### Stage 6 — Cross-validate (detector only)

`CrossValidator.evaluate()` resolves the claimed host and compares:

- **exact** — destination is in the resolved set → valid.
- **prefix** — destination shares a network prefix with a resolved address (`PREFIX_TOLERANCE_BITS_V4 = 24`) → valid, CDN edge rotation tolerated. *Deliberately not applied to loopback/RFC1918 destinations:* that tolerance exists to excuse CDN churn on public address space, and stretching it onto private space would only launder attacks.
- **none** → mismatch, proceed to confidence scoring.

Resolution uses `dns_fixtures.json` (`RESOLVER_MODE=fixture`), so the lab is deterministic and emits no DNS traffic. A 60-second TTL cache means repeated claims for the same host resolve once — in the captured run, **four zero-rated claims produced exactly one `dns_resolution` event**.

Failure to resolve is **never** treated as evidence of fraud. It returns `ZERO_RATING_UNVERIFIABLE` at LOW confidence and the flow is allowed through.

### Stage 7 — Enforcement

Only HIGH confidence is enforced (`DROP_ON_CONFIDENCE`). MEDIUM and LOW findings are logged for offline revenue-assurance review and allowed through, because blocking on ambiguous evidence breaks paying customers — which costs more than the fraud does.

Two modes (`ZRLAB_ENFORCEMENT`):

- `kill` (default) — `flow.kill()`, models a PCEF gate-close. The client sees a connection teardown.
- `block403` — synthesises a JSON 403. Easier to screenshot from the client side.

**Detection and enforcement are split for TLS.** The bypass is *detected* at the ClientHello, before any application data flows, but mitmproxy's `tls_clienthello` hook has no teardown primitive — so the drop is applied at the first request inside the tunnel. A real PCEF has the same two-phase shape for a different reason: it classifies on the ClientHello, then applies gate-status to subsequent packets of that service data flow.

A blocked flow never reaches the meter (`flow.metadata["zrlab_blocked"]`), so the subscriber is not billed for the rejection notice and the flow is not double-counted in the report.

### Stage 8 — Metering (`charging.py`)

Volume is counted as response status line + headers + body. The meter tracks a balance, grants quota in chunks, and emits the Gy session lifecycle:

| Event | When | Seen in the captured run? |
| ----- | ---- | ------------------------- |
| `gy_ccr_initial` (CCR-I) | addon start | Yes — grants 262,144 bytes |
| `gy_ccr_update` (CCR-U) | granted quota exhausted | **No** — only 65,743 bytes were charged, well under the grant |
| `gy_ccr_terminate` (CCR-T) | graceful shutdown | Yes — both phases, both platforms |

The absence of CCR-U is correct behaviour, not a gap: a single chargeable flow never exhausts a 256 KiB grant. To see the CCR-U path fire, lower `QUOTA_GRANT_BYTES` in `lab_config.py` below the per-flow volume.

### Stage 9 — Evidence emission

Every component writes JSON Lines through `logging_util.py`. Bare `print()` is not used anywhere in the project. The meter report is rewritten after *every* flow, not just at shutdown, so evidence survives an abrupt kill.

### Stage 10 — Reporting

`demo_report.py` reads only the JSONL evidence — nothing is recomputed — so the summary cannot drift from what the addons actually decided. It derives the "spoofed" column from `dns_fixtures.json` (lab ground truth) rather than from either addon's opinion, which is what lets it score the naive phase as *wrong* rather than simply reprinting the naive phase's own verdicts.

---

## 4. Life of a flow: all five scenarios traced

Each scenario runs twice — once per phase — with identical client behaviour.

### Scenario 1: `legit-charged`

Honest request for ordinary content.

| Claimed | Real dest | Naive verdict | Detector verdict |
|---------|-----------|---------------|------------------|
| `lab-origin.local` | `127.0.0.1` | `CHARGED` 64.2 KiB | `CHARGED_NORMAL` 64.2 KiB |

Both phases agree. The detector performs **no DNS resolution** — the claim is not zero-rated, so there is nothing worth lying about. This is the fast path that carries most real traffic.

### Scenario 2: `legit-zerorated`

Honest plaintext request to the genuine zero-rated service.

| Claimed | Real dest | Naive verdict | Detector verdict |
|---------|-----------|---------------|------------------|
| `zoom.us` | `127.0.0.2` | `ZERO-RATED` 0 B | `ZERO_RATED_VALID` 0 B |

The detector resolves `zoom.us` to `{127.0.0.2, 203.0.113.10, .11, .12}` and finds `127.0.0.2` **in** the set — exact match, zero-rate.

**This is the false-positive test.** A detector that breaks this flow would break the free tier it exists to protect.

### Scenario 3: `spoof-http` — THE ATTACK

Same request as scenario 1, but the `Host` header claims `zoom.us`.

| Claimed | Real dest | Naive verdict | Detector verdict |
|---------|-----------|---------------|------------------|
| `zoom.us` | `127.0.0.1` | `ZERO-RATED` 0 B **(leak)** | `DROPPED` (HIGH) |

*Naive:* hostname matches the whitelist, 0 bytes charged. 64.2 KiB of billable traffic delivered free.

*Detector:* `127.0.0.1` is not in the resolved set, and is not publicly routable — no public zero-rated service can live on loopback. Two independent signals, HIGH confidence, dropped at `detection_point=http_request`.

### Scenario 4: `legit-zerorated-tls`

Honest TLS request to the genuine zero-rated service.

| Claimed | Real dest | Naive verdict | Detector verdict |
|---------|-----------|---------------|------------------|
| `zoom.us` (SNI) | `127.0.0.2` | `ZERO-RATED` 0 B | `ZERO_RATED_VALID` 0 B |

The second false-positive test, over the encrypted path. The resolver answers from cache — no second `dns_resolution` event.

### Scenario 5: `spoof-tls` — THE ATTACK, ENCRYPTED

CONNECT to `127.0.0.1:18443`, SNI set to `zoom.us`.

| Claimed | Real dest | Naive verdict | Detector verdict |
|---------|-----------|---------------|------------------|
| `zoom.us` (SNI) | `127.0.0.1` | `ZERO-RATED` 0 B **(leak)** | `DROPPED` (HIGH) |

Note the detection point: **`tls_clienthello`**, not `http_request`. The bypass is caught from the ClientHello alone, before one byte of application data moves. Encryption gives the attacker no cover here, because SNI is sent in the clear precisely so intermediaries can route on it.

---

## 5. Hook timing reference

**Plaintext flow:**

```
  client connects to proxy
    -> request()          claim extracted, destination determined, verdict decided
                          (detector: enforcement applied here if HIGH)
    -> [upstream fetch]
    -> response()         volume metered, charging_decision logged
```

**TLS flow through CONNECT:**

```
  client sends CONNECT
    -> http_connect()     tunnel target known; SNI NOT yet visible
  client sends ClientHello
    -> tls_clienthello()  SNI visible -> DETECTION HAPPENS HERE
                          verdict stashed against the client connection id
  TLS handshake completes; client sends the inner request
    -> request()          re-evaluated with the inner Host header available;
                          ENFORCEMENT applied here
    -> response()         volume metered (skipped entirely if blocked)
```

The re-evaluation at `request()` is not redundant: it is the only point where the SNI and the inner `Host` header can be compared against **each other**. A disagreement means the client told two different stories about one connection, and promotes the finding to HIGH.

---

## 6. Decision matrix

| Claimed host | Resolvable? | Dest in resolved set? | Dest routable? | Verdict | Confidence | Action |
| ------------ | ----------- | --------------------- | -------------- | ------- | ---------- | ------ |
| not zero-rated | not checked | not checked | — | `CHARGED_NORMAL` | NONE | charge |
| zero-rated | yes | exact match | — | `ZERO_RATED_VALID` | NONE | charge 0 |
| zero-rated | yes | same prefix (/24) | yes | `ZERO_RATED_VALID` | NONE | charge 0 |
| zero-rated | yes | no | **no** | `BYPASS_SUSPECTED` | **HIGH** | **DROP** |
| zero-rated | yes | no | yes | `BYPASS_SUSPECTED` | MEDIUM | log only |
| zero-rated | any | any | any | + SNI/Host contradiction | **HIGH** | **DROP** |
| zero-rated | no | — | — | `ZERO_RATING_UNVERIFIABLE` | LOW | allow + flag |

---

## 7. The evidence trail

| File | Written by | Contents |
| ---- | ---------- | -------- |
| `logs/local_test_server.jsonl` | origin | listener startup, cert generation, per-request records |
| `logs/attacker_client.jsonl` | harness | what was sent, what came back, both phases (append mode) |
| `logs/classifier_naive.jsonl` | phase 1 addon | Gy lifecycle + every charging decision |
| `logs/detector.jsonl` | phase 2 addon | same, plus alerts and drops |
| `logs/detector_findings.jsonl` | phase 2 addon | findings only — the revenue-assurance feed |
| `logs/naive_meter_report.json` | phase 1 addon | final meter snapshot |
| `logs/detector_report.json` | phase 2 addon | final meter snapshot + block counts |

**The naive classifier convicting itself** — `real_ip` is present in its own log line, observed and then ignored:

```json
{"level":"ZERORATE","event":"charging_decision","verdict":"ZERO-RATED",
 "charged_bytes":0,"claimed_host":"zoom.us","real_ip":"127.0.0.1",
 "transport":"HTTP/Host","volume_bytes":65743,"rating_group":100,
 "reason":"claimed hostname matched zero-rating whitelist"}
```

**The detector's finding** for that same flow:

```json
{"level":"ALERT","event":"zero_rating_bypass_detected","claimed_host":"zoom.us",
 "real_host":"127.0.0.1","real_ip":"127.0.0.1",
 "resolved_ips":["127.0.0.2","203.0.113.10","203.0.113.11","203.0.113.12"],
 "transport":"HTTP/Host","verdict":"BYPASS_SUSPECTED","confidence":"HIGH",
 "signals":["claimed_host_resolves_elsewhere","destination_not_publicly_routable"],
 "detection_point":"http_request","action":"DROP","rating_group_claimed":100}
```

---

## 8. Full run transcript, in order

Event sequence from a real run. Phase 1 (`classifier_naive.jsonl`):

```
INFO     addon_started
INFO     gy_ccr_initial          granted=262144  balance=1048576
CHARGE   charging_decision       lab-origin.local -> 127.0.0.1  CHARGED     65743 B
ZERORATE charging_decision       zoom.us          -> 127.0.0.2  ZERO-RATED      0 B
ZERORATE charging_decision       zoom.us          -> 127.0.0.1  ZERO-RATED      0 B   <-- LEAK
DEBUG    tls_clienthello_seen
ZERORATE charging_decision       zoom.us          -> 127.0.0.2  ZERO-RATED      0 B
DEBUG    tls_clienthello_seen
ZERORATE charging_decision       zoom.us          -> 127.0.0.1  ZERO-RATED      0 B   <-- LEAK
INFO     lab_control_shutdown
INFO     gy_ccr_terminate        used=65743  balance=982833
INFO     addon_stopped
```

Phase 2 (`detector.jsonl`) — same five flows, same client behaviour:

```
INFO     addon_started
INFO     gy_ccr_initial          granted=262144  balance=1048576
CHARGE   charging_decision       lab-origin.local -> 127.0.0.1  CHARGED_NORMAL   65743 B
DEBUG    dns_resolution                                                  <-- ONCE, then cached
ZERORATE charging_decision       zoom.us          -> 127.0.0.2  ZERO_RATED_VALID     0 B
ALERT    zero_rating_bypass_detected   zoom.us -> 127.0.0.1  HIGH  at http_request
ALERT    flow_dropped                  zoom.us -> 127.0.0.1  DROPPED
ZERORATE charging_decision       zoom.us          -> 127.0.0.2  ZERO_RATED_VALID     0 B
ALERT    zero_rating_bypass_detected   zoom.us -> 127.0.0.1  HIGH  at tls_clienthello
ALERT    flow_dropped                  zoom.us -> 127.0.0.1  DROPPED
INFO     lab_control_shutdown
INFO     gy_ccr_terminate        used=65743  balance=982833
INFO     addon_stopped
```

Three things to notice in phase 2:

1. **One `dns_resolution` for four zero-rated claims** — the TTL cache working.
2. **No `dns_resolution` before the first flow** — non-zero-rated claims skip validation entirely.
3. **Different detection points** — `http_request` for the plaintext spoof, `tls_clienthello` for the encrypted one. The encrypted bypass is caught earlier in the connection's life than the plaintext one.

### Stopping cleanly

Both addons are stopped by an in-band control request (`GET http://zrlab.control/shutdown`), not a signal. Signal delivery to a child process differs across bash, Git Bash and PowerShell, and an addon killed before `done()` runs would never write its final CCR-T. Going in-band makes teardown identical everywhere — `gy_ccr_terminate` is present on both Windows and Linux.

---

## 9. Reproduction checklist

```bash
python -m venv .venv && ./.venv/bin/pip install -r requirements.txt && bash run_demo.sh
```

Verified identical on Windows 11 (Python 3.13, mitmproxy 12.2.3) and Ubuntu 24.04.

**Expected outcomes** — all ten scenario runs should match:

| Scenario | Phase 1 outcome | Phase 2 outcome |
| -------- | --------------- | --------------- |
| `legit-charged` | SERVED, charged | SERVED, charged |
| `legit-zerorated` | SERVED, free | SERVED, free |
| `spoof-http` | SERVED, free (leak) | **DROPPED** |
| `legit-zerorated-tls` | SERVED, free | SERVED, free |
| `spoof-tls` | SERVED, free (leak) | **DROPPED** |

**Expected totals:**

```
  leakage prevented   : 128.4 KiB  (100% of the attempted bypass)
  false positives     : 0   (out of 2 genuine zero-rated flow(s) offered)
  free tier preserved : 2 flow(s), 128.4 KiB correctly still waived
```

**Verification commands:**

```bash
grep -c gy_ccr_terminate logs/detector.jsonl logs/classifier_naive.jsonl
```

Expect `1` and `1` — the Gy session lifecycle completed in both phases.

```bash
grep -c zero_rating_bypass_detected logs/detector_findings.jsonl
```

Expect `2` — one plaintext bypass, one encrypted.

If a scenario reports `PROXY_UNAVAILABLE`, the harness never reached the proxy and nothing was classified. That is a lab setup failure, deliberately *not* reported as `DROPPED`, so a broken run can never be mistaken for a successful detection.

---

*Companion to [README.md](README.md). Defensive by design, local by construction.*

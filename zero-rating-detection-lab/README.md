# Zero-Rating Bypass Detection Lab

**A defensive, standards-based reference model for detecting zero-rating fraud in an Online Charging System (OCS) context.**

---

> ### ⚠️ Scope and safety — read first
>
> * This is a **LAB / EDUCATIONAL** project. It is a **simplified reference model built from public 3GPP concepts**, not any operator's production system, not a product, and not a description of how any particular network is implemented.
> * It contains **no real operator data**. Every address used is either loopback (`127.0.0.0/8`) or an RFC 5737 documentation prefix. The subscriber identifiers are fictional and use the MCC `999` test range.
> * It runs **entirely on one machine**. The demo binds only loopback addresses, resolves hostnames from a local JSON fixture, and emits **zero DNS queries and zero external packets**. It never touches, probes, or depends on a real carrier network.
> * The included attack harness (`attacker_client.py`) exists **only to validate the detector**. It has a hard-coded, non-overridable interlock that refuses any target outside `127.0.0.0/8`. See [Responsible use](#responsible-use) and [Reporting real-world abuse](#reporting-real-world-abuse).

---

## What this demonstrates

Operators zero-rate certain traffic — a partner video service, an education portal, an emergency-information site — so it does not decrement the subscriber's data balance. To do that, something in the network has to answer the question *"which service is this flow?"*, and the cheapest available answer is the **hostname the client claims**:

| Transport | Where the classifier reads the hostname |
| --------- | --------------------------------------- |
| Plaintext HTTP | the `Host:` request header |
| HTTPS | the **SNI** (Server Name Indication) field of the TLS ClientHello |

Both are **client-supplied strings, and neither is authenticated**. A subscriber who writes `Host: zoom.us` on traffic that is actually going somewhere else gets that traffic charged at zero. That is the bypass. At scale it is straightforward revenue leakage, and it is a real category of telecom fraud.

This lab shows the problem and the fix side by side:

```
  PHASE 1 - NAIVE CLASSIFIER   (trusts the claimed Host / SNI)
  CLAIMED HOST       ACTUAL DEST     TRANSPORT  VERDICT            CHARGED
  lab-origin.local   127.0.0.1       HTTP/Host  CHARGED           64.2 KiB
  zoom.us            127.0.0.2       HTTP/Host  ZERO-RATED             0 B
  zoom.us            127.0.0.1       HTTP/Host  ZERO-RATED             0 B  <== REVENUE LEAK: spoof believed
  zoom.us            127.0.0.2       TLS/SNI    ZERO-RATED             0 B
  zoom.us            127.0.0.1       TLS/SNI    ZERO-RATED             0 B  <== REVENUE LEAK: spoof believed

  PHASE 2 - CROSS-VALIDATING DETECTOR   (claim checked against real dest IP)
  lab-origin.local   127.0.0.1       HTTP/Host  CHARGED           64.2 KiB
  zoom.us            127.0.0.2       HTTP/Host  ZERO-RATED             0 B
  zoom.us            127.0.0.1       HTTP/Host  DROPPED                0 B  <== BLOCKED (HIGH)
  zoom.us            127.0.0.2       TLS/SNI    ZERO-RATED             0 B
  zoom.us            127.0.0.1       TLS/SNI    DROPPED                0 B  <== BLOCKED (HIGH)
```

Same five flows, same charging code, one changed input to the classification decision.

> For a stage-by-stage trace of the whole pipeline — hook order, decision logic,
> and every scenario followed end to end — see **[END_TO_END.md](END_TO_END.md)**.

---

## Where this sits in the charging pipeline

In a 3GPP packet core, traffic classification is the front of the charging chain, and everything downstream inherits its mistakes:

```
   UE / subscriber
        |
        |  service data flows
        v
  +--------------------------------------------------+
  |  Packet gateway  (PGW-C/U, or SMF + UPF in 5G)   |
  |                                                  |
  |   [ 1 ] TRAFFIC CLASSIFICATION  <-- attacked here|
  |         match flow against PCC rules             |
  |         (hostname / SNI / 5-tuple / app-ID)      |
  |            |                                     |
  |            v                                     |
  |   [ 2 ] RATING-GROUP ASSIGNMENT                  |
  |         zero-rated RG (0-rate)  or  standard RG  |
  |            |                                     |
  |            v                                     |
  |   [ 3 ] PCEF METERING + GATING                   |
  |         count octets per rating-group            |
  +--------------------------------------------------+
        |                              ^
        |  Diameter Gy                 |  quota grants
        |  CCR-I / CCR-U / CCR-T       |  CCA
        v                              |
  +--------------------------------------------------+
  |  OCS — Online Charging System                    |
  |   balance management, rating, quota control      |
  +--------------------------------------------------+
```

The security-relevant point for an OCS engineer: **the OCS is not the thing being fooled.** The OCS correctly charges whatever rating-group it is told about. The lie is injected at step 1, and by the time volume is reported over Gy the fraudulent flow is already labelled as free. Credit control is working perfectly on bad input. So the defence has to live at classification time — which is exactly where `detector.py` puts it.

The lab models this shape in general terms, following the public concepts in:

* **3GPP TS 32.240** — charging architecture and principles (online vs offline charging, charging keys / rating-groups).
* **3GPP TS 32.299** — Diameter charging applications; the Credit-Control-Request / Answer message flow (`CCR-I`, `CCR-U`, `CCR-T`), `Multiple-Services-Credit-Control`, `Granted-Service-Unit` / `Used-Service-Unit` reporting per rating-group.
* **3GPP TS 23.203** — policy and charging control architecture; the PCEF/TDF roles, PCC rules, and gating control.

`charging.py` reproduces the *shape* of a Gy session so the logs read familiarly to a charging engineer. **It is not a Diameter stack**: no AVPs are encoded, no peer is contacted, and nothing is placed on any wire.

---

## The attack, concretely

Nothing exotic is required — that is precisely the problem. The claimed identity and the actual destination are two independent fields, and a naive classifier only reads one of them.

**Plaintext:** send a request whose routing target is one host and whose `Host:` header is another.

```http
GET http://127.0.0.1:18080/content HTTP/1.1     <-- where the packets actually go
Host: zoom.us                                    <-- what the classifier reads
```

**HTTPS:** open the connection to the real destination, then put the zero-rated name in the TLS ClientHello's SNI extension. In Python that is one keyword argument:

```python
tls_sock = ctx.wrap_socket(sock, server_hostname="zoom.us")   # <-- the SNI, freely chosen
```

Encryption does not help here. SNI is sent in the clear precisely so intermediaries can route on it, which is also what makes it readable by a classifier — and writable by an attacker.

mitmproxy's own API documentation flags this for `Request.pretty_host`: in adversarial environments it may not reflect the actual destination, because the `Host` header can be spoofed. A classifier that keys on it inherits that caveat.

---

## The detection

The naive classifier uses one input. The detector adds a second one the client does **not** control — the destination the packets are actually going to — and cross-validates:

```
   claimed_host  (Host header / SNI)   <-- client-controlled, may be a lie
   real_dest_ip  (IP header dest)      <-- not client-controlled

   is claimed_host on the zero-rating whitelist?
        no  -> CHARGED_NORMAL         (no incentive to spoof a billed host; skip validation)
        yes -> resolve(claimed_host) -> set of legitimate IPs
                 real_dest_ip in that set   -> ZERO_RATED_VALID        charge 0
                 resolution failed          -> ZERO_RATING_UNVERIFIABLE allow + flag
                 otherwise                  -> BYPASS_SUSPECTED        log + drop
```

Three design decisions worth calling out, because they are what separate a detector that ships from one that gets switched off in week one:

**1. Validate only what is worth lying about.** A flow claiming a non-zero-rated hostname gains the subscriber nothing, so it skips resolution entirely. In production this matters: it keeps the expensive path off the overwhelming majority of traffic.

**2. Compare against the full resolved set, never a single address.** Any real zero-rated service is CDN-hosted, multi-homed and geo-balanced. Comparing the destination to "the" IP of a hostname would false-positive on essentially every legitimate flow. `dns_fixtures.json` deliberately gives each zero-rated host multiple addresses so this path is exercised in the demo.

**3. Failure to resolve is not evidence of fraud.** An unresolvable hostname is far more often a stale cache, a split-horizon DNS view, or a resolver timeout. Those flows return `ZERO_RATING_UNVERIFIABLE` at LOW confidence, are **allowed through**, and are logged for offline review rather than enforced against.

### Confidence, and what gets dropped

| Confidence | Condition | Action |
| ---------- | --------- | ------ |
| **HIGH** | Destination is not in the resolved set **and** is not publicly routable (loopback / RFC1918 / link-local) — no public zero-rated service can live there. Also HIGH when SNI and `Host` header contradict each other on the same connection. | **DROP** |
| **MEDIUM** | Destination is not in the resolved set, but is a plausible public address. Could be DNS skew. | Log only |
| **LOW** | Claimed host could not be resolved at all. | Log only, allow |

Only `HIGH` is enforced (`DROP_ON_CONFIDENCE` in `lab_config.py`). Everything else feeds an offline revenue-assurance queue. Blocking on ambiguous evidence breaks paying customers, which costs more than the fraud does.

### Residual false-positive risk

This is a hostname-vs-destination heuristic, and it has real limits. Configured in `lab_config.py`:

* **CDN edge rotation.** The subscriber's resolver and the detector may legitimately get different answers for the same name, seconds apart. Mitigated by (a) full-set comparison and (b) `PREFIX_TOLERANCE_BITS_V4 = 24`, which accepts a destination inside the same /24 as any resolved address. Widening that netmask trades detection sensitivity for fewer false positives; tightening it to `32` requires an exact match.
  *Note:* prefix tolerance is deliberately **not** applied to loopback/RFC1918 destinations. It exists to excuse CDN churn on public address space; stretching it onto private space would only launder attacks.
* **Shared hosting and multi-tenant edges.** A zero-rated host and a chargeable host behind the same CDN IP are indistinguishable by destination address alone. This check cannot separate them — it bounds the attack to "same IP as the real service", it does not eliminate it.
* **DNS-over-HTTPS / DNS-over-TLS.** If the detector cannot observe the subscriber's actual resolution, it must fall back to its own view of the name, which increases skew.
* **Long-lived connections.** A flow validated at setup is not re-validated if the destination's DNS mapping changes mid-session.
* **Client-side caching.** A client legitimately reusing a cached A record older than the detector's view will look like a mismatch. The TTL cache (`RESOLVER_CACHE_TTL`) narrows but does not close this window.

The honest framing: **this raises the cost of the bypass and makes it noisy and auditable. It does not make it impossible.** Layered defences are noted under [Limitations](#limitations).

---

## Project layout

| File | Role |
| ---- | ---- |
| `classifier_naive.py` | **The victim.** mitmproxy addon: classifies on claimed `Host`/SNI alone and meters accordingly. Intentionally exploitable. |
| `detector.py` | **The hero.** mitmproxy addon: cross-validates the claim against the real destination IP, emits structured findings, drops HIGH-confidence bypasses. |
| `attacker_client.py` | Test harness. Drives 5 scenarios (legit + spoofed, plaintext + TLS) through the proxy. Loopback-only, hard-enforced. |
| `logging_util.py` | Shared JSON-lines logger (`ts`, `level`, `component`, `event`, + structured fields). |
| `charging.py` | Conceptual Gy-style credit meter (balance, quota grants, CCR-I/U/T events), shared by both addons so before/after numbers come from identical accounting code. |
| `lab_config.py` | All tunables: whitelist, lab topology, resolver mode, confidence thresholds, enforcement action. |
| `local_test_server.py` | The lab origin. Four loopback listeners (HTTP + HTTPS on two addresses), self-signed cert generated on first run. |
| `dns_fixtures.json` | Offline DNS map. Makes the lab deterministic and network-free. |
| `demo_report.py` | Builds the before/after summary from the JSONL evidence files. |
| `run_demo.sh` / `run_demo.ps1` | End-to-end demo (bash / PowerShell). |
| `END_TO_END.md` | Full process walkthrough: what executes, in what order, with real log evidence. |

### Why two loopback addresses

The lab needs a genuine IP mismatch without leaving the machine, so the origin binds two loopback aliases:

* `127.0.0.2` — where the **genuine** zero-rated service lives. `dns_fixtures.json` maps `zoom.us` here.
* `127.0.0.1` — ordinary chargeable content, and where the spoofing client actually connects while claiming `zoom.us`.

So "claimed `zoom.us`, actually went to `127.0.0.1`" is a real, checkable mismatch — the same check that would run against public addresses in a real deployment.

---

## Setup

Requires **Python 3.10+**.

```bash
cd zero-rating-detection-lab
python -m venv .venv
```

Activate it — bash/Git Bash:

```bash
source .venv/Scripts/activate   # Windows;  use .venv/bin/activate on Linux/macOS
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then:

```bash
pip install -r requirements.txt
```

`run_demo` auto-detects `.venv/`, so activation is optional for running the demo.

## Run the demo

bash / Git Bash:

```bash
./run_demo.sh
```

PowerShell:

```powershell
.\run_demo.ps1
```

The script starts the loopback origin, runs the five scenarios through `classifier_naive.py`, runs the identical five through `detector.py`, then prints the before/after summary. It cleans up all processes on exit.

**Port conflicts:** defaults are `18080` / `18443` / `18081` rather than the usual `8080`/`8443`/`8081`, which collide with an already-running web server on many machines. `run_demo` pre-flights all of them and names the busy one. To override:

```bash
ZRLAB_PROXY_PORT=19081 ZRLAB_HTTP_PORT=19080 ZRLAB_HTTPS_PORT=19443 ./run_demo.sh
```

### Running the pieces by hand

```bash
python local_test_server.py
```

```bash
mitmdump -s detector.py --listen-host 127.0.0.1 --listen-port 18081 --set connection_strategy=eager --ssl-insecure
```

```bash
python attacker_client.py --phase detector
```

Useful flags: `--only <scenario>` runs one scenario, `--skip-tls` runs plaintext only, `--shutdown-proxy` stops the addon gracefully so it flushes its final report.

### A note on stopping the addons cleanly

`run_demo` stops each addon with an in-band control request (`GET http://zrlab.control/shutdown`,
handled in `lab_config.handle_control_request`) rather than by sending a signal. That is
deliberate: signal delivery to a child process differs across bash, Git Bash and PowerShell,
and an addon killed before its `done()` hook runs would never write its final `CCR-T` or its
meter report. Going in-band makes the teardown identical everywhere -- verified on both
Windows and Linux, where `gy_ccr_terminate` appears in both addons' logs.

As a second layer, the meter report is rewritten after *every* flow, not just at shutdown, so
the evidence files stay complete even if the process is killed outright.

### Environment variables

| Variable | Default | Effect |
| -------- | ------- | ------ |
| `ZRLAB_RESOLVER` | `fixture` | `fixture` = offline JSON map (no DNS traffic). `system` = OS resolver; **emits real DNS queries**, so the demo never selects it. |
| `ZRLAB_ENFORCEMENT` | `kill` | `kill` = tear down the flow (models a PCEF gate-close). `block403` = return a JSON 403 instead; easier to screenshot from the client side. |
| `ZRLAB_PROXY_PORT` / `ZRLAB_HTTP_PORT` / `ZRLAB_HTTPS_PORT` | `18081` / `18080` / `18443` | Port overrides. |
| `NO_COLOR` | unset | Disables ANSI colour in log output. |

### Troubleshooting

If a scenario reports `outcome=PROXY_UNAVAILABLE`, the harness could not reach the proxy at all — nothing was classified. That is a lab setup failure (mitmdump not up yet, or a port conflict), deliberately **not** reported as `DROPPED`, so a broken run can never be mistaken for a successful detection. `run_demo` waits for the listener before sending traffic, so this should only appear when running the pieces by hand.

---

## Sample output

Verbatim from a run on Windows 11 (Python 3.13, mitmproxy 12.2.3). The same demo was
run on Ubuntu 24.04 and produced identical figures on every line -- same charged
volumes, same two HIGH-confidence drops, same zero false positives.

```
====================================================================================================
  ZERO-RATING BYPASS DETECTION LAB  -  BEFORE / AFTER SUMMARY
====================================================================================================
  Simplified reference model built from public 3GPP concepts
  (traffic classification -> PCC rules -> PCEF metering -> OCS over Gy,
   cf. 3GPP TS 32.299 / TS 32.240). NOT any operator's production system.
  Every address in this run is loopback. Nothing left this machine.

  PHASE 1 - NAIVE CLASSIFIER   (trusts the claimed Host / SNI)
  ------------------------------------------------------------------------------------------------
  CLAIMED HOST       ACTUAL DEST     TRANSPORT  VERDICT            CHARGED
  lab-origin.local   127.0.0.1       HTTP/Host  CHARGED           64.2 KiB
  zoom.us            127.0.0.2       HTTP/Host  ZERO-RATED             0 B
  zoom.us            127.0.0.1       HTTP/Host  ZERO-RATED             0 B  <== REVENUE LEAK: spoof believed
  zoom.us            127.0.0.2       TLS/SNI    ZERO-RATED             0 B
  zoom.us            127.0.0.1       TLS/SNI    ZERO-RATED             0 B  <== REVENUE LEAK: spoof believed

  Meter totals after phase 1:
    billed to subscriber ....... 64.2 KiB
    waived as zero-rated ....... 256.8 KiB
    remaining balance .......... 959.8 KiB
    flows blocked .............. 0
    REVENUE LEAKAGE ............ 128.4 KiB   <== fraud succeeded

  PHASE 2 - CROSS-VALIDATING DETECTOR   (claim checked against real dest IP)
  ------------------------------------------------------------------------------------------------
  CLAIMED HOST       ACTUAL DEST     TRANSPORT  VERDICT            CHARGED
  lab-origin.local   127.0.0.1       HTTP/Host  CHARGED           64.2 KiB
  zoom.us            127.0.0.2       HTTP/Host  ZERO-RATED             0 B
  zoom.us            127.0.0.1       HTTP/Host  DROPPED                0 B  <== BLOCKED (HIGH)
  zoom.us            127.0.0.2       TLS/SNI    ZERO-RATED             0 B
  zoom.us            127.0.0.1       TLS/SNI    DROPPED                0 B  <== BLOCKED (HIGH)

  Meter totals after phase 2:
    billed to subscriber ....... 64.2 KiB
    waived as zero-rated ....... 128.4 KiB
    remaining balance .......... 959.8 KiB
    flows blocked .............. 2
    REVENUE LEAKAGE ............ 0 B   <== none

  DETECTOR FINDINGS (structured JSON, one object per detection)
  ------------------------------------------------------------------------------------------------
    [HIGH] BYPASS_SUSPECTED  claimed=zoom.us  real_ip=127.0.0.1  transport=HTTP/Host  action=DROP
        signal: claimed_host_resolves_elsewhere
        signal: destination_not_publicly_routable
    [HIGH] BYPASS_SUSPECTED  claimed=zoom.us  real_ip=127.0.0.1  transport=TLS/SNI  action=DROP
        signal: claimed_host_resolves_elsewhere
        signal: destination_not_publicly_routable

  RESULT
  ------------------------------------------------------------------------------------------------
    naive classifier    : 128.4 KiB waived on unverified claims  (2 spoofed flow(s) believed)
    cross-validating    : 0 B waived on unverified claims  (2 spoofed flow(s) dropped)

    leakage prevented   : 128.4 KiB  (100% of the attempted bypass)

    false positives     : 0   (out of 2 genuine zero-rated flow(s) offered)
    free tier preserved : 2 flow(s), 128.4 KiB correctly still waived
====================================================================================================
```

### The evidence files

Everything is JSON Lines — one self-describing object per line, ready for `jq`, Splunk, Elastic or a Kafka collector. Bare `print()` is not used anywhere in the project.

A detection record (`logs/detector_findings.jsonl`):

```json
{
  "ts": "2026-08-17T21:08:01.469Z",
  "level": "ALERT",
  "component": "detector",
  "event": "zero_rating_bypass_detected",
  "client_ip": "127.0.0.1",
  "claimed_host": "zoom.us",
  "real_host": "127.0.0.1",
  "real_ip": "127.0.0.1",
  "resolved_ips": ["127.0.0.2", "203.0.113.10", "203.0.113.11", "203.0.113.12"],
  "transport": "HTTP/Host",
  "verdict": "BYPASS_SUSPECTED",
  "confidence": "HIGH",
  "signals": ["claimed_host_resolves_elsewhere", "destination_not_publicly_routable"],
  "reason": "claimed zero-rated host resolves elsewhere AND the actual destination is a non-routable address that cannot host a public zero-rated service",
  "detection_point": "http_request",
  "action": "DROP",
  "rating_group_claimed": 100,
  "subscriber_msisdn": "+99900000001"
}
```

And the naive classifier convicting itself — note that `real_ip` is right there in its own log line, observed and then ignored:

```json
{
  "ts": "2026-08-17T21:07:50.942Z",
  "level": "ZERORATE",
  "component": "classifier_naive",
  "event": "charging_decision",
  "verdict": "ZERO-RATED",
  "charged_bytes": 0,
  "claimed_host": "zoom.us",
  "real_ip": "127.0.0.1",
  "transport": "HTTP/Host",
  "volume_bytes": 65743,
  "rating_group": 100,
  "reason": "claimed hostname matched zero-rating whitelist"
}
```

| File | Contents |
| ---- | -------- |
| `logs/classifier_naive.jsonl` | Naive phase: Gy session events + every charging decision. |
| `logs/detector.jsonl` | Detector phase: same, plus alerts and drops. |
| `logs/detector_findings.jsonl` | Findings only — the revenue-assurance feed. |
| `logs/attacker_client.jsonl` | What the harness sent and what came back, both phases. |
| `logs/naive_meter_report.json`, `logs/detector_report.json` | Final meter snapshots. |

---

## Limitations

Stated plainly, because a detection design is only as useful as its known boundaries.

1. **This is a model, not an implementation.** No Diameter stack, no PCC rule provisioning, no Gx/Sy interaction, no real PCEF. It demonstrates one classification-integrity check, not a charging product.
2. **The proxy is a lab convenience, not the proposal.** mitmproxy is a forward proxy, so "the real destination" here is reconstructed from the request line or CONNECT target. On a real gateway the destination is simply the IP header's destination field — one unambiguous value that is *harder* to lie about than in this lab, not easier.
3. **Metering is HTTP-level, not IP-level.** Volume is counted as response status line + headers + body. A real PCEF meters IP octets in both directions.
4. **Destination-IP validation bounds the attack; it does not end it.** An attacker who routes spoofed traffic through the genuine service's own address space still passes. Complementary layers used in practice: TLS certificate/SAN validation against the claimed name, ALPN and JA3/JA4-style handshake fingerprinting, behavioural volumetrics per rating-group, and correlating observed DNS answers with subsequent flows.
5. **Enforcement is per-flow, not per-subscriber.** There is no repeat-offender tracking, rate limiting, or escalation policy — a production system would feed findings into subscriber-level case management.
6. **IPv6 is handled in the address logic but not exercised** by the demo scenarios.
7. **No test suite.** The natural next step is unit tests over `CrossValidator.evaluate()` — the verdict matrix (valid / spoofed / unverifiable / CDN-prefix / non-routable) is pure and directly testable without any network.

---

## Responsible use

**Do not run this, or anything like it, against a network you do not own.**

`attacker_client.py` generates deliberately deceptive traffic. In a lab that is testing. Against a real mobile network it is **billing fraud**: a criminal offence in most jurisdictions, a breach of every operator's terms of service, and theft from an organisation that has not consented to being tested.

The safeguards are structural, not advisory:

* Every target passes through `assert_loopback()`, which refuses anything outside `127.0.0.0/8` before a socket is opened. There is no flag to disable it.
* Hostname resolution defaults to a local JSON fixture; the demo emits no DNS queries.
* The origin server refuses to start if configured to bind a non-loopback address.
* Every address in the repository is loopback or RFC 5737 documentation space.

If you extend this lab, keep those properties. If you are doing authorised work on a real network, you already have an engagement scope, written authorisation, and a change window — none of which this repository grants.

## Reporting real-world abuse

If you believe you have found a genuine zero-rating bypass in a production network, **do not investigate it further yourself**. Continuing to exercise it — even to "confirm" it — generates more fraudulent traffic and weakens your position considerably. Report it and stop.

Appropriate channels, roughly in order:

1. **The operator's security or revenue-assurance team.** Check for a `security.txt` at `https://<operator-domain>/.well-known/security.txt`, a published vulnerability disclosure policy, or a bug bounty programme. Revenue assurance is the team that owns this specific problem class.
2. **The operator's CERT/CSIRT**, if it runs one, or their abuse contact.
3. **Your national CERT/CSIRT**, if the operator has no disclosure channel or does not respond. FIRST maintains a directory of national teams at `first.org/members`.
4. **The national telecoms regulator**, where billing integrity is a regulated obligation and the operator is unresponsive.

When you report: describe the mechanism, provide timestamps and your own subscriber identifiers, state clearly that you stopped as soon as you understood the issue, and give them a way to reach you. Follow coordinated disclosure — give the operator reasonable time to fix it before publishing anything.

---

## Standards references

Cited in general terms as conceptual background; no specification text is reproduced.

* **3GPP TS 32.240** — Charging architecture and principles.
* **3GPP TS 32.299** — Diameter charging applications (online charging / Gy; CCR/CCA, MSCC, service units).
* **3GPP TS 23.203** — Policy and charging control architecture (PCEF, TDF, PCC rules, gating).
* **3GPP TS 29.212** — Policy and charging control over the Gx reference point.
* **IETF RFC 4006** — Diameter Credit-Control Application, the base protocol 3GPP's online charging application profiles.
* **IETF RFC 6066** — TLS extensions, including Server Name Indication (SNI).
* **IETF RFC 5737** — IPv4 address blocks reserved for documentation, used throughout `dns_fixtures.json`.

---

*Built as a portfolio project for Converged Charging / OCS engineering. Defensive by design, local by construction.*

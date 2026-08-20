# Study Guide — Reading & Understanding the Code

**A guided path through both labs so you can explain every part in an interview.**
Read the files in the order below. For each one: open it, find the function
named, and answer the **Self-check** out loud before moving on. Don't rush — the
goal is that you can defend any line.

Two labs:
- **`../sni-tunnel-lab`** — the **attack** (forges the SNI). Short, concrete. Start here.
- **`zero-rating-detection-lab`** (this folder) — the **defense** (catches it). The core.

---

## First, five words you must own

| Term | Plain meaning |
| ---- | ------------- |
| **Zero-rating** | Operator charges 0 bytes for whitelisted traffic (e.g. Zoom). |
| **SNI** | The hostname in the TLS ClientHello, sent in the clear. Client writes it — can lie. |
| **Host header** | The hostname in a plaintext HTTP request. Also client-written — can lie. |
| **OCS / Gy / PCEF** | The charging system (OCS), the interface it's fed over (Gy), and the gateway function that meters traffic and reports it (PCEF). 3GPP terms. |
| **Cross-validation** | Checking the *claimed* hostname against the *real* destination IP. The whole defense. |

If you can say those five from memory, the code will make sense.

---

## PHASE 1 — The attack (`../sni-tunnel-lab`) — start here

### 1. `lab2_config.py`
- **Find:** `SPOOFED_SNI = os.environ.get("ZRLAB_SPOOFED_SNI", "zoom.us")`
- **Understand:** this one string is the entire trick. Also find `_ALLOW_PUBLIC`
  and `_is_private_ip` — the interlock that refuses public relay.
- **Self-check:** *What single value makes ordinary traffic look zero-rated? What
  stops this lab from being a real bypass tool?*

### 2. `windows_spoofing_client.py`
- **Find:** `tunnel = _TLS_CTX.wrap_socket(raw, server_hostname=cfg.SPOOFED_SNI)`
- **Understand:** `server_hostname=` is literally where the SNI is forged. Note the
  client uses **raw sockets**, not `requests`/`urllib` — because those libraries
  derive the SNI from the URL, and the whole point is to *decouple* the SNI from
  the destination.
- **Self-check:** *Which single line forges the identity? Why can't you do this
  attack with a normal HTTP library?*

### 3. `vps_tunnel_server.py`
- **Find:** where it logs `spoofed_sni=...` (it reads the SNI off the handshake),
  and the `_is_private_ip(...)` check that decides `allowed=True/False`.
- **Understand:** the server *records* the SNI the client presented (proof of the
  spoof) and *refuses* to relay to any public IP.
- **Self-check:** *How does the server know the SNI was a lie? Why does it refuse
  `8.8.8.8` but allow `127.0.0.1`?*

You now understand the attack. Everything the defense does is a reaction to this.

---

## PHASE 2 — The defense (this folder) — the core

### 4. `lab_config.py`
- **Find:** `ZERO_RATED_HOSTS` (the whitelist) and `is_zero_rated()`.
- **Understand:** this is the operator's charging policy. Notice the decision uses
  **only the claimed hostname** — nothing else. Also skim `RATING_GROUP_*`
  (100 = zero-rated bucket, 200 = standard).
- **Self-check:** *What is the only input to the zero-rating decision here? Why is
  that dangerous?*

### 5. `classifier_naive.py` — the victim
- **Find:** `_claimed_host()` (reads SNI or Host header) and `_real_ip()`.
- **Understand:** the crucial detail — `_real_ip()` is computed and **logged**, then
  the verdict **ignores it**. The evidence that would expose the spoof sits right
  there in its own log, unused. That gap *is* the vulnerability.
- **Self-check:** *This classifier logs `real_ip` next to `verdict=ZERO-RATED`.
  Why doesn't it use it? Point to the exact place the bug lives.*

### 6. `detector.py` — the hero (read it in this sub-order)

This is the most important file. Read its pieces in order:

- **a. `class Finding`** — the shape of a decision (verdict, confidence, signals,
  whether to zero-rate, whether to drop). Read this first so the rest makes sense.
- **b. `LabResolver.resolve()`** — answers *"what SHOULD this hostname resolve
  to?"* from `dns_fixtures.json`. Note the TTL cache and that it's fully offline.
- **c. `CrossValidator.match_kind()`** — compares the real IP to the resolved set:
  returns `exact` / `prefix` / `none`. The `prefix` case is the **CDN tolerance**
  (false-positive control); note it's deliberately **not** applied to loopback/RFC1918.
- **d. `CrossValidator.evaluate()`** — **the decision tree.** This is the heart of
  the whole project. Trace it slowly.
- **e. `tls_clienthello()` vs `request()`** — detection happens at the ClientHello
  (SNI visible, before any data); enforcement happens at the first request (where
  mitmproxy can actually tear the flow down).
- **Self-check:** *Trace a flow claiming `zoom.us` but really going to `127.0.0.1`
  through `evaluate()`. Which branch fires, what confidence, and why does it drop?*
- **Self-check:** *Why is a flow claiming `zoom.us` that really goes to `127.0.0.2`
  NOT dropped? (Look at the fixture.)*

### 7. `charging.py` — the meter
- **Find:** `GyMeter.start_session()` (CCR-I), `meter()`, `stop_session()` (CCR-T).
- **Understand:** this models the Gy credit-control lifecycle. It's **shared** by
  both `classifier_naive.py` and `detector.py`, so the only thing that differs
  between "before" and "after" is the classification decision, not the accounting.
- **Self-check:** *What's a rating-group? Why is the meter shared between the naive
  and detector versions?*

---

## PHASE 3 — Supporting cast (skim, one pass each)

| File | What it does |
| ---- | ------------ |
| `logging_util.py` | The JSON-Lines logger everything uses. Why JSON lines: it's what a real revenue-assurance pipeline ingests. |
| `local_test_server.py` | The lab "internet" — serves 64 KiB on two loopback IPs (`127.0.0.1` = chargeable, `127.0.0.2` = the real zero-rated service). |
| `attacker_client.py` | Builds the 5 test flows (legit + spoofed, HTTP + TLS). Note `assert_loopback()` — the safety interlock. |
| `demo_report.py` | Builds the before/after summary by reading the JSONL evidence — it recomputes nothing. |
| `run_demo.sh` / `.ps1` | Orchestrates the whole 3-part story. |
| `dns_fixtures.json` | The offline DNS map. `zoom.us → {127.0.0.2, 203.0.113.x}`. This is the "ground truth" the detector checks against. |

---

## Two trace exercises (do these on paper)

**Exercise 1 — the spoof gets caught.** Follow the `spoof-http` flow:
`attacker_client.py` builds `Host: zoom.us` → real dest `127.0.0.1` →
`detector.request()` → `evaluate()` resolves `zoom.us` → `127.0.0.1` not in set →
not routable → `BYPASS_SUSPECTED / HIGH` → `_enforce()` → `flow.kill()`. Write each
step and the value at each step.

**Exercise 2 — the genuine flow survives.** Follow `legit-zerorated`:
`Host: zoom.us` → real dest `127.0.0.2` → `evaluate()` → `127.0.0.2` **is** in the
resolved set → `ZERO_RATED_VALID` → charged 0. This is the false-positive test:
prove to yourself the detector doesn't break the real free tier.

---

## Interview questions you should be able to answer

1. What is zero-rating, and why do operators do it?
2. How does SNI (or Host-header) spoofing defeat a naive classifier?
3. Why doesn't TLS encryption stop the SNI from being read — or forged?
4. What's the one extra input your detector uses that the client can't control?
5. Walk me through `CrossValidator.evaluate()`.
6. What are your HIGH / MEDIUM / LOW confidence levels, and why only drop on HIGH?
7. How do you avoid false positives on CDN-hosted services? (full resolved set + prefix tolerance)
8. Why is failure-to-resolve *not* treated as fraud?
9. Where does this sit in a real 3GPP network? (traffic classification → PCC rules → PCEF meters over Gy → OCS)
10. What are the limits of your model, and how would you extend it? (TLS fingerprinting, behavioral analysis, per-subscriber tracking)

If you can answer all ten, you understand the project better than most candidates.

---

## Three things NOT to say (calibration)

- ❌ "I built a production zero-rating detector." ✅ "I built a simplified
  reference model of the attack and a principled detection approach."
- ❌ "The proxy is how operators do it." ✅ "The proxy is a lab convenience to
  observe the mismatch; a real PCEF reads the IP header directly."
- ❌ "This makes the bypass impossible." ✅ "This raises the cost and makes the
  bypass noisy and auditable; layered defenses go further."

---

*Companion to [README.md](README.md), [END_TO_END.md](END_TO_END.md), and
[../sni-tunnel-lab/EVIDENCE.md](../sni-tunnel-lab/EVIDENCE.md).*

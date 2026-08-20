# Telecom Zero-Rating Fraud — Attack & Detection Lab

**A defensive, standards-based home lab that demonstrates a telecom *zero-rating bypass* and the *detection* that stops it — the attack and the defense, side by side, running entirely on hardware I own.**

Built as a portfolio project for **Converged Charging / OCS engineering**. It models the charging path conceptually after the 3GPP **Gy** interface (PCEF ⇄ OCS, Diameter Credit-Control per TS 32.299) and shows, hands-on, why traffic classification is the security-critical front of the charging chain.

> **⚠️ LAB / EDUCATIONAL — simplified reference model, not any operator's production system.**
> Everything runs locally. No real carrier network is touched, probed, or depended on. There is no real operator data; every address is loopback or RFC 5737 documentation space. The attack lab has a hard interlock that **refuses to relay to any public IP** — it demonstrates the *mechanism* of the bypass without being a usable bypass tool. Running an SNI-spoofing tunnel over a real metered link to dodge charging is billing fraud; this project does not do that and cannot be pointed at a live network.

---

## The idea in one sentence

A zero-rating classifier decides *"is this traffic free?"* from the **hostname the client claims** (HTTP `Host` header or TLS **SNI**) — and that hostname is client-controlled and unauthenticated, so a client can **claim `zoom.us` while sending traffic somewhere else** and get it charged at zero. The fix is to **cross-validate the claim against the real destination**.

```
   claimed identity   (Host header / TLS SNI)   ← the client writes this; it can lie
   actual destination (the IP packets go to)     ← the client cannot fake this

   naive classifier  : trusts the claim              → fooled  (revenue leaks)
   this project      : compares claim vs destination → bypass detected & dropped
```

---

## Two labs, one story

| Lab | Folder | Role | Proves |
| --- | ------ | ---- | ------ |
| **Detection** | [`zero-rating-detection-lab/`](zero-rating-detection-lab/) | the **defense** — the OCS engineer's job | a naive charging classifier is fooled by a spoofed hostname; a cross-validating detector catches and **drops** it |
| **Attack** | [`sni-tunnel-lab/`](sni-tunnel-lab/) | the **threat model** — what the defense faces | a client forges the TLS **SNI = `zoom.us`** and tunnels ordinary traffic to a server that isn't Zoom — **provable on the wire in Wireshark** |

```
   ┌──────────────────────────┐     forged TLS ClientHello      ┌─────────────────────────┐
   │  ATTACK  (sni-tunnel-lab) │  SNI=zoom.us → IP≠zoom (pcap)   │  DEFENSE (detection-lab)│
   │  spoofing client → VPS    │ ──────────────────────────────▶ │  resolve(zoom.us);      │
   │  records SNI, refuses     │                                 │  dest ∉ resolved set →  │
   │  public relay (interlock) │                                 │  BYPASS_SUSPECTED → DROP│
   └──────────────────────────┘                                 └─────────────────────────┘
```

---

## Headline result

Running the detection demo (five flows — legitimate + spoofed, HTTP + TLS — through a naive classifier, then through the detector):

```
  naive classifier    : 128.4 KiB waived on unverified claims  (2 spoofed flows believed)
  cross-validating     : 0 B      waived on unverified claims  (2 spoofed flows dropped)
  leakage prevented    : 128.4 KiB  (100% of the attempted bypass)
  false positives      : 0   (both genuine zero-rated flows correctly still free)
```

Verified identical on **Windows 11** and **Ubuntu 24.04**. The attack's forged SNI was captured cross-machine over a real LAN and confirmed in Wireshark.

---

## Where this sits in a real network (3GPP)

```
   UE ──service data flows──▶ Packet gateway (PGW-C/U · SMF+UPF)
                               │  [1] TRAFFIC CLASSIFICATION  ← the attack targets this
                               │  [2] rating-group assignment (0-rated vs standard)
                               │  [3] PCEF metering + gating
                               │
                               ▼  Diameter Gy  (CCR-I / CCR-U / CCR-T)
                             OCS  — balance, rating, quota control
```

The key insight for an OCS engineer: **the OCS is not what gets fooled.** It charges the rating-group it is told about, correctly. The lie is injected at classification (step 1), so the defense must live there too — which is exactly where the detector puts it. Concepts follow the public specs **3GPP TS 32.240** (charging architecture), **TS 32.299** (Diameter online charging / Gy), and **TS 23.203** (policy & charging control). No Diameter is placed on any wire; the labs model the *shape* of a Gy session so the logs read familiarly.

---

## Quick start

**Detection lab (start here — it's the core):**
```bash
cd zero-rating-detection-lab
python -m venv .venv && ./.venv/bin/pip install -r requirements.txt
bash run_demo.sh
```
(Windows: `.\.venv\Scripts\Activate.ps1` then `python run_demo.ps1`, or `bash run_demo.sh` in Git Bash.)

**Attack lab (the SNI-spoofing tunnel):**
```bash
cd sni-tunnel-lab
./setup_certs.sh
sudo ./capture_demo.sh        # one-command loopback demo + pcap
```

Both labs default to high ports (18080/18443/18081, and 4433 for the tunnel) to avoid colliding with a local web server, and pre-flight the ports before starting.

---

## Documentation map

| Document | What it is |
| -------- | ---------- |
| [`zero-rating-detection-lab/README.md`](zero-rating-detection-lab/README.md) | Detection lab: full write-up, design, false-positive handling, limitations |
| [`zero-rating-detection-lab/END_TO_END.md`](zero-rating-detection-lab/END_TO_END.md) | Stage-by-stage trace of the detection pipeline with real log evidence |
| [`zero-rating-detection-lab/STUDY_GUIDE.md`](zero-rating-detection-lab/STUDY_GUIDE.md) | Guided code-reading path + self-check and interview questions |
| [`sni-tunnel-lab/README.md`](sni-tunnel-lab/README.md) | Attack lab: the SNI-spoofing tunnel, setup and run |
| [`sni-tunnel-lab/EVIDENCE.md`](sni-tunnel-lab/EVIDENCE.md) | End-to-end guide + captured evidence tying both labs together |

---

## What this demonstrates

- **The attack** — SNI/Host-spoofing zero-rating bypass, reproduced on two real machines and captured on the wire.
- **The containment** — the tunnel endpoint records every spoof and refuses public relay, so the mechanism is shown without a working fraud tool.
- **The defense** — a cross-validating classifier that resolves the claimed host, checks the real destination against the full resolved address set (with CDN-tolerance to avoid false positives), and drops only high-confidence bypasses — recovering 100% of the attempted leakage with zero false positives.
- **Engineering practice** — structured JSON-Lines evidence, a shared charging meter so before/after numbers come from identical accounting, cross-platform verification, and honest documentation of limits.

---

## Responsible use

This is a defensive, closed-loop teaching lab, for validating detection logic on equipment you own. Do not run the attack harness against any network you do not control — that is billing fraud, and the attack lab is technically prevented from reaching the public internet regardless. If you ever find a genuine zero-rating bypass in a production network, **stop and report it** to the operator's revenue-assurance / security team, their CERT, or the national regulator, rather than continuing to exercise it. Full responsible-use and reporting guidance is in [`zero-rating-detection-lab/README.md`](zero-rating-detection-lab/README.md).

---

## License

Released under the [MIT License](LICENSE). The educational/defensive scope and responsible-use terms in the README and sub-lab docs still apply.

---

*Simplified reference model based on public 3GPP concepts. Not affiliated with, and not a description of, any operator's production system.*

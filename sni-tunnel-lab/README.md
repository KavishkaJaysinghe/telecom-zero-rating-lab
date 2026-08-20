# SNI-Spoofing Tunnel Lab (closed-loop)

**A two-machine demonstration of TLS SNI spoofing over a tunnel — the *attacker* side of the zero-rating story whose *defence* lives in [`../zero-rating-detection-lab`](../zero-rating-detection-lab).**

---

> ### ⚠️ Scope and safety — read first
>
> * **This is a closed-loop lab, not a working zero-rating bypass.** It runs between two machines you own and, by default, **refuses to relay to any public address** (see `is_forward_allowed()` in `lab2_config.py`). The forwarded content never needs to leave the VPS's own loopback.
> * **What it actually demonstrates** is one fact: the TLS **SNI is unauthenticated**, so a client can present `SNI=zoom.us` while tunnelling to something else entirely. You *see* the forged SNI on the wire (Wireshark / the VPS log); you do not defraud anyone.
> * **Running an SNI-spoofing tunnel over a metered/carrier connection to avoid data charges is billing fraud** — a criminal offence in most jurisdictions and a breach of every operator's terms of service. On plain home broadband there is no carrier in the path, so nothing is "bypassed" anyway. This lab exists to help you **detect** the technique, which is your job as an OCS engineer.
> * See [Responsible use](#responsible-use) and [Reporting real-world abuse](#reporting-real-world-abuse).

---

## One deliberate change from the brief

The original design asked the VPS to "forward the raw traffic to the real internet (e.g. YouTube)." That single component is what would turn a demonstration into a deployable fraud tool: a TLS tunnel with a forged `zoom.us` SNI that relays real traffic to the open internet is, on a carrier link, exactly the bypass an OCS engineer is paid to stop.

So the VPS here forwards to a **lab endpoint you control** — by default its own loopback origin — and **refuses public destinations out of the box**. You keep everything that makes this educational:

- a real TLS tunnel between the Windows client and the Linux VPS,
- a real forged SNI (`zoom.us`) in the ClientHello,
- real self-signed certs,
- a real `bypass_capture.pcap` you open in Wireshark to inspect the spoofed SNI,

— and you lose only the ability to actually evade a carrier's billing, which you must not do regardless.

---

## What this shows, and why it matters to an OCS engineer

Zero-rating classifiers read the hostname a client *claims* — the `Host:` header or the TLS **SNI**. Both are client-controlled. This lab builds the tunnel that forges the SNI, so you can watch the claim (`zoom.us`) diverge from the real destination on the wire.

That divergence is precisely the signal the **detector** in the sibling lab cross-validates:

```
   this lab (attacker)                        sibling lab (defender)
   ------------------                         ----------------------
   client presents SNI=zoom.us   ───────────►  detector reads claimed SNI = zoom.us
   tunnel really goes to X                      detector resolves zoom.us -> {legit IPs}
                                                real dest X not in that set  -> BYPASS
```

Being able to say *"I built the SNI-spoofing tunnel **and** the cross-validating detector that catches it, and here is the pcap showing the forged SNI"* is a complete, defensible attack-and-defence story.

---

## Architecture

```
  WINDOWS PC (client)                         LINUX LAPTOP ("VPS")
  ┌────────────────────────┐                  ┌───────────────────────────────┐
  │ browser / curl         │                  │ vps_tunnel_server.py :4433     │
  │   │ CONNECT host:port  │                  │   1. terminate TLS             │
  │   ▼                    │   TLS record     │   2. record SNI (=zoom.us)     │
  │ windows_spoofing_      │   SNI = zoom.us  │   3. read inner CONNECT        │
  │ client.py  :8080       │ ───────────────► │   4. interlock: lab dest only? │
  │   sets SNI = zoom.us   │  (LAN, real net) │   5. relay ↔ lab origin        │
  └────────────────────────┘                  │        (127.0.0.1:18080)       │
                                              └───────────────────────────────┘
       ▲                                              │
       │ the only hostname visible on the wire        │ content stays on
       │ between the two machines is the FORGED SNI   │ the VPS's loopback
       └──────────── record_traffic.sh (tcpdump) ─────┘
```

The tunnel crosses your real LAN (so the pcap is real), but the forwarded **content** stays on the VPS's loopback. Nothing touches the public internet.

---

## Files

| File | Runs on | Role |
| ---- | ------- | ---- |
| `vps_tunnel_server.py` | Linux | TLS-terminating tunnel endpoint. Records the SNI, reads the inner CONNECT, enforces the closed-loop interlock, relays to the lab destination. Can start its own origin with `--with-origin`. |
| `windows_spoofing_client.py` | Windows | Local CONNECT proxy on `127.0.0.1:8080`. Wraps browser traffic in TLS to the VPS **with SNI set to `zoom.us`**. |
| `lab2_config.py` | both | Shared config: topology, the spoofed SNI, and the `is_forward_allowed()` interlock. |
| `setup_certs.sh` | Linux | Generates the self-signed lab certificate (openssl). |
| `record_traffic.sh` | Linux | Captures 60 s of tunnel traffic to `bypass_capture.pcap` (tcpdump). |
| `smoke_test.sh` | either | One-machine self-test: runs both ends on loopback and proves the tunnel works and the interlock refuses public destinations. |
| `requirements.txt` | — | Runtime is stdlib-only; `cryptography` is optional (`--autocert`). |

---

## Setup and run (two machines)

### On the Linux laptop (the "VPS")

```bash
cd sni-tunnel-lab
chmod +x setup_certs.sh record_traffic.sh
./setup_certs.sh
python3 vps_tunnel_server.py --with-origin
```

The server prints its listen address and `public_forwarding=DISABLED (closed-loop)`. Note the laptop's LAN IP (e.g. `ip addr` → `192.168.1.10`).

Copy the certificate to the Windows machine so the client can verify the endpoint (optional — the client also runs without it):

```bash
scp certs/lab-vps-cert.pem <you>@<windows-ip>:/path/to/sni-tunnel-lab/certs/
```

### On the Windows PC (the "client")

```bash
set ZRLAB_VPS_IP=192.168.1.10
python windows_spoofing_client.py
```

It listens on `127.0.0.1:8080` and prints `spoofed_sni=zoom.us`.

### Test it with curl (through the Windows client)

```bash
curl --proxytunnel -x 127.0.0.1:8080 http://127.0.0.1:18080/
```

`--proxytunnel` forces curl to issue a `CONNECT`, which the client tunnels to the VPS with `SNI=zoom.us`. The VPS relays to its own loopback origin and you get:

```
ZRLAB-VPS-ORIGIN: you reached the lab origin through the TLS tunnel.
The SNI on the outer connection was spoofed; ...
```

`127.0.0.1` in that command is the VPS's *own* loopback (the origin `--with-origin` started). To point the tunnel at another host **you control on the lab LAN**, use its private IP — the interlock will still refuse anything public.

### One-machine self-test (optional)

Before splitting across two machines, prove the code end to end on one box:

```bash
./smoke_test.sh
```

It runs both ends on loopback, drives an honest request through the tunnel, and confirms the interlock refuses `8.8.8.8`. Verified on Windows 11 (Python 3.13) and portable to Linux.

---

## Capturing the spoofed SNI for Wireshark

On the Linux VPS, in a second terminal:

```bash
sudo ./record_traffic.sh
```

It captures TCP port 4433 for 60 seconds into `bypass_capture.pcap`. Generate tunnel traffic (the curl test) while it runs. Then open the pcap in Wireshark and apply:

```
tls.handshake.extensions_server_name
```

You will see **Server Name: zoom.us** on connections whose IP destination is your VPS — the claimed name and the real destination disagree. Or without the GUI:

```bash
tshark -r bypass_capture.pcap -Y tls.handshake.extensions_server_name \
       -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

The VPS log shows the same fact server-side, for every tunnel:

```
[vps] tunnel_connect  spoofed_sni=zoom.us  real_target=127.0.0.1:18080  allowed=True
```

---

## Verified behaviour

From the loopback self-test:

```
TEST 1 — honest lab destination through the SNI-spoofing tunnel
  ZRLAB-VPS-ORIGIN: you reached the lab origin through the TLS tunnel. ...

TEST 2 — interlock must REFUSE a public destination
  proxy path returned HTTP 000 for a public destination (refused, good)

VPS observations:
  tunnel_connect  spoofed_sni=zoom.us  real_target=127.0.0.1:18080  allowed=True   reason=loopback/private lab address
  tunnel_connect  spoofed_sni=zoom.us  real_target=8.8.8.8:443      allowed=False  reason=public IP address refused (closed-loop lab interlock)
  tunnel_refused  ...                  real_target=8.8.8.8:443      reason=public IP address refused
```

The forged SNI (`zoom.us`) is presented in **both** cases — the spoof itself always works. The relay only proceeds for the lab destination; the public one is refused **before any socket opens to it**, so nothing is ever sent to `8.8.8.8`.

---

## How the interlock works

`lab2_config.is_forward_allowed(host)` resolves the requested destination and permits the relay only if **every** resulting address is loopback / link-local / RFC1918. A literal public IP is refused directly; a hostname that resolves anywhere public (a real CDN, a video service) is refused too. The refusal is logged loudly and returns a 403 into the tunnel.

An informed operator could set `ZRLAB_ALLOW_PUBLIC_FORWARD=i-understand-this-may-be-fraud` to disable it — it is named that way on purpose, the lab never sets it, and the demo never needs it. The point is that the **shipped default cannot defraud anyone**.

---

## Limitations

1. **It is a demonstration, not a network element.** A plain TCP relay behind a TLS front; no SOCKS5, no HTTP semantics beyond a single CONNECT, no real routing.
2. **The pcap shows the SNI because TLS 1.2/1.3 send it in cleartext.** Encrypted ClientHello (ECH) would hide it — worth noting as the direction real classification/defence is heading.
3. **Closed-loop by construction.** The interlock bounds the relay to lab space. That is a safety property, not a limitation to "fix".
4. **Certificate trust is deliberately loose.** The client disables hostname verification because it is intentionally lying about the SNI; it verifies the endpoint against the lab cert if present. This models "the device trusts the tunnel endpoint", not a hardened PKI.

---

## Responsible use

**Run this only between machines you own, on a network you control, forwarding to lab endpoints you control.**

The safeguards are structural: the relay refuses public destinations by default; the forwarded content stays on the VPS's loopback; the certificate is a throwaway. If you extend the lab, keep those properties. Do not point it at the public internet over a metered or carrier connection — doing so to avoid data charges is billing fraud, full stop.

## Reporting real-world abuse

If you find a genuine zero-rating bypass in a production network, **do not exercise it further** — even to confirm it, since that generates more fraudulent traffic. Report it:

1. The operator's **revenue-assurance / security** team (check `https://<operator>/.well-known/security.txt` or a published disclosure policy — revenue assurance owns this problem class).
2. The operator's **CERT/CSIRT** or abuse contact.
3. Your **national CERT/CSIRT** (directory at `first.org/members`) if the operator has no channel.
4. The **telecoms regulator** where billing integrity is a regulated obligation and the operator is unresponsive.

Describe the mechanism, provide timestamps and your own subscriber identifiers, state that you stopped as soon as you understood the issue, and follow coordinated disclosure.

---

## Standards context

SNI is defined in **IETF RFC 6066** (TLS extensions). Its cleartext nature — and the reason it is both readable by classifiers and writable by clients — is why encrypted-ClientHello work exists. The charging-side context (PCEF classification → rating-groups → OCS over the Diameter Gy interface, 3GPP TS 32.299 / TS 32.240 / TS 23.203) is covered in the sibling detection lab.

---

*Attacker-side companion to [`../zero-rating-detection-lab`](../zero-rating-detection-lab). Closed-loop by construction; defensive in purpose.*

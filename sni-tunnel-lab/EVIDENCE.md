# Telecom Zero-Rating Bypass — End-to-End Lab Guide & Evidence

**Two linked home-lab projects that demonstrate the *attack* and the *defense* for
zero-rating fraud, start to finish, on hardware I own.**

| Lab | Folder | Role | What it proves |
| --- | ------ | ---- | -------------- |
| **Lab 1 — Detection** | `../zero-rating-detection-lab` | the **defense** (OCS engineer's job) | a naive charging classifier is fooled by a spoofed hostname; a cross-validating detector catches and drops it |
| **Lab 2 — Attack** | `sni-tunnel-lab` (this folder) | the **attack** (what defenders face) | a client forges the TLS **SNI = `zoom.us`** and tunnels ordinary traffic to a server that isn't Zoom, provable on the wire in Wireshark |

> **LAB / EDUCATIONAL — closed-loop reference model.** Built from public 3GPP
> concepts (traffic classification → PCC rules → PCEF metering → OCS over the
> Diameter Gy interface, cf. TS 32.299 / TS 32.240). **Not** any operator's
> production system. Lab 2 has a hard interlock that **refuses to relay to any
> public IP** — it only ever forwards to loopback/private lab addresses, so it
> demonstrates the *mechanism* of the bypass without being a usable bypass tool.
> Running an SNI-spoofing tunnel over a real metered carrier link to dodge
> charging is billing fraud; this lab does not do that and cannot be pointed at
> a real network.

---

## The one idea both labs share

A zero-rating classifier has to answer *"which service is this flow?"*, and the
cheapest answer is the hostname the client claims — the HTTP `Host` header, or
the TLS **SNI**. Both are **client-controlled and unauthenticated**.

```
   claimed identity  (Host header / TLS SNI)   <- the client writes this; it can lie
   actual destination (IP the packets go to)   <- the client cannot fake this
```

- **Lab 2** makes those two disagree on purpose: SNI says `zoom.us`, packets go to a lab server.
- **Lab 1** detects exactly that disagreement: it resolves the claimed host and checks whether the real destination is one of its addresses. If not → **bypass**, drop.

The pcap Lab 2 produces is literally the kind of ClientHello Lab 1 inspects.

```
   ┌─────────────────────────┐        forged TLS ClientHello         ┌────────────────────────┐
   │  Lab 2  ATTACK           │   SNI=zoom.us  →  IP=<not zoom>       │  Lab 1  DEFENSE        │
   │  windows_spoofing_client │ ───────────────────────────────────▶ │  detector.py           │
   │  → vps_tunnel_server     │        (captured in Wireshark)        │  resolve(zoom.us);     │
   │                          │                                       │  dest ∉ set → DROP     │
   └─────────────────────────┘                                       └────────────────────────┘
```

---

# PART A — Lab 2: the SNI-spoofing tunnel (the attack)

Roles: **Windows PC = client**, **Linux laptop = VPS**. You can also run both
ends on the Linux box over loopback for a one-machine smoke test.

## A0. Prerequisites

- **Linux (VPS):** Python 3.10+, `openssl`, `tcpdump`, `tshark`
  (`sudo apt install -y python3 openssl tcpdump tshark` — answer **No** to
  "should non-superusers capture packets", you only read pcaps here).
- **Windows (client):** Python 3.10+, and `curl.exe` (built into Windows 10/11).
- Both machines on the same LAN. Note the Linux LAN IP: `hostname -I`
  (this run used **`192.168.1.10`**; the Windows client was **`192.168.1.20`**).

## A1. Get the lab onto the Linux box

From **WSL or Git Bash on Windows** (`/mnt/c/...` in WSL, `/c/...` in Git Bash):

```bash
scp -r /mnt/c/path/to/telecom-zero-rating-lab/sni-tunnel-lab user@192.168.1.10:~/
```

## A2. Generate the tunnel certificate (Linux, once)

```bash
cd ~/sni-tunnel-lab && chmod +x *.sh && ./setup_certs.sh
```

Self-signed, throwaway, local only. The client accepts it without verification
on purpose — the lab exercises the **SNI**, not the PKI.

## A3. Start the VPS (Linux) — leave this running

```bash
cd ~/sni-tunnel-lab && sudo fuser -k 4433/tcp 18080/tcp 2>/dev/null; python3 vps_tunnel_server.py --with-origin
```

**You should see:**

```
[vps] lab_origin_started   addr=127.0.0.1:18080 note=content stays on VPS loopback
[vps] vps_listening        addr=0.0.0.0:4433 public_forwarding=DISABLED (closed-loop) ...
```

`--with-origin` also starts a tiny HTTP origin on the VPS's own loopback, so the
tunnel has something to reach without touching the internet.

## A4. Start the spoofing client (Windows) — leave this running

In **PowerShell**, set the VPS IP and port **and** launch the client **on one
line** (this matters — see Troubleshooting):

```bash
cd C:\path\to\telecom-zero-rating-lab\sni-tunnel-lab; $env:ZRLAB_VPS_IP="192.168.1.10"; $env:ZRLAB_CLIENT_PORT="18088"; python windows_spoofing_client.py
```

**Verify the startup line before continuing** — it must read:

```
client_listening ... addr=127.0.0.1:18088 vps=192.168.1.10:4433 spoofed_sni=zoom.us
```

If `vps=` shows `127.0.0.1`, the env var didn't apply and the client will tunnel
to itself. Fix it before running curl.

## A5. Drive traffic through the tunnel (Windows)

Second PowerShell window. **Use `curl.exe`, not `curl`** (PowerShell aliases
`curl` to a different tool that ignores `--proxytunnel`):

```bash
curl.exe -v --proxytunnel -x 127.0.0.1:18088 http://127.0.0.1:18080/
```

The `127.0.0.1:18080` here is resolved **by the VPS**, on the Linux side — it's
the VPS's own loopback origin.

## A6. Capture it on the wire (Linux)

Run this, then re-run the curl from A5 within 60 seconds. `-U` writes each packet
immediately and `timeout 60` auto-stops, so the file can't be left empty by
buffering:

```bash
cd ~/sni-tunnel-lab && sudo timeout 60 tcpdump -i any -U -s0 -w lan_capture.pcap 'tcp port 4433'
```

Then read the forged SNI straight out of the capture:

```bash
tshark -r lan_capture.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name | sort -u
```

**Expected:** `192.168.1.20   192.168.1.10   zoom.us` — a ClientHello leaving
the Windows PC and arriving at the Linux box, claiming `zoom.us` while addressed
to a machine that is not Zoom.

## A7. Read it in the Wireshark GUI (optional, best for screenshots)

Open `lan_capture.pcap`, apply the display filter:

```
tls.handshake.extensions_server_name
```

Click a ClientHello → **Transport Layer Security → Extension: server_name →
Server Name: zoom.us**. Note the packet's **IP dst** beside it: `192.168.1.10`,
not any Zoom address. That single frame is the whole attack.

---

# PART B — Lab 1: the detector (the defense)

Switch to the sibling folder. This is the OCS engineer's side: the same spoof,
caught.

## B1. Set up and run (Windows or Linux — verified identical on both)

```bash
cd ../zero-rating-detection-lab && python -m venv .venv && ./.venv/bin/pip install -r requirements.txt && bash run_demo.sh
```

(On Windows use `.\.venv\Scripts\Activate.ps1` then `python run_demo.ps1`, or just
`bash run_demo.sh` in Git Bash.)

## B2. What it does

It runs five flows twice — once through a **naive** classifier that trusts the
claimed hostname, once through the **cross-validating detector** — and prints a
before/after summary. The spoofed flows (claimed `zoom.us`, real destination
elsewhere) are **waived for free by the naive classifier** and **dropped by the
detector**.

## B3. The detector's finding (structured JSON it emits)

```json
{ "event":"zero_rating_bypass_detected", "claimed_host":"zoom.us",
  "real_ip":"127.0.0.1", "resolved_ips":["127.0.0.2","203.0.113.10","..."],
  "verdict":"BYPASS_SUSPECTED", "confidence":"HIGH",
  "signals":["claimed_host_resolves_elsewhere","destination_not_publicly_routable"],
  "action":"DROP" }
```

That is Lab 2's forged `zoom.us` ClientHello, described from the defender's seat.

---

# CAPTURED EVIDENCE (this home lab, 2026-08-18)

Real output from the runs, not illustrative.

### Lab 2 — cross-machine tunnel proof (VPS log, Linux `192.168.1.10`)

The Windows client (`192.168.1.20`) reached the Linux VPS over the LAN with a
forged SNI, and the tunnel relayed to the VPS's own loopback origin:

```
[vps] vps_listening   addr=0.0.0.0:4433 public_forwarding=DISABLED (closed-loop)
[vps] tunnel_connect  client=192.168.1.20:55298 spoofed_sni=zoom.us
                      real_target=127.0.0.1:18080 allowed=True reason=loopback/private lab address
[vps] tunnel_closed   client=192.168.1.20:55298 spoofed_sni=zoom.us
                      bytes_client_to_server=79 bytes_server_to_client=338
```

### Lab 2 — the client's view (curl, Windows)

```
> CONNECT 127.0.0.1:18080 HTTP/1.1
< HTTP/1.1 200 Connection established
> GET / HTTP/1.1
< HTTP/1.1 200 OK
ZRLAB-VPS-ORIGIN: you reached the lab origin through the TLS tunnel.
The SNI on the outer connection was spoofed; this content stayed on the VPS's
own loopback and never touched the public internet.
```

### Lab 2 — the closed-loop interlock working

When the same spoof was aimed at a **real public IP**, the VPS refused to relay:

```
[vps] tunnel_connect  spoofed_sni=zoom.us real_target=8.8.8.8:443 allowed=False
                      reason=public IP address refused (closed-loop lab interlock)
[vps] tunnel_refused  real_target=8.8.8.8:443 reason=public IP address refused (closed-loop lab interlock)
```

**The forge happens; the escape does not.** That is what keeps this a lab.

### Lab 2 — the forged SNI on the wire (tshark)

```
tshark -r bypass_capture.pcap -Y tls.handshake.extensions_server_name \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u
127.0.0.1       zoom.us
```

(Loopback run shown; the two-machine capture from A6 yields
`192.168.1.20  192.168.1.10  zoom.us`.)

### Lab 1 — the detector catching it (before/after summary)

```
  naive classifier    : 128.4 KiB waived on unverified claims  (2 spoofed flows believed)
  cross-validating    : 0 B      waived on unverified claims  (2 spoofed flows dropped)
  leakage prevented   : 128.4 KiB  (100% of the attempted bypass)
  false positives     : 0   (out of 2 genuine zero-rated flows offered)
```

Verified identical on Windows 11 and Ubuntu 24.04.

---

# TROUBLESHOOTING (every issue actually hit, and the fix)

| Symptom | Cause | Fix |
| ------- | ----- | --- |
| `curl: (56) Proxy CONNECT aborted` | Client can't reach the VPS — it's dialing `127.0.0.1` (itself) | The client's `vps=` line shows `127.0.0.1`. Set `$env:ZRLAB_VPS_IP` **in the same PowerShell window** as `python`, and confirm the startup line reads `vps=192.168.1.10:4433`. |
| `OSError: [Errno 98] Address already in use` | Default client port `8080` is taken on the box | Use `ZRLAB_CLIENT_PORT=18088` (already in the commands above). |
| Empty pcap / `tshark ... \| wc -l` = 0 | No traffic crossed, or tcpdump buffer not flushed | Confirm the VPS logs `tunnel_connect` when you curl; capture with `sudo timeout 60 tcpdump -i any -U ...`. |
| `curl` ignores `--proxytunnel` in PowerShell | `curl` is aliased to `Invoke-WebRequest` | Use `curl.exe`. |
| Windows can't reach `192.168.1.10:4433` | Linux firewall | `sudo ufw allow 4433/tcp` (only if `ufw` is active). Verify with `Test-NetConnection 192.168.1.10 -Port 4433` → `TcpTestSucceeded : True`. |
| Ports stuck across runs | A previous run's process still bound | `sudo fuser -k 4433/tcp 18080/tcp 18088/tcp` |
| Wrong Linux IP (DHCP changed it) | `192.168.1.10` no longer valid | `hostname -I` on Linux; use whatever it shows. |

---

# WHAT THIS DEMONSTRATES (portfolio summary)

On two real machines, end to end:

1. **Attack (Lab 2):** a Windows client forges the TLS SNI to `zoom.us` and
   tunnels ordinary traffic to a Linux endpoint — captured on the wire, the
   ClientHello says `zoom.us` while the IP destination is the Linux box.
2. **Containment:** the VPS records every spoof and **refuses any public relay**,
   so the lab shows the mechanism without being a working fraud tool.
3. **Defense (Lab 1):** a cross-validating classifier resolves the claimed host,
   sees the real destination isn't one of its addresses, flags
   `BYPASS_SUSPECTED / HIGH`, and drops the flow — recovering 100% of the
   attempted revenue leakage with zero false positives.

**The strongest single screenshot** pairs the Wireshark ClientHello
(`Server Name: zoom.us`, `IP dst: 192.168.1.10`) with the VPS log line
(`client=192.168.1.20 spoofed_sni=zoom.us`) and Lab 1's
`zero_rating_bypass_detected` finding: attack on one machine, detection on the
other, in one frame.

---

# RESPONSIBLE USE

This is a defensive, closed-loop teaching lab. Do not point the client at a VPS
you would use to reach the public internet over a metered carrier link — that is
billing fraud. Lab 2's interlock refuses public relay by construction. If you
ever discover a genuine zero-rating bypass in a production network, **stop and
report it** to the operator's revenue-assurance/security team, their CERT, or the
national regulator — do not keep exercising it. See
`../zero-rating-detection-lab/README.md` for the full responsible-use and
reporting guidance.

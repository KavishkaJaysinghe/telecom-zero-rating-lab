#!/usr/bin/env bash
# =============================================================================
#  LAB / EDUCATIONAL — SNI-spoofing tunnel, CLOSED-LOOP reference model.
# =============================================================================
#
#  sni-tunnel-lab :: capture_demo.sh          [ run on the Linux box, ONE command ]
#
#  Does the whole Wireshark demo in a single command, no second terminal:
#    1. clears any leftover lab processes on the lab ports,
#    2. makes sure the lab cert exists,
#    3. starts tcpdump on the tunnel port,
#    4. starts the VPS endpoint (+ its own lab origin) and the spoofing client,
#    5. drives one HONEST request and one REFUSED (public) request through the
#       tunnel, both presenting SNI=zoom.us,
#    6. stops the capture and prints the captured SNIs,
#    7. leaves bypass_capture.pcap for you to open in Wireshark.
#
#  tcpdump needs root, so run the whole thing with sudo:
#
#       sudo ./capture_demo.sh
#
#  Everything runs as root here (loopback lab, no privilege concern); the pcap
#  is handed back to your login user at the end so Wireshark can open it.
#
#  Then open bypass_capture.pcap in Wireshark and filter:
#       tls.handshake.extensions_server_name
#  You will see Server Name: zoom.us on packets whose IP dst is 127.0.0.1.
# =============================================================================
set -u
cd "$(dirname "$0")"

PORT="${ZRLAB_VPS_PORT:-4433}"
IFACE="${ZRLAB_CAPTURE_IFACE:-any}"   # 'any' includes loopback on Linux
CLIENT_PORT="${ZRLAB_CLIENT_PORT:-18088}"
ORIGIN_PORT="${ZRLAB_ORIGIN_PORT:-18080}"
OUT="bypass_capture.pcap"

# Export the ports so the Python processes (run as our own children, NOT via
# sudo -u) actually see them. This is the fix for the earlier failure: sudo -u
# strips the environment, so the client fell back to its default port 8080.
export ZRLAB_VPS_PORT="$PORT" ZRLAB_CLIENT_PORT="$CLIENT_PORT" ZRLAB_ORIGIN_PORT="$ORIGIN_PORT"

RUN_USER="${SUDO_USER:-$(id -un)}"
PY="$(command -v python3 || command -v python)"
[ -n "$PY" ] || { echo "python3 not found"; exit 1; }
command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump not found: sudo apt install tcpdump"; exit 1; }

mkdir -p logs
VPS_PID=""; CLIENT_PID=""; TCPDUMP_PID=""
cleanup() {
  [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null
  [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
  [ -n "$VPS_PID" ] && kill "$VPS_PID" 2>/dev/null
}
trap cleanup EXIT

# 0. Self-heal: clear any leftover lab process still holding the lab ports.
#    We are root here, so this reaches processes of any owner. Only the lab's
#    own ports are touched — never 8080 or anything else on the box.
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${PORT}/tcp" "${ORIGIN_PORT}/tcp" "${CLIENT_PORT}/tcp" 2>/dev/null || true
  sleep 1
fi

wait_port() {
  for _ in $(seq 1 40); do
    "$PY" -c "import socket,sys;s=socket.socket();s.settimeout(0.4);sys.exit(0 if s.connect_ex(('$1',$2))==0 else 1)" 2>/dev/null && return 0
    sleep 0.25
  done; return 1
}

# 1. certificate
if [ ! -f certs/lab-vps-cert.pem ]; then
  if command -v openssl >/dev/null 2>&1; then bash setup_certs.sh
  else "$PY" vps_tunnel_server.py --autocert; fi
fi

# 2. capture
echo "Starting capture on '$IFACE' tcp port $PORT -> $OUT"
tcpdump -i "$IFACE" -s0 -w "$OUT" "tcp port $PORT" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# 3. VPS + origin, then client (all as root children -> env is inherited)
"$PY" vps_tunnel_server.py --with-origin >logs/_vps.out 2>&1 &
VPS_PID=$!
wait_port 127.0.0.1 "$PORT"        || { echo "VPS failed";    cat logs/_vps.out; exit 1; }
wait_port 127.0.0.1 "$ORIGIN_PORT" || { echo "origin failed"; cat logs/_vps.out; exit 1; }

"$PY" windows_spoofing_client.py >logs/_client.out 2>&1 &
CLIENT_PID=$!
wait_port 127.0.0.1 "$CLIENT_PORT" || { echo "client failed"; cat logs/_client.out; exit 1; }

# 4. drive traffic through the tunnel (both present SNI=zoom.us)
echo "Driving tunnel traffic (honest + refused-public)..."
curl -s --max-time 10 --proxytunnel -x 127.0.0.1:"$CLIENT_PORT" \
  "http://127.0.0.1:${ORIGIN_PORT}/" >/dev/null 2>&1 || true
curl -s --max-time 8  --proxytunnel -x 127.0.0.1:"$CLIENT_PORT" \
  https://8.8.8.8/ >/dev/null 2>&1 || true
sleep 1

# 5. stop capture, hand the file back to the login user
kill "$TCPDUMP_PID" 2>/dev/null; TCPDUMP_PID=""
sleep 0.5
chown "$RUN_USER" "$OUT" 2>/dev/null || true

echo
echo "================================================================"
echo " VPS observed (claimed SNI vs real destination):"
echo "================================================================"
grep -E "tunnel_connect|tunnel_refused" logs/_vps.out | sed 's/^/  /'

echo
echo "================================================================"
echo " Spoofed SNI in the capture:"
echo "================================================================"
if command -v tshark >/dev/null 2>&1; then
  tshark -r "$OUT" -Y tls.handshake.extensions_server_name \
    -T fields -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null \
    | awk 'NF{print "  ip.dst="$1"  SNI="$2}' | sort -u
  echo
  echo "  ^ SNI=zoom.us while ip.dst=127.0.0.1 (your VPS) — the claim and the"
  echo "    destination disagree. That is the bypass signal the detector catches."
else
  echo "  tshark not installed. Open $OUT in Wireshark and filter:"
  echo "      tls.handshake.extensions_server_name"
  echo "  or: sudo apt install -y tshark  and re-run."
fi

echo
echo "Saved $OUT — open it in Wireshark any time (filter above)."

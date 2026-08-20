#!/usr/bin/env bash
# =============================================================================
#  LAB / EDUCATIONAL — SNI-spoofing tunnel, CLOSED-LOOP reference model.
# =============================================================================
#
#  sni-tunnel-lab :: smoke_test.sh
#
#  One-machine self-test: runs the VPS endpoint (with its own lab origin) and
#  the spoofing client on loopback, drives one request through the tunnel with
#  curl, and shows that the VPS observed SNI=zoom.us while the real destination
#  was the loopback origin. Also confirms the interlock refuses a public IP.
#
#  This proves the code works before you split it across two machines. It needs
#  Python 3 and (for --autocert) the 'cryptography' package; on the real VPS you
#  will instead run ./setup_certs.sh with openssl.
#
#     ./smoke_test.sh
# =============================================================================
set -u
cd "$(dirname "$0")"

PY="${ZRLAB_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
# Client on a high port so the test never collides with a local 8080 service.
export ZRLAB_CLIENT_PORT="${ZRLAB_CLIENT_PORT:-18088}"
mkdir -p logs

wait_port() {
  for _ in $(seq 1 40); do
    "$PY" -c "import socket,sys;s=socket.socket();s.settimeout(0.4);sys.exit(0 if s.connect_ex(('$1',$2))==0 else 1)" 2>/dev/null && return 0
    sleep 0.25
  done; return 1
}

cleanup() { [ -n "${VPS_PID:-}" ] && kill "$VPS_PID" 2>/dev/null; [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null; }
trap cleanup EXIT

# Certs: prefer openssl-made ones; fall back to --autocert.
if [ ! -f certs/lab-vps-cert.pem ]; then
  if command -v openssl >/dev/null 2>&1; then bash setup_certs.sh; else AUTOCERT=--autocert; fi
fi

"$PY" vps_tunnel_server.py --with-origin ${AUTOCERT:-} >logs/_vps.out 2>&1 &
VPS_PID=$!
# Wait for BOTH the TLS endpoint (4433) and the embedded lab origin (18080),
# or the first request races origin startup and stalls.
wait_port 127.0.0.1 4433  || { echo "VPS failed to start"; cat logs/_vps.out; exit 1; }
wait_port 127.0.0.1 18080 || { echo "lab origin failed to start"; cat logs/_vps.out; exit 1; }

"$PY" windows_spoofing_client.py >logs/_client.out 2>&1 &
CLIENT_PID=$!
wait_port 127.0.0.1 "$ZRLAB_CLIENT_PORT" || { echo "client failed"; cat logs/_client.out; exit 1; }

echo "================================================================"
echo " TEST 1 — honest lab destination through the SNI-spoofing tunnel"
echo "================================================================"
curl -s --max-time 10 --proxytunnel -x 127.0.0.1:"$ZRLAB_CLIENT_PORT" http://127.0.0.1:18080/
echo
echo "================================================================"
echo " TEST 2 — interlock must REFUSE a public destination"
echo "================================================================"
code=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" \
  --proxytunnel -x 127.0.0.1:"$ZRLAB_CLIENT_PORT" https://8.8.8.8/ 2>/dev/null)
echo "proxy path returned HTTP ${code:-000} for a public destination (000/403 = refused, good)"
echo
echo "================================================================"
echo " VPS observations (note spoofed_sni vs real_target)"
echo "================================================================"
grep -E "tunnel_connect|tunnel_refused" logs/_vps.out | tail -6

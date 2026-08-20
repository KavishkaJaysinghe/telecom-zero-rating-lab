#!/usr/bin/env bash
# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: run_demo.sh
#
#  Runs the whole three-part story end to end against the local loopback
#  origin, then prints a before/after summary:
#
#     (a) legitimate traffic is charged correctly by the naive classifier
#     (b) SPOOFED traffic fools the naive classifier — the meter fails to bill
#     (c) the SAME spoofed traffic is caught and dropped by the detector
#
#  Works in bash on Linux/macOS and in Git Bash on Windows.
#  For native PowerShell, use run_demo.ps1 instead.
#
#  Nothing in this script contacts a network. Every listener and every target
#  is a 127.0.0.0/8 address on this machine.
# =============================================================================

set -uo pipefail

cd "$(dirname "$0")"

# --- resolve the interpreter -------------------------------------------------
# Prefer the project virtualenv if one exists, so the demo is reproducible.
if [ -x ".venv/Scripts/python.exe" ]; then          # Windows venv layout
  PY=".venv/Scripts/python.exe"
  MITMDUMP=".venv/Scripts/mitmdump.exe"
elif [ -x ".venv/bin/python" ]; then                 # POSIX venv layout
  PY=".venv/bin/python"
  MITMDUMP=".venv/bin/mitmdump"
else
  PY="$(command -v python3 || command -v python)"
  MITMDUMP="$(command -v mitmdump)"
fi

if [ -z "${PY:-}" ] || [ ! -x "$PY" ] && ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: no python interpreter found. See README setup instructions." >&2
  exit 1
fi
if [ -z "${MITMDUMP:-}" ]; then
  echo "ERROR: mitmdump not found. Run: pip install -r requirements.txt" >&2
  exit 1
fi

# Force ANSI colour through the pipe so the naive-vs-detector contrast is
# visible in a screenshot even when output is not a tty.
export ZRLAB_FORCE_COLOR=1
# Belt-and-braces: pin the offline resolver so the demo emits zero DNS queries.
export ZRLAB_RESOLVER=fixture

# Single source of truth for the lab topology is lab_config.py — read it here
# rather than duplicating port numbers in the shell.
eval "$("$PY" -c "
import lab_config as c
print(f'PROXY_HOST={c.PROXY_HOST}')
print(f'PROXY_PORT={c.PROXY_PORT}')
print(f'HTTP_PORT={c.ORIGIN_HTTP_PORT}')
print(f'HTTPS_PORT={c.ORIGIN_HTTPS_PORT}')
print(f'ZR_IP={c.ORIGIN_ZERO_RATED_IP}')
print(f'CH_IP={c.ORIGIN_CHARGED_IP}')
")"
READY_FILE="logs/.origin-ready"

# --- pre-flight: are the ports we need actually free? ------------------------
# 8080/8443/8081 collide with a running web server on many dev machines, which
# is why the defaults are in the 18xxx range. Fail early and say which is busy.
preflight_ports() {
  "$PY" - "$PROXY_HOST" "$PROXY_PORT" "$ZR_IP" "$CH_IP" "$HTTP_PORT" "$HTTPS_PORT" <<'PYEOF'
import socket, sys
proxy_host, proxy_port, zr_ip, ch_ip, http_port, https_port = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
)
targets = [(proxy_host, proxy_port, "proxy (ZRLAB_PROXY_PORT)")]
for ip in (zr_ip, ch_ip):
    targets.append((ip, http_port, "origin http (ZRLAB_HTTP_PORT)"))
    targets.append((ip, https_port, "origin https (ZRLAB_HTTPS_PORT)"))
busy = []
for ip, port, label in targets:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((ip, port))
    except OSError as exc:
        busy.append(f"  {ip}:{port}  [{label}]  -> {exc}")
    finally:
        s.close()
if busy:
    print("ERROR: these lab ports are not available:", file=sys.stderr)
    print("\n".join(busy), file=sys.stderr)
    print("\nOverride them, e.g.:", file=sys.stderr)
    print("  ZRLAB_PROXY_PORT=19081 ZRLAB_HTTP_PORT=19080 ZRLAB_HTTPS_PORT=19443 ./run_demo.sh",
          file=sys.stderr)
    sys.exit(1)
PYEOF
}

ORIGIN_PID=""
PROXY_PID=""

cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "$ORIGIN_PID" ] && kill "$ORIGIN_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

banner() {
  echo ""
  echo "================================================================================"
  echo "  $1"
  echo "================================================================================"
}

# Wait for a TCP listener to accept connections (portable, no netcat needed).
wait_for_port() {
  local host="$1" port="$2" tries="${3:-60}"
  for _ in $(seq 1 "$tries"); do
    if "$PY" -c "
import socket,sys
s=socket.socket()
s.settimeout(0.4)
sys.exit(0 if s.connect_ex(('$host',$port))==0 else 1)
" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# Start one mitmdump phase, run the attacker scenarios through it, stop it.
run_phase() {
  local addon="$1" phase="$2" label="$3"

  banner "$label"
  echo "  addon      : $addon"
  echo "  proxy      : $PROXY_HOST:$PROXY_PORT"
  echo "  scenarios  : legit-charged, legit-zerorated, spoof-http,"
  echo "               legit-zerorated-tls, spoof-tls"
  echo ""

  # --ssl-insecure: the lab origin uses a self-signed local certificate.
  # --set connection_strategy=eager: connect upstream before replying, so the
  #   real destination is known at request time.
  # --set termlog_verbosity=warn / flow_detail=0: silence mitmproxy's own
  #   request chatter, so what reaches the terminal is the ADDON's charging
  #   and detection log lines and nothing else.
  #
  # Output is tee'd rather than redirected: the addon's decision lines are the
  # whole point of the demo and belong on screen, but a copy still lands in
  # logs/ for debugging a failed start. Process substitution keeps $! as the
  # mitmdump PID (a pipeline would give us tee's instead).
  "$MITMDUMP" \
    -s "$addon" \
    --listen-host "$PROXY_HOST" \
    --listen-port "$PROXY_PORT" \
    --set connection_strategy=eager \
    --set termlog_verbosity=warn \
    --set flow_detail=0 \
    --ssl-insecure \
    > >(tee "logs/mitmdump_${phase}.out") 2>&1 &
  PROXY_PID=$!

  if ! wait_for_port "$PROXY_HOST" "$PROXY_PORT"; then
    echo "ERROR: proxy did not come up. See logs/mitmdump_${phase}.out" >&2
    cat "logs/mitmdump_${phase}.out" >&2
    exit 1
  fi

  "$PY" attacker_client.py --phase "$phase" --shutdown-proxy

  # The harness's --shutdown-proxy asks the addon to stop gracefully so it
  # writes its final CCR-T and meter report. Give it a moment, then insist.
  for _ in $(seq 1 20); do
    kill -0 "$PROXY_PID" 2>/dev/null || break
    sleep 0.25
  done
  kill "$PROXY_PID" 2>/dev/null
  wait "$PROXY_PID" 2>/dev/null
  PROXY_PID=""
}

# =============================================================================
#  Go
# =============================================================================
banner "ZERO-RATING BYPASS DETECTION LAB"
cat <<'INTRO'
  Simplified reference model built from public 3GPP concepts: traffic
  classification feeds charging rules, the packet gateway (PCEF) meters usage
  to the OCS over the Diameter Gy interface (cf. 3GPP TS 32.299, TS 32.240).

  This is NOT any operator's production system and contains no operator data.
  Every listener and every target below is a 127.0.0.0/8 loopback address.
  Nothing in this demo touches, probes, or depends on a real network.
INTRO

# Fresh evidence for every run.
rm -rf logs
mkdir -p logs

preflight_ports || exit 1

banner "STEP 0 — start the local origin server (loopback only)"
"$PY" local_test_server.py --ready-file "$READY_FILE" &
ORIGIN_PID=$!
if ! wait_for_port "$CH_IP" "$HTTP_PORT" || ! wait_for_port "$ZR_IP" "$HTTPS_PORT"; then
  echo "ERROR: local origin failed to start. See logs/local_test_server.jsonl" >&2
  exit 1
fi
echo "  $ZR_IP:$HTTP_PORT/$HTTPS_PORT  = genuine zero-rated service (zoom.us in dns_fixtures.json)"
echo "  $CH_IP:$HTTP_PORT/$HTTPS_PORT  = ordinary chargeable content"

run_phase classifier_naive.py naive \
  "STEP 1+2 — NAIVE CLASSIFIER: legit traffic charged, spoofed traffic waived"

run_phase detector.py detector \
  "STEP 3 — CROSS-VALIDATING DETECTOR: the same spoofed traffic is dropped"

banner "SUMMARY"
"$PY" demo_report.py

echo ""
echo "  Responsible use: this lab is for validating defensive detection logic on"
echo "  equipment you own. Do not run the attacker harness against any network"
echo "  you do not control. See the README for how to report real-world abuse."
echo ""

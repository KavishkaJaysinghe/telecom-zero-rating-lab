#!/usr/bin/env bash
# =============================================================================
#  LAB / EDUCATIONAL — SNI-spoofing tunnel, CLOSED-LOOP reference model.
# =============================================================================
#
#  sni-tunnel-lab :: record_traffic.sh
#
#  Captures 60 seconds of traffic on the tunnel port into bypass_capture.pcap,
#  so you can open it in Wireshark and SEE the forged SNI in the ClientHello.
#
#  Run this on the Linux "VPS", as root (tcpdump needs raw-socket access):
#     sudo ./record_traffic.sh
#
#  Then generate some tunnel traffic from the Windows client (the curl test in
#  the README). When capture finishes, open the pcap in Wireshark and apply:
#
#       tls.handshake.extensions_server_name
#
#  You will see  Server Name: zoom.us  on connections whose IP destination is
#  your VPS / lab origin — the claim and the destination disagree, which is
#  precisely the signal the detector cross-validates.
#
#  tshark one-liner (no GUI needed) to print the captured SNIs:
#     tshark -r bypass_capture.pcap -Y tls.handshake.extensions_server_name \
#            -T fields -e ip.dst -e tls.handshake.extensions_server_name
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"

PORT="${ZRLAB_VPS_PORT:-4433}"
IFACE="${ZRLAB_CAPTURE_IFACE:-any}"
DURATION="${ZRLAB_CAPTURE_SECONDS:-60}"
OUT="bypass_capture.pcap"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump not found. Install it: sudo apt install tcpdump" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Note: tcpdump usually needs root. If this fails, re-run with sudo." >&2
fi

echo "Capturing TCP port $PORT on interface '$IFACE' for ${DURATION}s -> $OUT"
echo "Generate tunnel traffic now (run the curl test on the Windows client)."
echo

# -G <secs> -W 1 rotates once after DURATION and exits; timeout is a backstop
# in case the environment ignores -W. Both keep the capture to ~DURATION.
timeout "$((DURATION + 2))" \
  tcpdump -i "$IFACE" -s 0 -w "$OUT" -G "$DURATION" -W 1 "tcp port $PORT" \
  || true

echo
if [ -f "$OUT" ]; then
  echo "Saved $OUT ($(du -h "$OUT" | cut -f1))."
  echo "Inspect the spoofed SNI with:"
  echo "  tshark -r $OUT -Y tls.handshake.extensions_server_name \\"
  echo "         -T fields -e ip.dst -e tls.handshake.extensions_server_name"
else
  echo "No capture file produced — check permissions and the interface name." >&2
fi

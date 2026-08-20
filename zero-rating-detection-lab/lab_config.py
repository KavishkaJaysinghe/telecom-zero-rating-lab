# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: lab_config.py
#
#  Shared configuration for the whole lab. Every knob that a reviewer might
#  want to change lives here so the addons themselves stay readable.
#
#  SCOPE NOTE: This is a SIMPLIFIED REFERENCE MODEL built from public 3GPP
#  concepts (traffic classification -> charging rules -> PCEF metering ->
#  OCS over the Diameter Gy interface, cf. 3GPP TS 32.299 / TS 32.240).
#  It is NOT any operator's production system, contains no real operator
#  data, and every address below is loopback or an RFC 5737 documentation
#  address. Nothing here resolves or connects to the public Internet.
# =============================================================================

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
LOG_DIR = PROJECT_ROOT / "logs"
CERT_DIR = PROJECT_ROOT / "certs"
DNS_FIXTURE_FILE = PROJECT_ROOT / "dns_fixtures.json"

# --------------------------------------------------------------------------
# Lab network layout (all loopback — see SCOPE NOTE above)
# --------------------------------------------------------------------------
# The lab origin server binds two loopback aliases so that we can model
# "two different destination IPs" without leaving the machine:
#
#   127.0.0.2  = where the *genuine* zero-rated service lives in this lab.
#   127.0.0.1  = where ordinary, chargeable content lives.
#
# A spoofing client claims Host/SNI "zoom.us" (which the lab DNS fixture maps
# to 127.0.0.2) while actually connecting to 127.0.0.1. That IP mismatch is
# precisely what detector.py catches.
ORIGIN_ZERO_RATED_IP = "127.0.0.2"  # genuine zero-rated service address
ORIGIN_CHARGED_IP = "127.0.0.1"  # ordinary chargeable content address

# Ports are in the high range on purpose: 8080/8443/8081 collide with an
# already-running web server on a lot of developer machines. Override any of
# them via the environment if these clash too — run_demo does a pre-flight
# check and tells you which one is busy.
ORIGIN_HTTP_PORT = int(os.environ.get("ZRLAB_HTTP_PORT", "18080"))
ORIGIN_HTTPS_PORT = int(os.environ.get("ZRLAB_HTTPS_PORT", "18443"))

# Proxy port that the mitmproxy addons listen on. Only ONE addon runs at a
# time (naive OR detector) so both can reuse the same port.
PROXY_PORT = int(os.environ.get("ZRLAB_PROXY_PORT", "18081"))
PROXY_HOST = "127.0.0.1"

# Size of the canned response body the lab origin returns, in bytes. Fixed so
# that the charging meter produces clean, screenshot-friendly numbers.
ORIGIN_PAYLOAD_BYTES = 64 * 1024  # 64 KiB

# --------------------------------------------------------------------------
# Charging policy — the "zero-rating whitelist"
# --------------------------------------------------------------------------
# In a real network this list is not a Python set; it is a set of PCC rules
# with rating-groups / service-identifiers provisioned onto the PCEF, where
# the zero-rated rating-group is configured for 0-rate (or is simply not
# reported to the OCS). We model it as a hostname allow-list because that is
# the layer the attack targets.
ZERO_RATED_HOSTS = {
    "zoom.us",
    "teams.microsoft.com",
    "edu.lab-origin.local",
}

# Rating-group IDs are cosmetic here, but they make the log lines look like
# something an OCS engineer would actually recognise on a Gy trace.
RATING_GROUP_ZERO_RATED = 100  # 0-rated bucket
RATING_GROUP_STANDARD = 200  # standard metered bucket
SERVICE_ID_HTTP = 1

# Match subdomains too? "zoom.us" then also zero-rates "api.zoom.us".
# Operators do this a lot, and it widens the spoofing surface — see README.
ZERO_RATE_MATCH_SUBDOMAINS = True

# --------------------------------------------------------------------------
# Subscriber / quota model (conceptual Gy, TS 32.299 style)
# --------------------------------------------------------------------------
SUBSCRIBER_MSISDN = "+99900000001"  # fictional, reserved-style test number
SUBSCRIBER_IMSI = "999990000000001"  # MCC 999 = reserved for testing
INITIAL_QUOTA_BYTES = 1 * 1024 * 1024  # 1 MiB starting balance
QUOTA_GRANT_BYTES = 256 * 1024  # Granted-Service-Unit per CCR-U

# --------------------------------------------------------------------------
# Detector configuration
# --------------------------------------------------------------------------
# Resolver mode:
#   "fixture" (default) — resolve claimed hostnames from dns_fixtures.json.
#                         Fully offline and deterministic. No DNS packets are
#                         emitted. This is what the demo uses.
#   "system"            — use the OS resolver (socket.getaddrinfo). Only for
#                         experimenting on your own machine; it does emit real
#                         DNS queries, so the demo does NOT use it.
RESOLVER_MODE = os.environ.get("ZRLAB_RESOLVER", "fixture")

# How long a resolved IP set stays cached, seconds. Mirrors the fact that a
# real PCEF/probe would keep a short-lived DNS observation cache rather than
# resolving per packet.
RESOLVER_CACHE_TTL = 60

# --- False-positive controls (see README "Residual false-positive risk") ----
#
# CDN tolerance. A zero-rated hostname routinely resolves to a large, rotating
# set of edge IPs, and the set the *subscriber's* resolver saw may differ from
# the set the detector sees. Two dampeners:
#
#  1. PREFIX_TOLERANCE_BITS: accept a destination that falls inside the same
#     network prefix as any resolved IP, not just an exact match. 32 = exact
#     match only (strictest). 24 = accept anything in the same /24, which
#     covers most single-CDN-POP rotation. Widening this trades detection
#     sensitivity for fewer false positives.
PREFIX_TOLERANCE_BITS_V4 = 24
PREFIX_TOLERANCE_BITS_V6 = 48

#  2. Only *drop* on HIGH confidence. MEDIUM findings are logged for offline
#     revenue-assurance review but are allowed through, because the most
#     common cause of a MEDIUM finding is benign CDN/DNS skew, not fraud.
DROP_ON_CONFIDENCE = {"HIGH"}

# Destinations that can never legitimately host a public zero-rated service.
# A claimed zero-rated host pointing at one of these is a very strong signal.
# (In this lab that is exactly how the spoof presents itself; in a real
# deployment the equivalent check is "destination is not in the service's
# published prefix set / not in the partner's ASN".)
IMPLAUSIBLE_DEST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# NOTE for the lab: the genuine zero-rated origin also lives on loopback
# (127.0.0.2), which would trip IMPLAUSIBLE_DEST_NETWORKS for *everything*.
# So the implausibility check only fires when the destination is ALSO absent
# from the resolved set. Genuine traffic to 127.0.0.2 matches the fixture and
# is cleared before that check is ever reached. See detector.py.

# Enforcement action on a dropped flow:
#   "kill"     — tear the connection down with no response (models a PCEF
#                gate-close / packet drop). This is the default because it is
#                what the charging enforcement point actually does.
#   "block403" — return a 403 with a JSON verdict body. Friendlier for
#                debugging and screenshots of the client side.
ENFORCEMENT_MODE = os.environ.get("ZRLAB_ENFORCEMENT", "kill")

# --------------------------------------------------------------------------
# Lab control channel
# --------------------------------------------------------------------------
# run_demo needs to stop each addon *gracefully* so its CCR-T / final report
# is written, and portable process signalling across Windows/Linux/macOS
# shells is unreliable. So the addons answer one in-band control request:
#
#     GET http://zrlab.control/shutdown   ->  ctx.master.shutdown()
#
# It is handled before classification, is never metered, and never reaches a
# network. Obviously a real charging node would not expose anything like this;
# it exists purely so the demo script has a clean stop.
CONTROL_HOST = "zrlab.control"


def handle_control_request(flow, log) -> bool:
    """Answer the lab control request, if this flow is one. Returns True if so.

    Called first thing in each addon's `request` hook. The mitmproxy imports
    are deliberately local: lab_config is also imported by demo_report.py and
    by the test harness, neither of which should require mitmproxy.
    """
    from mitmproxy import ctx, http  # local import - see docstring

    host = normalise_host(flow.request.host_header) or normalise_host(
        flow.request.pretty_host
    )
    if host != CONTROL_HOST:
        return False

    flow.metadata["zrlab_control"] = True
    flow.response = http.Response.make(
        200, b'{"lab":"control","action":"shutdown"}', {"Content-Type": "application/json"}
    )
    log.info("lab_control_shutdown", note="graceful stop requested by run_demo")
    ctx.master.shutdown()
    return True

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def normalise_host(host: str | None) -> str:
    """Lower-case, strip any :port, strip trailing dot and IPv6 brackets."""
    if not host:
        return ""
    h = host.strip().lower()
    if h.startswith("["):  # [::1]:8443
        end = h.find("]")
        if end != -1:
            return h[1:end]
    if h.count(":") == 1:  # host:port (never IPv6, those have >1 colon)
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def is_zero_rated(host: str | None) -> bool:
    """Would the operator's charging policy zero-rate this claimed hostname?"""
    h = normalise_host(host)
    if not h:
        return False
    if h in ZERO_RATED_HOSTS:
        return True
    if ZERO_RATE_MATCH_SUBDOMAINS:
        return any(h.endswith("." + z) for z in ZERO_RATED_HOSTS)
    return False


def load_dns_fixtures() -> dict[str, list[str]]:
    """Load the offline DNS map used by RESOLVER_MODE='fixture'."""
    if not DNS_FIXTURE_FILE.exists():
        return {}
    with DNS_FIXTURE_FILE.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    # Ignore the leading "_comment" key and normalise host keys.
    return {
        normalise_host(k): list(v)
        for k, v in raw.items()
        if not k.startswith("_") and isinstance(v, list)
    }


def human_bytes(n: int) -> str:
    """Format a byte count for human-readable log/summary output."""
    step = 1024.0
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(value) < step or unit == "GiB":
            return f"{value:,.1f} {unit}" if unit != "B" else f"{int(value):,} B"
        value /= step
    return f"{value:,.1f} GiB"

# =============================================================================
#  LAB / EDUCATIONAL — SNI-spoofing tunnel, CLOSED-LOOP reference model.
#  Run only between machines you own. Do not forward to the public internet
#  over a metered/carrier link — that is billing fraud, not a demo.
# =============================================================================
#
#  sni-tunnel-lab :: lab2_config.py
#
#  Shared configuration for the two-machine SNI-spoofing tunnel lab.
#
#  WHAT THIS LAB IS
#  ----------------
#  A deliberately SMALL, closed-loop demonstration of one fact: the TLS SNI a
#  client puts in its ClientHello is unauthenticated, so a client can present
#  SNI="zoom.us" while actually tunnelling to an entirely different endpoint.
#  This is the attacker side of the zero-rating story whose DEFENCE lives in
#  ../zero-rating-detection-lab (detector.py cross-validates the claimed SNI
#  against the real destination and catches exactly this).
#
#  WHAT THIS LAB IS NOT
#  --------------------
#  It is NOT a working zero-rating bypass against a real network, and it is
#  built so it cannot become one by accident:
#
#    * The VPS forwards ONLY to loopback / RFC1918 / lab addresses. Out of the
#      box it will refuse to relay to a public IP (see is_forward_allowed()).
#      So even if you CONNECT to youtube.com through it, the relay is denied.
#    * The whole point is observable on the wire (the forged SNI in the pcap),
#      not the content — content never needs to leave the VPS's own loopback.
#
#  Running an SNI-spoofing tunnel over a metered mobile connection to avoid
#  data charges is billing fraud: a criminal offence in most jurisdictions and
#  a breach of every operator's terms of service. This lab exists to help you
#  DETECT that, which is your job as an OCS engineer — not to perform it.
# =============================================================================

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CERT_DIR = PROJECT_ROOT / "certs"
CERT_FILE = CERT_DIR / "lab-vps-cert.pem"
KEY_FILE = CERT_DIR / "lab-vps-key.pem"
LOG_DIR = PROJECT_ROOT / "logs"

# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------
# The VPS (Linux laptop) binds all interfaces so the Windows client can reach
# it across your LAN. Both machines are yours, on your own network.
VPS_LISTEN_HOST = os.environ.get("ZRLAB_VPS_LISTEN", "0.0.0.0")
VPS_PORT = int(os.environ.get("ZRLAB_VPS_PORT", "4433"))

# Where the Windows client dials. Defaults to loopback so the whole lab can be
# smoke-tested on ONE machine; set ZRLAB_VPS_IP to the Linux laptop's LAN IP
# (e.g. 192.168.1.10) for the real two-machine run.
VPS_IP = os.environ.get("ZRLAB_VPS_IP", "127.0.0.1")

# The Windows-side local proxy the browser / curl points at.
CLIENT_LISTEN_HOST = os.environ.get("ZRLAB_CLIENT_LISTEN", "127.0.0.1")
CLIENT_LISTEN_PORT = int(os.environ.get("ZRLAB_CLIENT_PORT", "8080"))

# The forged SNI. This is the entire trick: a name the operator would zero-rate.
SPOOFED_SNI = os.environ.get("ZRLAB_SPOOFED_SNI", "zoom.us")

# Optional lab origin the VPS can start for a fully self-contained demo.
LAB_ORIGIN_HOST = "127.0.0.1"
LAB_ORIGIN_PORT = int(os.environ.get("ZRLAB_ORIGIN_PORT", "18080"))

# --------------------------------------------------------------------------
# Safety interlock: where may the VPS relay to?
# --------------------------------------------------------------------------
# Default-closed. The relay is permitted only to loopback, link-local, and
# RFC1918 private space — i.e. the lab. A public destination is refused. This
# is what keeps the tool a demonstration rather than an open proxy that could
# be pointed at the internet over a carrier link.
#
# Yes, an informed user could widen this. The point is that the SHIPPED default
# cannot defraud anyone, and the refusal is logged loudly if you try.
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Set ZRLAB_ALLOW_PUBLIC_FORWARD=i-understand-this-may-be-fraud to disable the
# interlock. Named that way on purpose: you cannot flip it without reading what
# it means. The lab never sets it; the demo never needs it.
_ALLOW_PUBLIC = (
    os.environ.get("ZRLAB_ALLOW_PUBLIC_FORWARD", "") == "i-understand-this-may-be-fraud"
)


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def is_forward_allowed(host: str) -> tuple[bool, str]:
    """Decide whether the VPS may relay to `host`.

    Returns (allowed, reason). A hostname is resolved and EVERY resulting
    address must be private/lab space, so a name that points anywhere public
    (youtube.com, a CDN, ...) is refused. Literal private IPs pass directly.
    """
    if _ALLOW_PUBLIC:
        return True, "interlock disabled by explicit operator override"

    # Literal IP?
    try:
        ipaddress.ip_address(host)
        if _is_private_ip(host):
            return True, "loopback/private lab address"
        return False, "public IP address refused (closed-loop lab interlock)"
    except ValueError:
        pass

    # Hostname: resolve and require all addresses to be private.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, f"could not resolve '{host}'"
    addrs = {info[4][0] for info in infos}
    if addrs and all(_is_private_ip(a) for a in addrs):
        return True, "hostname resolves only to lab/private space"
    return False, (
        f"'{host}' resolves to public address(es) {sorted(addrs)} — refused. "
        "This lab forwards to your own machines only."
    )

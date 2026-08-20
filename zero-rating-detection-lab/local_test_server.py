# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: local_test_server.py
#
#  The lab "origin" — the content server that stands in for both a zero-rated
#  partner service and ordinary chargeable web content.
#
#  It binds FOUR listeners, all on loopback and nothing else:
#
#      127.0.0.2:8080  http    "genuine zero-rated service"  (e.g. zoom.us)
#      127.0.0.2:8443  https   same, over TLS
#      127.0.0.1:8080  http    ordinary chargeable content
#      127.0.0.1:8443  https   same, over TLS
#
#  Two loopback aliases are what make the demo meaningful without leaving the
#  machine: dns_fixtures.json maps the zero-rated hostnames to 127.0.0.2, so a
#  client that claims "zoom.us" while actually connecting to 127.0.0.1 produces
#  a genuine, checkable IP mismatch — the exact condition detector.py looks
#  for. No external address is ever contacted.
#
#  The TLS certificate is self-signed and generated locally on first run into
#  ./certs/. It is a throwaway lab credential; it is not trusted by anything
#  outside this project and is regenerated whenever you delete the folder.
# =============================================================================

from __future__ import annotations

import argparse
import datetime as dt
import http.server
import socket
import ssl
import sys
import threading
from pathlib import Path

import lab_config as cfg
from logging_util import JsonLinesLogger

LOG = JsonLinesLogger("origin", "local_test_server.jsonl")

CERT_FILE = cfg.CERT_DIR / "lab-origin-cert.pem"
KEY_FILE = cfg.CERT_DIR / "lab-origin-key.pem"

# A deterministic payload so the charging meter produces clean round numbers.
PAYLOAD = (b"ZRLAB-CONTENT-" * 8192)[: cfg.ORIGIN_PAYLOAD_BYTES]


# ---------------------------------------------------------------------------
# Self-signed certificate for the lab origin
# ---------------------------------------------------------------------------
def ensure_certificate() -> tuple[Path, Path]:
    """Generate a throwaway self-signed cert/key pair if not already present.

    SANs cover the loopback addresses and the lab hostnames so that a client
    which sets SNI to a zero-rated name still completes a handshake. mitmproxy
    is run with --ssl-insecure in the demo, so upstream verification of this
    cert is skipped anyway; the SANs are here to keep the handshake realistic.
    """
    if CERT_FILE.exists() and KEY_FILE.exists():
        return CERT_FILE, KEY_FILE

    # cryptography ships as a mitmproxy dependency, so this import is safe.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress as _ip

    cfg.CERT_DIR.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "zero-rating-lab-origin"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZR Detection Lab (educational)"),
        ]
    )
    sans = [
        x509.DNSName("lab-origin.local"),
        x509.DNSName("cdn.lab-origin.local"),
        x509.DNSName("edu.lab-origin.local"),
        x509.DNSName("localhost"),
        x509.IPAddress(_ip.ip_address(cfg.ORIGIN_CHARGED_IP)),
        x509.IPAddress(_ip.ip_address(cfg.ORIGIN_ZERO_RATED_IP)),
    ]
    # Also cover the whitelisted hostnames, so the TLS scenarios handshake
    # cleanly against the local origin.
    sans += [x509.DNSName(h) for h in sorted(cfg.ZERO_RATED_HOSTS) if "." in h]

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    LOG.info(
        "lab_certificate_generated",
        cert=str(CERT_FILE),
        subject_alt_names=[str(s.value) for s in sans],
        note="self-signed throwaway credential for local lab use only",
    )
    return CERT_FILE, KEY_FILE


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class OriginHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ZRLabOrigin/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # Which role this listener plays, injected by the server factory below.
    role = "chargeable"
    bind_ip = ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        LOG.debug(
            "origin_request",
            bind_ip=self.bind_ip,
            role=self.role,
            path=self.path,
            host_header=self.headers.get("Host", ""),
            client=self.client_address[0],
        )
        body = PAYLOAD
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        # Echo the lab role so a screenshot of the client output shows which
        # listener actually served the bytes.
        self.send_header("X-ZRLab-Origin-Role", self.role)
        self.send_header("X-ZRLab-Origin-IP", self.bind_ip)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        """Silence stdlib's stderr logging — everything goes through JSONL."""
        return


class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(bind_ip: str, port: int, role: str, tls: bool) -> ThreadedHTTPServer:
    handler = type(
        "BoundOriginHandler",
        (OriginHandler,),
        {"role": role, "bind_ip": bind_ip},
    )
    server = ThreadedHTTPServer((bind_ip, port), handler)
    if tls:
        cert, key = ensure_certificate()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local lab origin server (loopback only)."
    )
    parser.add_argument(
        "--ready-file",
        help="Touch this file once all listeners are up (used by run_demo).",
    )
    args = parser.parse_args()

    listeners = [
        (cfg.ORIGIN_ZERO_RATED_IP, cfg.ORIGIN_HTTP_PORT, "zero-rated-partner", False),
        (cfg.ORIGIN_ZERO_RATED_IP, cfg.ORIGIN_HTTPS_PORT, "zero-rated-partner", True),
        (cfg.ORIGIN_CHARGED_IP, cfg.ORIGIN_HTTP_PORT, "chargeable", False),
        (cfg.ORIGIN_CHARGED_IP, cfg.ORIGIN_HTTPS_PORT, "chargeable", True),
    ]

    servers = []
    for bind_ip, port, role, tls in listeners:
        try:
            server = make_server(bind_ip, port, role, tls)
        except OSError as exc:
            LOG.error(
                "listener_bind_failed",
                bind_ip=bind_ip,
                port=port,
                error=str(exc),
                hint="another process may already hold this port",
            )
            for s in servers:
                s.shutdown()
            return 1
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        LOG.info(
            "listener_started",
            bind_ip=bind_ip,
            port=port,
            role=role,
            scheme="https" if tls else "http",
        )

    LOG.info(
        "origin_ready",
        payload_bytes=cfg.ORIGIN_PAYLOAD_BYTES,
        listeners=len(servers),
        scope="loopback only - no external interface is bound",
    )

    if args.ready_file:
        Path(args.ready_file).write_text("ready", encoding="utf-8")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        LOG.info("origin_shutdown")
        for s in servers:
            s.shutdown()
    return 0


if __name__ == "__main__":
    # Belt-and-braces guard: refuse to run if someone edits the config to bind
    # a non-loopback address.
    for ip in (cfg.ORIGIN_ZERO_RATED_IP, cfg.ORIGIN_CHARGED_IP):
        if not ip.startswith("127."):
            LOG.error(
                "refusing_to_start",
                bind_ip=ip,
                reason="this lab binds loopback addresses only",
            )
            sys.exit(2)
    socket.setdefaulttimeout(30)
    sys.exit(main())

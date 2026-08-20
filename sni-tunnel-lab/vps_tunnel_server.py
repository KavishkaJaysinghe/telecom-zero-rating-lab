# =============================================================================
#  LAB / EDUCATIONAL — SNI-spoofing tunnel, CLOSED-LOOP reference model.
#  Run only between machines you own. The relay refuses public destinations
#  by default (see lab2_config.is_forward_allowed). Do not defeat that over a
#  metered/carrier link — that is billing fraud, not a demo.
# =============================================================================
#
#  sni-tunnel-lab :: vps_tunnel_server.py            [ runs on the Linux "VPS" ]
#
#  A TLS-terminating tunnel endpoint. It:
#    1. accepts a TLS connection on :4433,
#    2. RECORDS the SNI the client presented (this is the forged "zoom.us"),
#    3. reads the inner HTTP CONNECT the client sent through the tunnel,
#    4. checks the requested destination against the closed-loop interlock,
#    5. relays raw bytes between the tunnel and that destination.
#
#  The recorded SNI is logged so you can see, server-side, that the endpoint
#  was told "zoom.us" while the tunnel actually carried traffic to somewhere
#  else entirely. The same fact is visible on the wire in the pcap captured by
#  record_traffic.sh — Wireshark filter: tls.handshake.extensions_server_name
#
#  This models a "VPS" only in the loosest sense: it is a plain TCP relay
#  behind a TLS front. It does NOT try to be a full HTTP or SOCKS proxy; a
#  single CONNECT-then-relay is all the demonstration needs.
#
#  RUN (self-contained, starts its own lab origin):
#     python3 vps_tunnel_server.py --with-origin
#
#  RUN (relay to some other lab host you control):
#     python3 vps_tunnel_server.py
# =============================================================================

from __future__ import annotations

import argparse
import http.server
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone

import lab2_config as cfg

# --------------------------------------------------------------------------
# Minimal structured logging (stdlib only, so the VPS needs nothing installed)
# --------------------------------------------------------------------------
_LOG_LOCK = threading.Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def log(event: str, **fields) -> None:
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    line = f"{_ts()} [vps] {event:<24} {parts}".rstrip()
    with _LOG_LOCK:
        print(line, flush=True)


# --------------------------------------------------------------------------
# Optional self-contained lab origin (so the whole demo is one command)
# --------------------------------------------------------------------------
class _OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        body = (
            b"ZRLAB-VPS-ORIGIN: you reached the lab origin through the TLS tunnel.\n"
            b"The SNI on the outer connection was spoofed; this content stayed on "
            b"the VPS's own loopback and never touched the public internet.\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # silence stdlib stderr logging
        return


def _start_lab_origin() -> None:
    srv = http.server.ThreadingHTTPServer(
        (cfg.LAB_ORIGIN_HOST, cfg.LAB_ORIGIN_PORT), _OriginHandler
    )
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(
        "lab_origin_started",
        addr=f"{cfg.LAB_ORIGIN_HOST}:{cfg.LAB_ORIGIN_PORT}",
        note="content stays on VPS loopback",
    )


# --------------------------------------------------------------------------
# SNI capture
# --------------------------------------------------------------------------
# The ssl module fires sni_callback during the handshake with the ClientHello's
# server_name. We stash it on the SSLSocket so the handler can read it back.
def _sni_callback(sslsocket, server_name, sslcontext):  # noqa: ANN001
    try:
        sslsocket._zrlab_sni = server_name
    except Exception:
        pass
    # Returning None => continue the handshake normally.


def _make_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if not (cfg.CERT_FILE.exists() and cfg.KEY_FILE.exists()):
        log(
            "no_certificate",
            hint="run ./setup_certs.sh first (or start with --autocert)",
            cert=str(cfg.CERT_FILE),
        )
        raise SystemExit(2)
    ctx.load_cert_chain(certfile=str(cfg.CERT_FILE), keyfile=str(cfg.KEY_FILE))
    ctx.sni_callback = _sni_callback
    return ctx


# --------------------------------------------------------------------------
# Inner request parsing + relay
# --------------------------------------------------------------------------
def _read_headers(sock: ssl.SSLSocket) -> bytes:
    """Read until the end of the HTTP request-line + headers block."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:  # a CONNECT preamble is never this big
            break
    return buf


def _relay(a: socket.socket, b: socket.socket, counters: dict, key: str) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
            counters[key] += len(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _handle(tls_conn: ssl.SSLSocket, peer: tuple) -> None:
    sni = getattr(tls_conn, "_zrlab_sni", None)
    client = f"{peer[0]}:{peer[1]}"
    try:
        preamble = _read_headers(tls_conn)
        if not preamble:
            log("tunnel_empty", client=client, sni=sni)
            return
        line = preamble.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split()
        # We only implement CONNECT: the client tunnels everything that way.
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            log("tunnel_bad_request", client=client, sni=sni, first_line=line[:80])
            tls_conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        authority = parts[1]
        host, _, port_s = authority.rpartition(":")
        if not host:  # authority had no colon
            host, port_s = authority, "80"
        try:
            port = int(port_s)
        except ValueError:
            port = 80

        allowed, reason = cfg.is_forward_allowed(host)
        log(
            "tunnel_connect",
            client=client,
            spoofed_sni=sni,
            real_target=f"{host}:{port}",
            allowed=allowed,
            reason=reason,
        )
        if not allowed:
            # This is the interlock doing its job. Loud, and no relay.
            tls_conn.sendall(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"ZRLAB closed-loop interlock: this tunnel forwards to lab/private "
                b"addresses only. Refusing to relay to a public destination.\n"
            )
            log("tunnel_refused", client=client, real_target=f"{host}:{port}", reason=reason)
            return

        # Open the onward connection to the lab destination.
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            tls_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            log("tunnel_upstream_fail", client=client, real_target=f"{host}:{port}", error=str(exc))
            return

        tls_conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        counters = {"c2s": 0, "s2c": 0}
        t1 = threading.Thread(target=_relay, args=(tls_conn, upstream, counters, "c2s"), daemon=True)
        t2 = threading.Thread(target=_relay, args=(upstream, tls_conn, counters, "s2c"), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        try:
            upstream.close()
        except OSError:
            pass
        log(
            "tunnel_closed",
            client=client,
            spoofed_sni=sni,
            real_target=f"{host}:{port}",
            bytes_client_to_server=counters["c2s"],
            bytes_server_to_client=counters["s2c"],
        )
    except ssl.SSLError as exc:
        log("tls_error", client=client, error=str(exc))
    except OSError as exc:
        log("conn_error", client=client, error=str(exc))
    finally:
        try:
            tls_conn.close()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Closed-loop TLS tunnel endpoint for the SNI-spoofing lab."
    )
    ap.add_argument(
        "--with-origin",
        action="store_true",
        help="Also start a lab HTTP origin on 127.0.0.1:%d so the demo is one command."
        % cfg.LAB_ORIGIN_PORT,
    )
    ap.add_argument(
        "--autocert",
        action="store_true",
        help="Generate a self-signed cert with the 'cryptography' package if none exists.",
    )
    args = ap.parse_args()

    cfg.LOG_DIR.mkdir(exist_ok=True)

    if args.autocert and not (cfg.CERT_FILE.exists() and cfg.KEY_FILE.exists()):
        _autocert()

    if args.with_origin:
        _start_lab_origin()

    ctx = _make_tls_context()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((cfg.VPS_LISTEN_HOST, cfg.VPS_PORT))
    srv.listen(64)

    allow_public = cfg._ALLOW_PUBLIC
    log(
        "vps_listening",
        addr=f"{cfg.VPS_LISTEN_HOST}:{cfg.VPS_PORT}",
        public_forwarding="ENABLED (operator override)" if allow_public else "DISABLED (closed-loop)",
        banner="LAB / EDUCATIONAL - relay to your own machines only",
    )
    if allow_public:
        log(
            "interlock_disabled_warning",
            note="public forwarding is ON. Running this over a metered/carrier "
            "link to avoid data charges is billing fraud. You have been warned.",
        )

    try:
        while True:
            raw, peer = srv.accept()
            try:
                tls_conn = ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as exc:
                log("handshake_fail", client=f"{peer[0]}:{peer[1]}", error=str(exc))
                raw.close()
                continue
            threading.Thread(target=_handle, args=(tls_conn, peer), daemon=True).start()
    except KeyboardInterrupt:
        log("vps_shutdown")
    finally:
        srv.close()
    return 0


def _autocert() -> None:
    """Best-effort self-signed cert via 'cryptography' (for the Windows smoke test)."""
    try:
        import datetime as _dt
        import ipaddress as _ip

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        log("autocert_unavailable", hint="pip install cryptography, or run ./setup_certs.sh")
        raise SystemExit(2)

    cfg.CERT_DIR.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zrlab-vps")])
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName(cfg.SPOOFED_SNI),
            x509.DNSName("teams.microsoft.com"),
            x509.DNSName("lab-vps.local"),
            x509.DNSName("localhost"),
            x509.IPAddress(_ip.ip_address("127.0.0.1")),
        ]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cfg.KEY_FILE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cfg.CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log("autocert_generated", cert=str(cfg.CERT_FILE))


if __name__ == "__main__":
    sys.exit(main())

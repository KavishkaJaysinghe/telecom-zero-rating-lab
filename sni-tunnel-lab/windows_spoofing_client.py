# =============================================================================
#  LAB / EDUCATIONAL — SNI-spoofing tunnel, CLOSED-LOOP reference model.
#  Point this only at a VPS you own. The endpoint refuses public destinations
#  by default. Do not use this to evade charges on a metered/carrier link —
#  that is billing fraud, not a demo.
# =============================================================================
#
#  sni-tunnel-lab :: windows_spoofing_client.py     [ runs on the Windows PC ]
#
#  A local CONNECT proxy that your browser or curl points at
#  (127.0.0.1:8080). For each connection it:
#    1. reads the browser's  CONNECT host:port  request,
#    2. opens a TLS connection to the VPS,
#    3. >>> sets the TLS SNI to "zoom.us" <<<  (the whole point of the lab),
#    4. tunnels the browser's CONNECT through, and relays raw bytes.
#
#  The destination host:port the browser asked for is carried INSIDE the
#  encrypted tunnel. On the wire between this client and the VPS, the only
#  hostname visible is the forged SNI — which is exactly what a naive operator
#  classifier would read, and exactly what the detector in
#  ../zero-rating-detection-lab cross-validates against the real destination.
#
#  Raw sockets are used on purpose: libraries like requests/urllib derive the
#  SNI from the URL, and decoupling the SNI from the destination is the thing
#  being demonstrated.
#
#  RUN:
#     set ZRLAB_VPS_IP=192.168.1.10      (the Linux laptop's LAN IP)
#     python windows_spoofing_client.py
#
#  For a one-machine smoke test leave ZRLAB_VPS_IP unset (defaults to 127.0.0.1).
# =============================================================================

from __future__ import annotations

import socket
import ssl
import sys
import threading
from datetime import datetime, timezone

import lab2_config as cfg

_LOG_LOCK = threading.Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def log(event: str, **fields) -> None:
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    with _LOG_LOCK:
        print(f"{_ts()} [client] {event:<22} {parts}".rstrip(), flush=True)


def _client_tls_context() -> ssl.SSLContext:
    """TLS context for the tunnel to the VPS.

    We verify the VPS against the lab certificate if it has been copied over
    (models 'the device trusts the tunnel endpoint'), but we DISABLE hostname
    checking — because we are deliberately presenting SNI 'zoom.us' to an
    endpoint whose certificate/identity is the VPS, not zoom.us. Verifying the
    name would defeat the very thing under test. If no lab cert is present we
    fall back to no verification, since what this lab exercises is the SNI, not
    the PKI.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if cfg.CERT_FILE.exists():
        try:
            ctx.load_verify_locations(cafile=str(cfg.CERT_FILE))
            ctx.verify_mode = ssl.CERT_REQUIRED
            return ctx
        except ssl.SSLError:
            pass
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_TLS_CTX = _client_tls_context()


def _relay(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _read_headers(sock: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


def _handle(browser: socket.socket, peer: tuple) -> None:
    client = f"{peer[0]}:{peer[1]}"
    tunnel: ssl.SSLSocket | None = None
    try:
        preamble = _read_headers(browser)
        if not preamble:
            return
        line = preamble.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            # Keep the client simple: it is a CONNECT tunnel. Tell the caller
            # to use CONNECT (curl: --proxytunnel).
            browser.sendall(
                b"HTTP/1.1 405 Method Not Allowed\r\n"
                b"Content-Type: text/plain\r\n\r\n"
                b"This lab proxy only supports CONNECT. Try: "
                b"curl --proxytunnel -x 127.0.0.1:8080 http://<lab-host>/\n"
            )
            log("rejected_non_connect", client=client, first_line=line[:80])
            return

        target = parts[1]  # host:port the browser wants to reach

        # 1. TCP to the VPS.
        raw = socket.create_connection((cfg.VPS_IP, cfg.VPS_PORT), timeout=10)
        # 2. TLS to the VPS, presenting the FORGED SNI.
        tunnel = _TLS_CTX.wrap_socket(raw, server_hostname=cfg.SPOOFED_SNI)

        negotiated = tunnel.version()
        log(
            "tunnel_up",
            client=client,
            vps=f"{cfg.VPS_IP}:{cfg.VPS_PORT}",
            spoofed_sni=cfg.SPOOFED_SNI,
            real_target=target,
            tls=negotiated,
        )

        # 3. Ask the VPS (through the tunnel) to reach the real destination.
        tunnel.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        inner = _read_headers(tunnel)
        status = inner.split(b"\r\n", 1)[0].decode("latin-1", "replace") if inner else ""
        if b" 200 " not in inner.split(b"\r\n", 1)[0]:
            browser.sendall((("HTTP/1.1 502 Bad Gateway\r\n\r\n")).encode())
            log("tunnel_connect_failed", client=client, real_target=target, vps_status=status)
            return

        # 4. Tell the browser its tunnel is ready, then relay both directions.
        browser.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        t1 = threading.Thread(target=_relay, args=(browser, tunnel), daemon=True)
        t2 = threading.Thread(target=_relay, args=(tunnel, browser), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        log("tunnel_closed", client=client, real_target=target)
    except ssl.SSLError as exc:
        log("tls_error", client=client, error=str(exc))
        try:
            browser.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass
    except OSError as exc:
        log("conn_error", client=client, error=str(exc))
    finally:
        for s in (browser, tunnel):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((cfg.CLIENT_LISTEN_HOST, cfg.CLIENT_LISTEN_PORT))
    srv.listen(64)
    log(
        "client_listening",
        addr=f"{cfg.CLIENT_LISTEN_HOST}:{cfg.CLIENT_LISTEN_PORT}",
        vps=f"{cfg.VPS_IP}:{cfg.VPS_PORT}",
        spoofed_sni=cfg.SPOOFED_SNI,
        banner="LAB / EDUCATIONAL - point at your own VPS only",
    )
    try:
        while True:
            conn, peer = srv.accept()
            threading.Thread(target=_handle, args=(conn, peer), daemon=True).start()
    except KeyboardInterrupt:
        log("client_shutdown")
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

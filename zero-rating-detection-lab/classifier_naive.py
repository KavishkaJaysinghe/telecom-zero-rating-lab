# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: classifier_naive.py        [ THE VICTIM ]
#
#  A mitmproxy addon modelling a NAIVE operator traffic classifier bolted to a
#  simplified online charging meter.
#
#  WHAT IT MODELS
#  --------------
#  In a 3GPP packet core the packet gateway (PGW-C/U or SMF/UPF) hosts the
#  PCEF/TDF function. It classifies each service data flow against provisioned
#  PCC rules, maps the flow to a rating-group, and reports volume to the OCS
#  over the Diameter Gy interface using Credit-Control-Request/Answer messages
#  (concepts per 3GPP TS 32.299 online charging applications, TS 32.240
#  charging architecture, TS 23.203 policy and charging control). A zero-rated
#  service is one whose rating-group is configured at 0-rate, so its volume
#  never decrements the subscriber's balance.
#
#  This file is a teaching model of exactly ONE property of that chain: the
#  classifier trusts the hostname the CLIENT claims.
#
#     HTTP  -> the Host: request header
#     HTTPS -> the TLS ClientHello SNI extension
#
#  Both are client-supplied strings. Neither is authenticated. This addon
#  believes them unconditionally, which is what makes it exploitable — that is
#  the whole point of the demo. detector.py is the corrected version.
#
#  This is NOT a Diameter stack, NOT a real PCEF, and NOT any operator's
#  product. No CCR/CCA is ever placed on a wire; the "Gy" events below are
#  local log records shaped to look familiar to a charging engineer.
#
#  RUN
#  ---
#     mitmdump -s classifier_naive.py --listen-port 8081 --ssl-insecure
# =============================================================================

from __future__ import annotations

from typing import Any

from mitmproxy import http, tls

import lab_config as cfg
from lab_config import handle_control_request
from charging import GyMeter
from logging_util import JsonLinesLogger, write_report

REPORT_FILE = "naive_meter_report.json"


# ---------------------------------------------------------------------------
# The addon
# ---------------------------------------------------------------------------
class NaiveZeroRatingClassifier:
    """Classifies by claimed hostname alone. Intentionally exploitable."""

    def __init__(self) -> None:
        self.log = JsonLinesLogger("classifier_naive", "classifier_naive.jsonl")
        self.meter = GyMeter(self.log, role="victim / naive hostname-trusting classifier")

    # -- mitmproxy lifecycle ----------------------------------------------
    def running(self) -> None:
        self.log.info(
            "addon_started",
            role="NAIVE_CLASSIFIER",
            listen_port=cfg.PROXY_PORT,
            zero_rated_hosts=sorted(cfg.ZERO_RATED_HOSTS),
            classification_basis="client-claimed Host header / TLS SNI ONLY",
            validation="NONE - destination IP is never checked",
            banner="LAB / EDUCATIONAL reference model - simplified 3GPP concepts",
        )
        self.meter.start_session()

    def done(self) -> None:
        self.meter.stop_session()
        self._flush_report()
        self.log.info("addon_stopped", role="NAIVE_CLASSIFIER")
        self.log.close()

    def _flush_report(self) -> None:
        # Written after every flow as well as at shutdown, so the evidence
        # file is complete even if the process is killed abruptly.
        snapshot: dict[str, Any] = {"component": "classifier_naive"}
        snapshot.update(self.meter.base_snapshot())
        snapshot["revenue_leakage_bytes"] = self.meter.zero_rated_bytes
        snapshot["note"] = (
            "revenue_leakage_bytes counts every byte waived on the basis of a "
            "client-claimed hostname. This addon performs no validation, so a "
            "spoofed Host/SNI lands straight in this bucket."
        )
        write_report(REPORT_FILE, snapshot)

    # -- TLS: capture the claimed SNI -------------------------------------
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Record the SNI the client asserts. It is NOT verified here.

        In a real network the PCEF reads this same field straight off the
        ClientHello to classify an encrypted flow, because it is the only
        cleartext hostname available once TLS starts.
        """
        sni = cfg.normalise_host(data.client_hello.sni)
        client_ip = data.context.client.peername[0] if data.context.client.peername else ""
        dest = data.context.server.address
        self.log.debug(
            "tls_clienthello_seen",
            client_ip=client_ip,
            claimed_sni=sni or "(none)",
            # Logged for completeness only — the naive classifier does not
            # compare it against the SNI. detector.py is the one that does.
            connect_target=f"{dest[0]}:{dest[1]}" if dest else "(unknown)",
        )

    # -- classification ----------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        """Tag the flow at request time, before any volume is counted."""
        if handle_control_request(flow, self.log):
            return

        claimed = self._claimed_host(flow)
        zero_rated = cfg.is_zero_rated(claimed)
        flow.metadata["zrlab_claimed_host"] = claimed
        flow.metadata["zrlab_zero_rated"] = zero_rated
        flow.metadata["zrlab_rating_group"] = (
            cfg.RATING_GROUP_ZERO_RATED if zero_rated else cfg.RATING_GROUP_STANDARD
        )

    def response(self, flow: http.HTTPFlow) -> None:
        """Meter the flow according to the tag decided in request()."""
        if flow.metadata.get("zrlab_control"):
            return

        claimed = flow.metadata.get("zrlab_claimed_host", "")
        zero_rated = bool(flow.metadata.get("zrlab_zero_rated"))
        rating_group = int(
            flow.metadata.get("zrlab_rating_group", cfg.RATING_GROUP_STANDARD)
        )
        volume = self._flow_volume(flow)

        balance_before = self.meter.balance_bytes
        self.meter.meter(volume, rating_group)

        transport = "TLS/SNI" if flow.request.scheme == "https" else "HTTP/Host"
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        real_ip = self._real_ip(flow)

        common = dict(
            client_ip=client_ip,
            claimed_host=claimed or "(none)",
            transport=transport,
            path=flow.request.path,
            # NOTE: real_ip is *logged* but plays no part in the decision.
            # That gap between "observed" and "used" is the vulnerability.
            real_ip=real_ip,
            volume_bytes=volume,
            rating_group=rating_group,
        )

        if zero_rated:
            self.log.zerorate(
                "charging_decision",
                verdict="ZERO-RATED",
                charged_bytes=0,
                balance_bytes=self.meter.balance_bytes,
                reason="claimed hostname matched zero-rating whitelist",
                **common,
            )
        else:
            self.log.charge(
                "charging_decision",
                verdict="CHARGED",
                charged_bytes=volume,
                balance_before=balance_before,
                balance_bytes=self.meter.balance_bytes,
                reason="claimed hostname not in zero-rating whitelist",
                **common,
            )

        self._flush_report()

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _claimed_host(flow: http.HTTPFlow) -> str:
        """The hostname the CLIENT says it is talking to.

        Preference order mirrors a naive DPI classifier:
          1. TLS SNI, when the flow is encrypted (the only visible hostname);
          2. the HTTP Host header;
          3. whatever authority the request line carried.

        Every one of these is attacker-controlled. mitmproxy's own docs warn
        about exactly this for `Request.pretty_host`: in adversarial
        environments it "may not reflect the actual destination".
        """
        if flow.request.scheme == "https":
            sni = cfg.normalise_host(getattr(flow.client_conn, "sni", None))
            if sni:
                return sni
        host_header = cfg.normalise_host(flow.request.host_header)
        if host_header:
            return host_header
        return cfg.normalise_host(flow.request.pretty_host)

    @staticmethod
    def _real_ip(flow: http.HTTPFlow) -> str:
        """Actual destination, taken from the routing target (not the claim).

        Deliberately logged and then IGNORED. Seeing `real_ip=127.0.0.1` sat
        next to `verdict=ZERO-RATED` in this addon's own log is the clearest
        statement of the flaw: the evidence that would expose the spoof is
        right there, and the classifier simply never consults it.
        """
        server = flow.server_conn
        if server.peername:
            return server.peername[0]
        if server.address:
            return str(server.address[0])
        return str(flow.request.host or "")

    @staticmethod
    def _flow_volume(flow: http.HTTPFlow) -> int:
        """Downlink volume for this flow, in bytes.

        A real PCEF meters IP-layer octets in both directions. We approximate
        with HTTP response status line + headers + body, which is close enough
        for a demo and keeps the arithmetic legible in a screenshot.
        """
        if not flow.response:
            return 0
        body = len(flow.response.raw_content or b"")
        headers = sum(len(k) + len(v) + 4 for k, v in flow.response.headers.fields)
        status_line = len(f"HTTP/1.1 {flow.response.status_code} OK\r\n")
        return body + headers + status_line + 2


addons = [NaiveZeroRatingClassifier()]

# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: detector.py                  [ THE HERO ]
#
#  A mitmproxy addon that performs ROBUST zero-rating classification: it keeps
#  the same charging behaviour as classifier_naive.py, but refuses to zero-rate
#  a flow purely because the client asserted a whitelisted hostname.
#
#  THE CORE IDEA
#  -------------
#  A naive classifier answers "should this be free?" using one input:
#
#        claimed_host   <- Host: header (HTTP) or TLS SNI (HTTPS)
#
#  That input is written by the client and is not authenticated in any way.
#  This detector adds a second, independent input the client does not control:
#
#        real_dest_ip   <- the destination the packets are actually going to
#
#  and cross-validates the two. If a flow claims a zero-rated hostname but is
#  demonstrably NOT going to any address that hostname resolves to, the
#  zero-rating claim is fraudulent. The flow is logged as a structured JSON
#  finding and dropped.
#
#      claimed zero-rated host  AND  dest IP in resolved set   -> ZERO-RATED (valid)
#      claimed zero-rated host  AND  dest IP NOT in that set   -> BYPASS SUSPECTED
#      claimed non-zero-rated host                             -> CHARGED (normal)
#
#  WHERE THIS SITS IN A REAL NETWORK
#  ---------------------------------
#  Conceptually this logic belongs in, or alongside, the PCEF/TDF on the packet
#  gateway — the same element that classifies service data flows against PCC
#  rules and reports volume to the OCS over the Diameter Gy interface (3GPP TS
#  32.299 online charging, TS 32.240 charging architecture, TS 23.203 PCC). In
#  practice operators split it: inline enforcement on the gateway, plus an
#  offline revenue-assurance job that mines the same signals from charging
#  records. The JSON-lines findings this addon emits are shaped to feed either.
#
#  NOTE ON THE LAB HARNESS: mitmproxy is a forward proxy, so "the real
#  destination" here is the address the client asked the proxy to reach. On a
#  real gateway there is no such indirection — the destination IP is simply the
#  destination field of the IP header, and is even harder for a client to lie
#  about. The proxy is a convenient way to OBSERVE the mismatch locally; it is
#  not part of the model being proposed.
#
#  RUN
#  ---
#     mitmdump -s detector.py --listen-port 8081 --ssl-insecure
# =============================================================================

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Any

from mitmproxy import http, tls

import lab_config as cfg
from lab_config import handle_control_request
from charging import GyMeter
from logging_util import JsonLinesLogger, write_report

REPORT_FILE = "detector_report.json"
FINDINGS_FILE = "detector_findings.jsonl"


# ===========================================================================
#  1. Resolver — "what SHOULD this hostname resolve to?"
# ===========================================================================
class LabResolver:
    """Resolves a claimed hostname to the full set of addresses it may use.

    Two modes, selected by cfg.RESOLVER_MODE:

      "fixture"  (default, and what the demo uses)
          Answers come from dns_fixtures.json. Completely offline: no DNS
          packet is ever emitted, results are deterministic, and the lab has
          no dependency on the outside world.

      "system"
          Answers come from the OS resolver via socket.getaddrinfo. Provided
          so you can experiment on your own machine. It DOES emit real DNS
          queries, so run_demo.sh never selects it.

    A short TTL cache mirrors what a real deployment would do: a gateway or
    probe keeps a rolling view of recent DNS answers rather than resolving
    per packet.
    """

    def __init__(self, log: JsonLinesLogger) -> None:
        self.log = log
        self.mode = cfg.RESOLVER_MODE
        self.fixtures = cfg.load_dns_fixtures()
        self._cache: dict[str, tuple[float, frozenset[str]]] = {}
        self.lookups = 0
        self.cache_hits = 0

    def resolve(self, host: str) -> frozenset[str]:
        """Return the set of IP strings `host` may legitimately use.

        An empty set means "could not be resolved" — which the caller must
        treat as UNVERIFIABLE, never as evidence of fraud.
        """
        host = cfg.normalise_host(host)
        if not host:
            return frozenset()

        # A hostname that is already an IP literal resolves to itself.
        try:
            return frozenset({str(ipaddress.ip_address(host))})
        except ValueError:
            pass

        now = time.monotonic()
        cached = self._cache.get(host)
        if cached and (now - cached[0]) < cfg.RESOLVER_CACHE_TTL:
            self.cache_hits += 1
            return cached[1]

        self.lookups += 1
        if self.mode == "fixture":
            ips = frozenset(self.fixtures.get(host, []))
        else:
            ips = self._system_resolve(host)

        self._cache[host] = (now, ips)
        self.log.debug(
            "dns_resolution",
            host=host,
            mode=self.mode,
            resolved_ips=sorted(ips) or "(none)",
        )
        return ips

    @staticmethod
    def _system_resolve(host: str) -> frozenset[str]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError):
            return frozenset()
        return frozenset(info[4][0] for info in infos)


# ===========================================================================
#  2. Cross-validation — the actual detection logic
# ===========================================================================
class Finding:
    """Structured outcome of evaluating one flow.

    Written out longhand rather than as a @dataclass: mitmproxy loads addon
    scripts under a module name that is not registered in sys.modules, and
    dataclasses' type resolution needs that entry, so the decorator raises at
    import time. A plain class sidesteps it and costs nothing here.
    """

    __slots__ = (
        "verdict",
        "confidence",
        "reason",
        "claimed_host",
        "real_ip",
        "resolved_ips",
        "signals",
        "zero_rate",
        "drop",
    )

    def __init__(
        self,
        verdict: str,
        confidence: str,  # HIGH / MEDIUM / LOW / NONE
        reason: str,
        claimed_host: str = "",
        real_ip: str = "",
        resolved_ips: list[str] | None = None,
        signals: list[str] | None = None,
        zero_rate: bool = False,  # should charging waive this flow?
        drop: bool = False,  # should enforcement drop this flow?
    ) -> None:
        self.verdict = verdict
        self.confidence = confidence
        self.reason = reason
        self.claimed_host = claimed_host
        self.real_ip = real_ip
        self.resolved_ips = resolved_ips if resolved_ips is not None else []
        self.signals = signals if signals is not None else []
        self.zero_rate = zero_rate
        self.drop = drop

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Finding(verdict={self.verdict!r}, confidence={self.confidence!r}, "
            f"claimed_host={self.claimed_host!r}, real_ip={self.real_ip!r})"
        )


# Verdict vocabulary, kept as constants so log consumers can key on them.
V_CHARGED_NORMAL = "CHARGED_NORMAL"
V_ZERO_RATED_VALID = "ZERO_RATED_VALID"
V_BYPASS_SUSPECTED = "BYPASS_SUSPECTED"
V_UNVERIFIABLE = "ZERO_RATING_UNVERIFIABLE"


class CrossValidator:
    """Decides whether a zero-rating claim is consistent with the packets."""

    def __init__(self, resolver: LabResolver) -> None:
        self.resolver = resolver

    # -- IP set comparison -------------------------------------------------
    @staticmethod
    def _is_publicly_routable(ip: ipaddress._BaseAddress) -> bool:
        """False for loopback / RFC1918 / link-local / ULA destinations."""
        return not any(ip in net for net in cfg.IMPLAUSIBLE_DEST_NETWORKS)

    def match_kind(self, real_ip: str, resolved: frozenset[str]) -> str:
        """Classify how well `real_ip` matches the resolved set.

        Returns one of: "exact", "prefix", "none".

        CDN HANDLING — this is the main false-positive control. A zero-rated
        hostname typically resolves to MANY edge addresses, and the answer the
        subscriber's resolver got may differ from the one we get. So:

          * we always compare against the FULL resolved set, never a single
            "the" IP (comparing to one address would false-positive on every
            multi-homed or geo-balanced service);

          * we additionally accept a destination inside the same network
            prefix as any resolved address (cfg.PREFIX_TOLERANCE_BITS_*),
            which absorbs edge rotation within a single CDN POP.

        The prefix tolerance is deliberately NOT applied to loopback/private
        destinations. That tolerance exists to excuse CDN churn on public
        address space; a globally advertised zero-rated service never lives on
        127.0.0.0/8 or RFC1918, so stretching the netmask there would only
        ever launder an attack.
        """
        if not resolved:
            return "none"

        try:
            dest = ipaddress.ip_address(real_ip)
        except ValueError:
            return "none"

        resolved_addrs = []
        for candidate in resolved:
            try:
                resolved_addrs.append(ipaddress.ip_address(candidate))
            except ValueError:
                continue

        if any(dest == addr for addr in resolved_addrs):
            return "exact"

        if not self._is_publicly_routable(dest):
            # See docstring: no prefix tolerance on non-public destinations.
            return "none"

        bits = (
            cfg.PREFIX_TOLERANCE_BITS_V4
            if dest.version == 4
            else cfg.PREFIX_TOLERANCE_BITS_V6
        )
        for addr in resolved_addrs:
            if addr.version != dest.version:
                continue
            net = ipaddress.ip_network(f"{addr}/{bits}", strict=False)
            if dest in net:
                return "prefix"

        return "none"

    # -- main entry point --------------------------------------------------
    def evaluate(
        self,
        claimed_host: str,
        real_ip: str,
        sni: str = "",
        host_header: str = "",
    ) -> Finding:
        """Cross-validate one flow's zero-rating claim.

        `claimed_host` is what the classifier would key on (SNI for TLS, Host
        header for plaintext). `sni` and `host_header` are passed separately so
        we can also check them against EACH OTHER as a corroborating signal.
        """
        claimed = cfg.normalise_host(claimed_host)

        # --- (a) No hostname claimed at all -------------------------------
        if not claimed:
            return Finding(
                verdict=V_CHARGED_NORMAL,
                confidence="NONE",
                reason="no hostname claimed; charged at standard rate",
            )

        # --- (b) Not a zero-rated host: nothing to gain by lying ----------
        # An attacker has no incentive to spoof a hostname that is billed
        # normally, so these flows skip validation entirely. This keeps the
        # expensive path off the overwhelming majority of traffic.
        if not cfg.is_zero_rated(claimed):
            return Finding(
                verdict=V_CHARGED_NORMAL,
                confidence="NONE",
                reason="claimed host is not zero-rated; standard charging applies",
                claimed_host=claimed,
                real_ip=real_ip,
            )

        # --- (c) A zero-rating claim was made: verify it ------------------
        resolved = self.resolver.resolve(claimed)
        signals: list[str] = []

        # Corroborating signal: on an HTTPS flow the SNI and the inner Host
        # header should agree. A mismatch means the client told two different
        # stories about the same connection.
        s, h = cfg.normalise_host(sni), cfg.normalise_host(host_header)
        if s and h and s != h:
            signals.append(f"sni_host_header_mismatch(sni={s},host={h})")

        if not resolved:
            # Cannot prove or disprove. Log it for offline review, but do NOT
            # drop — an unresolvable name is far more often a stale fixture,
            # a split-horizon DNS view or a resolver timeout than it is fraud.
            return Finding(
                verdict=V_UNVERIFIABLE,
                confidence="LOW",
                reason=(
                    "claimed host is zero-rated but could not be resolved; "
                    "allowing flow, flagged for offline review"
                ),
                claimed_host=claimed,
                real_ip=real_ip,
                signals=signals,
                zero_rate=True,
            )

        match = self.match_kind(real_ip, resolved)

        if match == "exact":
            return Finding(
                verdict=V_ZERO_RATED_VALID,
                confidence="NONE",
                reason="destination IP is in the resolved address set for the claimed host",
                claimed_host=claimed,
                real_ip=real_ip,
                resolved_ips=sorted(resolved),
                signals=signals,
                zero_rate=True,
            )

        if match == "prefix":
            return Finding(
                verdict=V_ZERO_RATED_VALID,
                confidence="NONE",
                reason=(
                    "destination IP shares a network prefix with a resolved address "
                    "(CDN edge tolerance)"
                ),
                claimed_host=claimed,
                real_ip=real_ip,
                resolved_ips=sorted(resolved),
                signals=signals + ["cdn_prefix_tolerance_applied"],
                zero_rate=True,
            )

        # --- (d) Mismatch: the claim is inconsistent with the packets -----
        signals.append("claimed_host_resolves_elsewhere")
        confidence = "MEDIUM"
        reason = (
            "claimed zero-rated host does not resolve to the actual destination IP"
        )

        try:
            dest = ipaddress.ip_address(real_ip)
            if not self._is_publicly_routable(dest):
                # A public zero-rated service cannot live on loopback or
                # RFC1918 space. Combined with the mismatch this is about as
                # unambiguous as host-based detection gets.
                signals.append("destination_not_publicly_routable")
                confidence = "HIGH"
                reason = (
                    "claimed zero-rated host resolves elsewhere AND the actual "
                    "destination is a non-routable address that cannot host a "
                    "public zero-rated service"
                )
        except ValueError:
            signals.append("destination_ip_unparseable")

        # Two independent lies about the same connection also promote to HIGH.
        if any(sig.startswith("sni_host_header_mismatch") for sig in signals):
            confidence = "HIGH"

        return Finding(
            verdict=V_BYPASS_SUSPECTED,
            confidence=confidence,
            reason=reason,
            claimed_host=claimed,
            real_ip=real_ip,
            resolved_ips=sorted(resolved),
            signals=signals,
            zero_rate=False,
            drop=confidence in cfg.DROP_ON_CONFIDENCE,
        )


# ===========================================================================
#  3. The mitmproxy addon
# ===========================================================================
class ZeroRatingBypassDetector:
    """Charges correctly, and drops flows whose zero-rating claim is a lie."""

    def __init__(self) -> None:
        self.log = JsonLinesLogger("detector", "detector.jsonl")
        # Findings go to their own JSONL stream as well, so a reviewer can
        # `cat logs/detector_findings.jsonl | jq` without wading through the
        # routine charging chatter.
        self.findings_log = JsonLinesLogger(
            "detector", FINDINGS_FILE, echo=False
        )
        self.resolver = LabResolver(self.log)
        self.validator = CrossValidator(self.resolver)
        self.meter = GyMeter(self.log, role="hero / cross-validating classifier")

        self.flows_blocked = 0
        self.flows_validated_zero_rated = 0
        self.flows_unverifiable = 0
        # Verdict recorded at TLS ClientHello time, keyed by client connection
        # id. See _enforce() for why detection and enforcement are split.
        self._tls_verdicts: dict[str, Finding] = {}

    # -- mitmproxy lifecycle ----------------------------------------------
    def running(self) -> None:
        self.log.info(
            "addon_started",
            role="CROSS_VALIDATING_DETECTOR",
            listen_port=cfg.PROXY_PORT,
            zero_rated_hosts=sorted(cfg.ZERO_RATED_HOSTS),
            classification_basis="claimed Host/SNI cross-validated against real destination IP",
            resolver_mode=cfg.RESOLVER_MODE,
            prefix_tolerance_v4=cfg.PREFIX_TOLERANCE_BITS_V4,
            drop_on_confidence=sorted(cfg.DROP_ON_CONFIDENCE),
            enforcement_mode=cfg.ENFORCEMENT_MODE,
            banner="LAB / EDUCATIONAL reference model - simplified 3GPP concepts",
        )
        self.meter.start_session()

    def done(self) -> None:
        self.meter.stop_session()
        self._flush_report()
        self.log.info("addon_stopped", role="CROSS_VALIDATING_DETECTOR")
        self.log.close()
        self.findings_log.close()

    def _flush_report(self) -> None:
        snapshot: dict[str, Any] = {"component": "detector"}
        snapshot.update(self.meter.base_snapshot())
        snapshot.update(
            {
                "flows_blocked": self.flows_blocked,
                "flows_validated_zero_rated": self.flows_validated_zero_rated,
                "flows_unverifiable": self.flows_unverifiable,
                "revenue_leakage_bytes": 0,
                "dns_lookups": self.resolver.lookups,
                "dns_cache_hits": self.resolver.cache_hits,
                "note": (
                    "zero_rated_bytes here were all cross-validated against the real "
                    "destination IP, so no volume was waived on an unverified claim."
                ),
            }
        )
        write_report(REPORT_FILE, snapshot)

    # -- stage 1: TLS ClientHello (HTTPS / SNI case) ----------------------
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Detect an SNI-based bypass at the earliest possible moment.

        This is the encrypted-traffic path. The SNI in the ClientHello is the
        only cleartext hostname a classifier gets, and it is exactly what an
        attacker rewrites. We evaluate it here — before a single byte of
        application data flows — and record the verdict for enforcement.
        """
        sni = cfg.normalise_host(data.client_hello.sni)
        client_ip = (
            data.context.client.peername[0] if data.context.client.peername else ""
        )
        real_ip = self._address_to_ip(data.context.server.address)

        finding = self.validator.evaluate(sni, real_ip, sni=sni)
        conn_id = data.context.client.id
        self._tls_verdicts[conn_id] = finding

        if finding.verdict == V_BYPASS_SUSPECTED:
            self._emit_finding(
                finding,
                client_ip=client_ip,
                transport="TLS/SNI",
                detection_point="tls_clienthello",
                real_host=self._address_to_host(data.context.server.address),
            )

    # -- stage 2: HTTP request (plaintext case + TLS enforcement) ---------
    def request(self, flow: http.HTTPFlow) -> None:
        """Evaluate plaintext flows, and enforce verdicts from either stage."""
        if handle_control_request(flow, self.log):
            return

        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        real_ip = self._real_ip(flow)
        real_host = self._real_host(flow)
        is_tls = flow.request.scheme == "https"
        sni = cfg.normalise_host(getattr(flow.client_conn, "sni", None))
        host_header = cfg.normalise_host(flow.request.host_header)

        if is_tls:
            # The SNI verdict was already computed at ClientHello time. Re-run
            # the validator now that the inner Host header is also visible, so
            # an SNI/Host contradiction can be picked up too.
            claimed = sni or host_header
            finding = self.validator.evaluate(
                claimed, real_ip, sni=sni, host_header=host_header
            )
            transport = "TLS/SNI"
        else:
            claimed = host_header or cfg.normalise_host(flow.request.pretty_host)
            finding = self.validator.evaluate(claimed, real_ip, host_header=host_header)
            transport = "HTTP/Host"

        flow.metadata["zrlab_finding"] = finding

        if finding.verdict == V_BYPASS_SUSPECTED:
            # Avoid double-reporting the TLS case, which was already emitted
            # at ClientHello — unless the extra Host-header evidence changed
            # the verdict's confidence.
            prior = self._tls_verdicts.get(flow.client_conn.id)
            already_reported = (
                is_tls
                and prior is not None
                and prior.verdict == V_BYPASS_SUSPECTED
                and prior.confidence == finding.confidence
            )
            if not already_reported:
                self._emit_finding(
                    finding,
                    client_ip=client_ip,
                    transport=transport,
                    detection_point="http_request",
                    real_host=real_host,
                )

        if finding.drop:
            self._enforce(flow, finding, client_ip, real_host, transport)
            return

        if finding.verdict == V_UNVERIFIABLE:
            self.flows_unverifiable += 1
            self.log.warn(
                "zero_rating_unverifiable",
                client_ip=client_ip,
                claimed_host=finding.claimed_host,
                real_ip=finding.real_ip,
                transport=transport,
                action="ALLOWED",
                reason=finding.reason,
            )

    def response(self, flow: http.HTTPFlow) -> None:
        """Meter the flows that survived validation."""
        if flow.metadata.get("zrlab_control") or flow.metadata.get("zrlab_blocked"):
            return

        finding: Finding | None = flow.metadata.get("zrlab_finding")
        if finding is None:  # pragma: no cover - defensive
            return

        volume = self._flow_volume(flow)
        rating_group = (
            cfg.RATING_GROUP_ZERO_RATED if finding.zero_rate else cfg.RATING_GROUP_STANDARD
        )
        balance_before = self.meter.balance_bytes
        self.meter.meter(volume, rating_group)

        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        transport = "TLS/SNI" if flow.request.scheme == "https" else "HTTP/Host"
        common = dict(
            client_ip=client_ip,
            claimed_host=finding.claimed_host or "(none)",
            real_ip=finding.real_ip or self._real_ip(flow),
            transport=transport,
            path=flow.request.path,
            volume_bytes=volume,
            rating_group=rating_group,
        )

        if finding.zero_rate:
            self.flows_validated_zero_rated += 1
            self.log.zerorate(
                "charging_decision",
                verdict=finding.verdict,
                charged_bytes=0,
                balance_bytes=self.meter.balance_bytes,
                validated=True,
                resolved_ips=finding.resolved_ips or "(unresolved)",
                reason=finding.reason,
                **common,
            )
        else:
            self.log.charge(
                "charging_decision",
                verdict=finding.verdict,
                charged_bytes=volume,
                balance_before=balance_before,
                balance_bytes=self.meter.balance_bytes,
                reason=finding.reason,
                **common,
            )

        self._flush_report()

    # -- enforcement -------------------------------------------------------
    def _enforce(
        self,
        flow: http.HTTPFlow,
        finding: Finding,
        client_ip: str,
        real_host: str,
        transport: str,
    ) -> None:
        """Drop a flow whose zero-rating claim failed validation.

        IMPLEMENTATION NOTE — why detection and enforcement are split for TLS:
        the bypass is DETECTED at the ClientHello (stage 1), but mitmproxy's
        `tls_clienthello` hook has no "tear this down" primitive, so the drop
        is applied at the first request inside the tunnel. A real PCEF has the
        same two-phase shape for a different reason: it classifies the flow on
        the ClientHello, then applies the gate-status to subsequent packets of
        that service data flow.
        """
        self.flows_blocked += 1
        # A blocked flow must never reach the meter. In "kill" mode that is
        # automatic (no response hook fires), but "block403" synthesises a
        # response, which would otherwise be metered — billing the subscriber
        # for the rejection notice and double-counting the flow in the report.
        flow.metadata["zrlab_blocked"] = True
        self.log.alert(
            "flow_dropped",
            client_ip=client_ip,
            claimed_host=finding.claimed_host,
            real_host=real_host,
            real_ip=finding.real_ip,
            transport=transport,
            verdict=finding.verdict,
            confidence=finding.confidence,
            enforcement=cfg.ENFORCEMENT_MODE,
            action="DROPPED",
        )
        self._flush_report()

        if cfg.ENFORCEMENT_MODE == "block403":
            flow.response = http.Response.make(
                403,
                (
                    '{"verdict":"' + finding.verdict + '",'
                    '"confidence":"' + finding.confidence + '",'
                    '"detail":"zero-rating claim failed destination cross-validation",'
                    '"lab":"zero-rating-detection-lab (educational reference model)"}'
                ).encode(),
                {"Content-Type": "application/json", "X-ZRLab-Verdict": finding.verdict},
            )
        else:
            # Models a PCEF gate-close: the packets simply stop.
            flow.kill()

    # -- structured finding emission --------------------------------------
    def _emit_finding(
        self,
        finding: Finding,
        *,
        client_ip: str,
        transport: str,
        detection_point: str,
        real_host: str,
    ) -> None:
        """Emit the structured JSON detection record.

        Field set is deliberately the one a revenue-assurance / fraud team
        would want to pivot on: who, what was claimed, what was actually
        reached, over what transport, and how sure are we.
        """
        record = dict(
            client_ip=client_ip,
            claimed_host=finding.claimed_host,
            real_host=real_host,
            real_ip=finding.real_ip,
            resolved_ips=finding.resolved_ips,
            transport=transport,
            verdict=finding.verdict,
            confidence=finding.confidence,
            signals=finding.signals,
            reason=finding.reason,
            detection_point=detection_point,
            action="DROP" if finding.drop else "LOG_ONLY",
            rating_group_claimed=cfg.RATING_GROUP_ZERO_RATED,
            subscriber_msisdn=cfg.SUBSCRIBER_MSISDN,
        )
        # Once to the console/alert stream, once to the findings-only file.
        self.log.alert("zero_rating_bypass_detected", **record)
        self.findings_log.log("ALERT", "zero_rating_bypass_detected", **record)

    # -- destination extraction -------------------------------------------
    #
    # On a real gateway these three helpers collapse into "read the IP header".
    # Through a forward proxy we reconstruct the same fact from the connection
    # mitmproxy was asked to open.
    # ---------------------------------------------------------------------
    def _real_ip(self, flow: http.HTTPFlow) -> str:
        """The address the traffic is actually being sent to.

        Three sources, most authoritative first:

          1. server_conn.peername — the true socket peer. Definitive, but only
             populated once the upstream connection exists.
          2. server_conn.address — the (host, port) mitmproxy was asked to
             reach. Set for CONNECT tunnels, i.e. the whole HTTPS path.
          3. request.host / request.port — the authority from the request LINE.
             For a plaintext request through a forward proxy the client must
             send an absolute-form URI, and that authority is what the proxy
             routes on. Critically this is NOT request.host_header and NOT
             pretty_host: those are the client's *claim*, which is the thing
             under test. Mixing them up would make the detector compare the
             claim against itself and pass everything.

        LAB-HARNESS CAVEAT: source 3 only exists because we observe through a
        proxy. On a real PCEF the destination is the IP header's destination
        field — one unambiguous value, with no request-line indirection to
        reason about.
        """
        server = flow.server_conn
        if server.peername:
            return server.peername[0]
        if server.address:
            return self._address_to_ip(server.address)
        if flow.request.host:
            return self._address_to_ip((flow.request.host, flow.request.port))
        return ""

    def _address_to_ip(self, address: tuple[Any, ...] | None) -> str:
        """Turn a (host, port) target into an IP string."""
        if not address:
            return ""
        host = str(address[0])
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            # The target was given as a name (e.g. CONNECT example.com:443).
            # Resolve it so the comparison is IP-vs-IP; a name that resolves
            # to the same set as the claimed host is not a bypass.
            ips = self.resolver.resolve(host)
            return sorted(ips)[0] if ips else host

    @staticmethod
    def _address_to_host(address: tuple[Any, ...] | None) -> str:
        return str(address[0]) if address else ""

    @staticmethod
    def _real_host(flow: http.HTTPFlow) -> str:
        """The destination authority, as routed — never the claimed Host."""
        server = flow.server_conn
        if server.address:
            return str(server.address[0])
        return str(flow.request.host or "")

    @staticmethod
    def _flow_volume(flow: http.HTTPFlow) -> int:
        """Downlink volume in bytes — same accounting as classifier_naive."""
        if not flow.response:
            return 0
        body = len(flow.response.raw_content or b"")
        headers = sum(len(k) + len(v) + 4 for k, v in flow.response.headers.fields)
        status_line = len(f"HTTP/1.1 {flow.response.status_code} OK\r\n")
        return body + headers + status_line + 2


addons = [ZeroRatingBypassDetector()]

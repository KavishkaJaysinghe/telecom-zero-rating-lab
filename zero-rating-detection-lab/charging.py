# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: charging.py
#
#  The conceptual Gy-style credit meter, shared by classifier_naive.py (which
#  is fooled) and detector.py (which is not), so that the "before" and "after"
#  numbers in the demo summary are produced by identical accounting code and
#  the only variable is the classification decision.
#
#  STANDARDS CONTEXT (general terms only)
#  --------------------------------------
#  3GPP TS 32.240 describes the charging architecture; TS 32.299 specifies the
#  Diameter charging applications, where an online (Gy) session is driven by
#  Credit-Control-Request / Credit-Control-Answer pairs:
#
#      CCR-I (INITIAL_REQUEST)      session start, OCS grants a quota chunk
#      CCR-U (UPDATE_REQUEST)       report Used-Service-Unit, request more
#      CCR-T (TERMINATION_REQUEST)  final report, session teardown
#
#  Volume is reported per rating-group inside Multiple-Services-Credit-Control,
#  and a zero-rated service is simply a rating-group the operator configures at
#  0-rate. This module reproduces that SHAPE so the logs read familiarly. It is
#  emphatically NOT a Diameter implementation: no AVPs are encoded, no peer is
#  contacted, nothing leaves the process.
# =============================================================================

from __future__ import annotations

from typing import Any

import lab_config as cfg
from logging_util import JsonLinesLogger, utc_now_iso


class GyMeter:
    """In-process stand-in for OCS-side credit control.

    Tracks a subscriber balance in bytes, quota granted to the gateway in
    chunks, and per-rating-group used volume.
    """

    def __init__(self, log: JsonLinesLogger, role: str) -> None:
        self.log = log
        self.role = role
        self.balance_bytes = cfg.INITIAL_QUOTA_BYTES
        self.granted_bytes = 0  # quota currently held by the "gateway"
        self.used_since_grant = 0
        self.charged_bytes = 0  # volume that decremented the balance
        self.zero_rated_bytes = 0  # volume waived by zero-rating policy
        self.session_id = f"lab-ocs;{utc_now_iso()};1"
        self.request_number = 0
        self.flows_charged = 0
        self.flows_zero_rated = 0

    # -- session lifecycle -------------------------------------------------
    def start_session(self) -> None:
        """CCR-I: initial request; the OCS grants a first quota chunk."""
        self.request_number = 0
        grant = min(cfg.QUOTA_GRANT_BYTES, self.balance_bytes)
        self.granted_bytes = grant
        self.used_since_grant = 0
        self.log.info(
            "gy_ccr_initial",
            cc_request_type="INITIAL_REQUEST",
            cc_request_number=self.request_number,
            session_id=self.session_id,
            msisdn=cfg.SUBSCRIBER_MSISDN,
            imsi=cfg.SUBSCRIBER_IMSI,
            granted_service_unit_bytes=grant,
            balance_bytes=self.balance_bytes,
            note="conceptual model of a Gy CCR, not a real Diameter message",
        )

    def _request_more_quota(self) -> None:
        """CCR-U: report used volume, request the next quota chunk."""
        self.request_number += 1
        reported = self.used_since_grant
        grant = min(cfg.QUOTA_GRANT_BYTES, max(self.balance_bytes, 0))
        self.granted_bytes = grant
        self.used_since_grant = 0
        self.log.info(
            "gy_ccr_update",
            cc_request_type="UPDATE_REQUEST",
            cc_request_number=self.request_number,
            session_id=self.session_id,
            used_service_unit_bytes=reported,
            granted_service_unit_bytes=grant,
            balance_bytes=self.balance_bytes,
        )

    def stop_session(self) -> None:
        """CCR-T: final report at session teardown."""
        self.request_number += 1
        self.log.info(
            "gy_ccr_terminate",
            cc_request_type="TERMINATION_REQUEST",
            cc_request_number=self.request_number,
            session_id=self.session_id,
            used_service_unit_bytes=self.used_since_grant,
            total_charged_bytes=self.charged_bytes,
            total_zero_rated_bytes=self.zero_rated_bytes,
            balance_bytes=self.balance_bytes,
        )

    # -- metering ----------------------------------------------------------
    def meter(self, volume: int, rating_group: int) -> None:
        """Add `volume` bytes of downlink traffic to the given rating-group."""
        if rating_group == cfg.RATING_GROUP_ZERO_RATED:
            # 0-rate bucket: counted for reporting, never billed.
            self.zero_rated_bytes += volume
            self.flows_zero_rated += 1
            return

        self.charged_bytes += volume
        self.used_since_grant += volume
        self.balance_bytes = max(0, self.balance_bytes - volume)
        self.flows_charged += 1
        # Quota chunk exhausted -> the gateway goes back to the OCS for more.
        if self.used_since_grant >= self.granted_bytes:
            self._request_more_quota()

    def base_snapshot(self) -> dict[str, Any]:
        """Fields common to both the naive and detector reports."""
        return {
            "role": self.role,
            "generated_at": utc_now_iso(),
            "session_id": self.session_id,
            "subscriber_msisdn": cfg.SUBSCRIBER_MSISDN,
            "initial_quota_bytes": cfg.INITIAL_QUOTA_BYTES,
            "balance_bytes": self.balance_bytes,
            "charged_bytes": self.charged_bytes,
            "zero_rated_bytes": self.zero_rated_bytes,
            "flows_charged": self.flows_charged,
            "flows_zero_rated": self.flows_zero_rated,
        }

# =============================================================================
#  LAB / EDUCATIONAL - defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: demo_report.py
#
#  Builds the before/after summary that run_demo.sh prints at the end.
#
#  It reads ONLY the JSON-lines evidence files the two addons wrote - the same
#  artefacts a mediation or revenue-assurance pipeline would receive. Nothing
#  is recomputed or re-simulated here, so the summary cannot drift from what
#  the addons actually decided.
# =============================================================================

from __future__ import annotations

import argparse
import sys
from typing import Any

import lab_config as cfg
from logging_util import read_events, read_report

W = 100  # summary width

# Verdict constants are verbose on purpose (log consumers key on them), but a
# terminal table needs short labels. Map rather than truncate, so a screenshot
# never shows a half-word like "ZERO_RATING_UNVE".
VERDICT_LABEL = {
    "CHARGED_NORMAL": "CHARGED",
    "ZERO_RATED_VALID": "ZERO-RATED",
    "BYPASS_SUSPECTED": "BYPASS_SUSPECT",
    "ZERO_RATING_UNVERIFIABLE": "UNVERIFIABLE",
    "ZERO-RATED": "ZERO-RATED",
    "CHARGED": "CHARGED",
    "DROPPED": "DROPPED",
}


# ---------------------------------------------------------------------------
# Plain-text rendering helpers (stdout here is a report, not a log stream)
# ---------------------------------------------------------------------------
def rule(char: str = "=") -> str:
    return char * W


def heading(text: str) -> list[str]:
    return [rule("="), f"  {text}", rule("=")]


def section(text: str) -> list[str]:
    return ["", f"  {text}", f"  {'-' * (W - 4)}"]


# ---------------------------------------------------------------------------
# Evidence loading
# ---------------------------------------------------------------------------
def load_phase_rows(logfile: str) -> list[dict[str, Any]]:
    """Per-flow outcomes for one phase, in the order the addon decided them."""
    rows: list[dict[str, Any]] = []
    for ev in read_events(cfg.LOG_DIR / logfile):
        if ev.get("event") == "charging_decision":
            rows.append(
                {
                    "claimed": ev.get("claimed_host", ""),
                    "real_ip": ev.get("real_ip", ""),
                    "transport": ev.get("transport", ""),
                    "verdict": ev.get("verdict", ""),
                    "charged": int(ev.get("charged_bytes", 0) or 0),
                    "volume": int(ev.get("volume_bytes", 0) or 0),
                    "dropped": False,
                }
            )
        elif ev.get("event") == "flow_dropped":
            rows.append(
                {
                    "claimed": ev.get("claimed_host", ""),
                    "real_ip": ev.get("real_ip", ""),
                    "transport": ev.get("transport", ""),
                    "verdict": "DROPPED",
                    "charged": 0,
                    "volume": 0,
                    "dropped": True,
                    "confidence": ev.get("confidence", ""),
                }
            )
    return rows


def annotate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mark rows where a zero-rating was granted without validation.

    A row is a revenue leak when the claimed hostname was zero-rated but the
    destination IP is not in that hostname's resolved address set. We consult
    the same fixture the detector uses, so this column is derived from lab
    ground truth rather than from either addon's opinion.
    """
    fixtures = cfg.load_dns_fixtures()
    for row in rows:
        legit_ips = fixtures.get(cfg.normalise_host(row["claimed"]), [])
        row["spoofed"] = bool(
            cfg.is_zero_rated(row["claimed"]) and row["real_ip"] not in legit_ips
        )
        row["leak"] = row["spoofed"] and not row["dropped"] and row["charged"] == 0
    return rows


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
COLS = "  {:<18} {:<15} {:<10} {:<15} {:>10}  {}"


def render_table(rows: list[dict[str, Any]]) -> list[str]:
    out = [
        COLS.format(
            "CLAIMED HOST", "ACTUAL DEST", "TRANSPORT", "VERDICT", "CHARGED", ""
        )
    ]
    if not rows:
        out.append("  (no flows recorded)")
        return out
    for row in rows:
        flag = ""
        if row["leak"]:
            flag = "<== REVENUE LEAK: spoof believed"
        elif row["dropped"]:
            flag = f"<== BLOCKED ({row.get('confidence', '')})"
        elif row["spoofed"]:
            flag = "<== spoof, correctly not waived"
        verdict = VERDICT_LABEL.get(row["verdict"], row["verdict"])
        out.append(
            COLS.format(
                row["claimed"][:18],
                row["real_ip"][:15] or "(unknown)",
                row["transport"][:10],
                verdict[:15],
                cfg.human_bytes(row["charged"]),
                flag,
            )
        )
    return out


def render_totals(label: str, report: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    charged = int(report.get("charged_bytes", 0) or 0)
    waived = int(report.get("zero_rated_bytes", 0) or 0)
    leaked = sum(r["volume"] for r in rows if r["leak"])
    blocked = sum(1 for r in rows if r["dropped"])
    lines = [
        "",
        f"  {label}",
        f"    billed to subscriber ....... {cfg.human_bytes(charged)}",
        f"    waived as zero-rated ....... {cfg.human_bytes(waived)}",
        f"    remaining balance .......... {cfg.human_bytes(int(report.get('balance_bytes', 0) or 0))}",
        f"    flows blocked .............. {blocked}",
        f"    REVENUE LEAKAGE ............ {cfg.human_bytes(leaked)}"
        + ("   <== fraud succeeded" if leaked else "   <== none"),
    ]
    return lines


def render_findings() -> list[str]:
    findings = read_events(cfg.LOG_DIR / "detector_findings.jsonl")
    out = section("DETECTOR FINDINGS (structured JSON, one object per detection)")
    if not findings:
        out.append("  (none)")
        return out
    for f in findings:
        out.append(
            f"    [{f.get('confidence', '')}] {f.get('verdict', '')}"
            f"  claimed={f.get('claimed_host', '')}"
            f"  real_ip={f.get('real_ip', '')}"
            f"  transport={f.get('transport', '')}"
            f"  action={f.get('action', '')}"
        )
        for sig in f.get("signals", []) or []:
            out.append(f"        signal: {sig}")
    return out


def build_report() -> str:
    naive_rows = annotate(load_phase_rows("classifier_naive.jsonl"))
    det_rows = annotate(load_phase_rows("detector.jsonl"))
    naive_report = read_report("naive_meter_report.json")
    det_report = read_report("detector_report.json")

    lines: list[str] = []
    lines += heading("ZERO-RATING BYPASS DETECTION LAB  -  BEFORE / AFTER SUMMARY")
    lines += [
        "  Simplified reference model built from public 3GPP concepts",
        "  (traffic classification -> PCC rules -> PCEF metering -> OCS over Gy,",
        "   cf. 3GPP TS 32.299 / TS 32.240). NOT any operator's production system.",
        "  Every address in this run is loopback. Nothing left this machine.",
    ]

    lines += section("PHASE 1 - NAIVE CLASSIFIER   (trusts the claimed Host / SNI)")
    lines += render_table(naive_rows)
    lines += render_totals("Meter totals after phase 1:", naive_report, naive_rows)

    lines += section("PHASE 2 - CROSS-VALIDATING DETECTOR   (claim checked against real dest IP)")
    lines += render_table(det_rows)
    lines += render_totals("Meter totals after phase 2:", det_report, det_rows)

    lines += render_findings()

    # --- the headline comparison ------------------------------------------
    naive_leak = sum(r["volume"] for r in naive_rows if r["leak"])
    det_leak = sum(r["volume"] for r in det_rows if r["leak"])
    blocked = sum(1 for r in det_rows if r["dropped"])

    lines += section("RESULT")
    lines += [
        f"    naive classifier    : {cfg.human_bytes(naive_leak)} waived on unverified claims"
        f"  ({sum(1 for r in naive_rows if r['leak'])} spoofed flow(s) believed)",
        f"    cross-validating    : {cfg.human_bytes(det_leak)} waived on unverified claims"
        f"  ({blocked} spoofed flow(s) dropped)",
        "",
        f"    leakage prevented   : {cfg.human_bytes(naive_leak - det_leak)}"
        f"  ({_pct(naive_leak - det_leak, naive_leak)} of the attempted bypass)",
    ]

    # Legitimate zero-rating must survive, or the detector is useless in
    # production: a bypass detector that breaks the free tier it protects gets
    # switched off in week one. So report a real false-positive COUNT.
    # A false positive = a flow whose zero-rating claim was TRUE (the
    # destination really is in the claimed host's address set) that we
    # nonetheless dropped or billed.
    genuine = [
        r for r in det_rows if cfg.is_zero_rated(r["claimed"]) and not r["spoofed"]
    ]
    false_positives = [r for r in genuine if r["dropped"] or r["charged"] > 0]
    preserved = [r for r in genuine if not r["dropped"] and r["charged"] == 0]
    lines += [
        "",
        f"    false positives     : {len(false_positives)}"
        f"   (out of {len(genuine)} genuine zero-rated flow(s) offered)",
        f"    free tier preserved : {len(preserved)} flow(s), "
        f"{cfg.human_bytes(sum(r['volume'] for r in preserved))} correctly still waived",
    ]

    lines += ["", rule("=")]
    lines += [
        "  Evidence files (JSON Lines):",
        f"    {cfg.LOG_DIR / 'classifier_naive.jsonl'}",
        f"    {cfg.LOG_DIR / 'detector.jsonl'}",
        f"    {cfg.LOG_DIR / 'detector_findings.jsonl'}",
        f"    {cfg.LOG_DIR / 'attacker_client.jsonl'}",
        rule("="),
    ]
    return "\n".join(lines)


def _pct(part: int, whole: int) -> str:
    if whole <= 0:
        return "n/a"
    return f"{100.0 * part / whole:.0f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the demo before/after summary.")
    parser.parse_args()
    # stdout, not the JSONL logger: this is a human report, and run_demo.sh
    # pipes it straight to the terminal for the portfolio screenshot.
    print(build_report())
    return 0


if __name__ == "__main__":
    sys.exit(main())

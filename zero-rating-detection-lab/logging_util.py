# =============================================================================
#  LAB / EDUCATIONAL — defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: logging_util.py
#
#  Shared structured JSON-lines logger.
#
#  Why JSON Lines: charging and fraud events in a real deployment are shipped
#  to a mediation / revenue-assurance pipeline, not read off a console. One
#  self-describing JSON object per line is the lowest-common-denominator
#  format that every collector (Kafka, Splunk, Elastic, plain `jq`) ingests
#  without a schema negotiation. Bare print() is deliberately never used in
#  this project.
#
#  Every record carries at minimum:  ts, level, event, component
#  Callers add whatever structured fields the event needs as **kwargs.
# =============================================================================

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from lab_config import LOG_DIR

# --------------------------------------------------------------------------
# Terminal colouring — purely cosmetic, so the naive-vs-detector contrast is
# obvious in a screenshot. Disabled automatically when output is redirected
# or when the conventional NO_COLOR variable is set.
# --------------------------------------------------------------------------
_RESET = "\033[0m"
_COLOURS = {
    "DEBUG": "\033[90m",  # grey
    "INFO": "\033[36m",  # cyan
    "CHARGE": "\033[32m",  # green
    "ZERORATE": "\033[34m",  # blue
    "WARN": "\033[33m",  # yellow
    "ALERT": "\033[1;31m",  # bold red
    "ERROR": "\033[31m",  # red
}


def _colour_enabled(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("ZRLAB_FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _enable_windows_ansi() -> None:
    """Turn on VT100 processing for legacy Windows consoles (no-op elsewhere)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # -11 = STD_OUTPUT_HANDLE, -12 = STD_ERROR_HANDLE
        for handle_id in (-11, -12):
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # pragma: no cover - cosmetic only, never fatal
        pass


_enable_windows_ansi()


def utc_now_iso() -> str:
    """RFC3339 / ISO-8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class JsonLinesLogger:
    """Append-only JSON-lines logger with an optional human-readable mirror.

    Thread-safe: mitmproxy runs addon hooks on its own event loop thread and
    the lab origin server is threaded, so writes are mutex-protected and each
    line is flushed immediately (a killed demo must not lose its evidence).
    """

    def __init__(
        self,
        component: str,
        filename: str | None = None,
        echo: bool = True,
        echo_stream: TextIO | None = None,
        append: bool = False,
    ) -> None:
        self.component = component
        self.echo = echo
        self.echo_stream = echo_stream or sys.stderr
        self._colour = echo and _colour_enabled(self.echo_stream)
        self._lock = threading.Lock()

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path: Path = LOG_DIR / (filename or f"{component}.jsonl")
        # Default is truncate-on-start, so each run produces a clean evidence
        # file. append=True is for writers that are invoked more than once per
        # demo run (the attacker harness runs in both phases).
        self._fh = self.path.open("a" if append else "w", encoding="utf-8")

    # -- core -------------------------------------------------------------
    def log(self, level: str, event: str, **fields: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            "ts": utc_now_iso(),
            "level": level.upper(),
            "component": self.component,
            "event": event,
        }
        record.update(fields)

        line = json.dumps(record, separators=(",", ":"), default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            if self.echo:
                self.echo_stream.write(self._format_human(record) + "\n")
                self.echo_stream.flush()
        return record

    # -- level shorthands --------------------------------------------------
    def debug(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("DEBUG", event, **f)

    def info(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("INFO", event, **f)

    def charge(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("CHARGE", event, **f)

    def zerorate(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("ZERORATE", event, **f)

    def warn(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("WARN", event, **f)

    def alert(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("ALERT", event, **f)

    def error(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("ERROR", event, **f)

    # -- presentation ------------------------------------------------------
    def _format_human(self, record: dict[str, Any]) -> str:
        """One compact line for the console; the JSONL file stays canonical."""
        level = record["level"]
        skip = {"ts", "level", "component", "event"}
        detail = " ".join(
            f"{k}={record[k]}" for k in record if k not in skip and record[k] != ""
        )
        # Trim the timestamp to HH:MM:SS for on-screen density.
        clock = record["ts"][11:19]
        head = f"{clock} [{level:<8}] {record['event']:<26}"
        line = f"{head} {detail}".rstrip()
        if self._colour:
            colour = _COLOURS.get(level, "")
            return f"{colour}{line}{_RESET}"
        return line

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                self._fh.close()


def read_events(path: Path | str) -> list[dict[str, Any]]:
    """Read a JSON-lines file back into a list of records.

    Used by demo_report.py to build the before/after summary from the same
    evidence files an analyst would receive. Malformed trailing lines (e.g.
    from a hard kill mid-write) are skipped rather than raising.
    """
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def write_report(name: str, payload: dict[str, Any]) -> Path:
    """Write a single-object JSON summary (meter totals, detector totals)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / name
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def read_report(name: str) -> dict[str, Any]:
    """Read back a JSON summary written by write_report(); {} if absent."""
    path = LOG_DIR / name
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError:
        return {}

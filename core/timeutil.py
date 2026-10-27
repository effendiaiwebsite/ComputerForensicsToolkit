"""Timestamp helpers shared by the sidecar ops and the report generator."""

from __future__ import annotations

from datetime import UTC, datetime


def iso_to_ms(s: str | None) -> int | None:
    """Best-effort ISO 8601 → epoch milliseconds; ``None`` when unparsable.

    Accepts a ``Z`` suffix and fractional seconds longer than the six digits
    ``datetime.fromisoformat`` tolerates (artifact timestamps carry 100 ns
    ticks). Naive values are taken as UTC.
    """
    if not s:
        return None
    txt = s.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        if "." not in txt:
            return None
        head, _, tail = txt.partition(".")
        tz_idx = next((i for i, ch in enumerate(tail) if ch in "+-"), -1)
        tz = tail[tz_idx:] if tz_idx >= 0 else ""
        frac = (tail[:tz_idx] if tz_idx >= 0 else tail)[:6]
        try:
            dt = datetime.fromisoformat(f"{head}.{frac}{tz}")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp() * 1000)

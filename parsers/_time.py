"""Timestamp normalization shared by every parser.

All parsers emit ``YYYY-MM-DDTHH:MM:SSZ`` (the ``core.events.utc_iso``
convention) so text ``ORDER BY timestamp`` in the store is chronological.
Library output arrives in several shapes: aware ``datetime``, regipy's
``isoformat()`` with ``+00:00``, python-evtx's space-separated
``isoformat(" ")``, WinVer's ``%Y-%m-%d %H:%M:%S`` and AmCache's
``MM/DD/YYYY HH:MM:SS`` link date. Naive inputs are taken as UTC.

FILETIME 0 decodes to 1601-01-01; any year before 1970 is a sentinel for
"unset" and becomes ``None`` rather than a bogus 17th-century event.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

_MIN_YEAR = 1970
_MAX_YEAR = 9000
_FALLBACK_FORMATS = ("%m/%d/%Y %H:%M:%S",)


def to_iso_utc(value: Any, *, microseconds: bool = False) -> str | None:
    """Normalize ``value`` to ``...Z`` UTC ISO 8601, or ``None`` when absent/unusable."""
    dt = to_datetime_utc(value)
    if dt is None:
        return None
    if microseconds:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_datetime_utc(value: Any) -> datetime | None:
    """Coerce a datetime or timestamp string to an aware UTC ``datetime``."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = _parse_str(value.strip())
        if dt is None:
            return None
    else:
        return None
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    if dt.year < _MIN_YEAR or dt.year > _MAX_YEAR:
        return None
    return dt


def _parse_str(text: str) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in _FALLBACK_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    logger.debug("unrecognized timestamp string: %r", text)
    return None

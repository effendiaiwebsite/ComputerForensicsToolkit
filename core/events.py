"""Normalized forensic ``Event`` — universal glue between parsers, store, rules, UI.

See ``docs/EVENT_SCHEMA.md`` for the canonical field-by-field spec. This module
is the Python source of truth.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

TimestampSource = Literal["direct", "inferred", "none"]
HostOs = Literal["windows", "macos", "linux"]


@dataclass
class Event:
    host_os: HostOs
    host_id: str
    source_artifact: str
    source_path: str
    event_type: str
    summary: str
    evidence: dict[str, Any]
    collection_id: str
    parser_version: str
    timestamp: str | None = None
    timestamp_source: TimestampSource = "none"
    user: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def to_json_str(self) -> str:
        return json.dumps(self.to_json(), separators=(",", ":"), default=str)


def utc_iso(dt: datetime) -> str:
    """Format a datetime as a Z-suffixed ISO 8601 string in UTC."""
    if dt.tzinfo is None:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(
    *,
    host_os: HostOs,
    host_id: str,
    source_artifact: str,
    source_path: str,
    event_type: str,
    summary: str,
    evidence: dict[str, Any],
    collection_id: str,
    parser_version: str,
    timestamp: datetime | str | None = None,
    timestamp_source: TimestampSource | None = None,
    user: str | None = None,
    raw: dict[str, Any] | None = None,
) -> Event:
    """Build an ``Event`` with sensible defaults.

    If ``timestamp_source`` is not given, infer it from the presence of
    ``timestamp`` — ``"direct"`` when given, ``"none"`` when ``None``.
    """
    ts_str: str | None
    if isinstance(timestamp, datetime):
        ts_str = utc_iso(timestamp)
    else:
        ts_str = timestamp

    if timestamp_source is None:
        timestamp_source = "direct" if ts_str is not None else "none"

    return Event(
        host_os=host_os,
        host_id=host_id,
        source_artifact=source_artifact,
        source_path=source_path,
        event_type=event_type,
        summary=summary,
        evidence=evidence,
        collection_id=collection_id,
        parser_version=parser_version,
        timestamp=ts_str,
        timestamp_source=timestamp_source,
        user=user,
        raw=raw or {},
    )

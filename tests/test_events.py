"""Tests for the normalized Event schema."""

from __future__ import annotations

from datetime import UTC, datetime

from core.events import Event, make_event, utc_iso


def test_make_event_infers_timestamp_source_direct() -> None:
    ev = make_event(
        host_os="windows",
        host_id="HOST",
        source_artifact="registry.system",
        source_path=r"C:\hive",
        event_type="usb_connection",
        summary="x",
        evidence={"a": 1},
        collection_id="col-1",
        parser_version="p/0.1",
        timestamp=datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC),
    )
    assert ev.timestamp == "2026-06-11T12:00:00Z"
    assert ev.timestamp_source == "direct"


def test_make_event_infers_timestamp_source_none_when_missing() -> None:
    ev = make_event(
        host_os="windows",
        host_id="HOST",
        source_artifact="registry.system",
        source_path=r"C:\hive",
        event_type="system_config_change",
        summary="x",
        evidence={},
        collection_id="col-1",
        parser_version="p/0.1",
    )
    assert ev.timestamp is None
    assert ev.timestamp_source == "none"


def test_event_id_is_unique() -> None:
    a = make_event(
        host_os="windows", host_id="H", source_artifact="s", source_path="p",
        event_type="t", summary="x", evidence={}, collection_id="c", parser_version="v",
    )
    b = make_event(
        host_os="windows", host_id="H", source_artifact="s", source_path="p",
        event_type="t", summary="x", evidence={}, collection_id="c", parser_version="v",
    )
    assert a.event_id != b.event_id


def test_to_json_roundtrips_through_dict() -> None:
    ev = make_event(
        host_os="linux", host_id="laptop", source_artifact="syslog", source_path="/var/log/syslog",
        event_type="logon", summary="ok", evidence={"user": "root"},
        collection_id="col", parser_version="v",
    )
    payload = ev.to_json()
    assert payload["host_os"] == "linux"
    assert payload["evidence"] == {"user": "root"}
    assert payload["raw"] == {}
    assert isinstance(payload["event_id"], str)


def test_utc_iso_handles_naive_datetime_as_utc() -> None:
    s = utc_iso(datetime(2026, 1, 1, 0, 0, 0))
    assert s.endswith("Z")


def test_event_dataclass_accepts_string_timestamp_directly() -> None:
    ev = Event(
        host_os="windows", host_id="H", source_artifact="s", source_path="p",
        event_type="t", summary="x", evidence={}, collection_id="c", parser_version="v",
        timestamp="2026-06-11T00:00:00Z", timestamp_source="direct",
    )
    assert ev.timestamp == "2026-06-11T00:00:00Z"

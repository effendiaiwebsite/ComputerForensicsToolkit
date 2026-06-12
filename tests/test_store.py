"""Tests for the SQLite EventStore."""

from __future__ import annotations

import pytest

from core.events import make_event
from core.store import EventStore


def _ev(**overrides):
    defaults = dict(
        host_os="windows",
        host_id="HOST",
        source_artifact="registry.system",
        source_path=r"C:\hive",
        event_type="usb_connection",
        summary="USB: SanDisk Cruzer",
        evidence={"vendor": "SanDisk"},
        collection_id="col-1",
        parser_version="p/0.1",
    )
    defaults.update(overrides)
    return make_event(**defaults)


def test_insert_and_count() -> None:
    store = EventStore()
    store.register_collection("col-1", "HOST", "windows", "2026-06-11T00:00:00Z")
    n = store.insert_events([_ev(), _ev(event_type="service_install", summary="svc x")])
    assert n == 2
    assert store.count_events() == 2
    assert store.count_events(collection_id="col-1") == 2
    assert store.count_events(collection_id="col-other") == 0


def test_query_filter_by_event_type() -> None:
    store = EventStore()
    store.insert_events([
        _ev(event_type="usb_connection", summary="usb 1"),
        _ev(event_type="service_install", summary="svc 1"),
        _ev(event_type="usb_connection", summary="usb 2"),
    ])
    rows = store.query_events(event_type="usb_connection")
    assert len(rows) == 2
    assert all(r["event_type"] == "usb_connection" for r in rows)


def test_query_summary_contains_case_insensitive_like() -> None:
    store = EventStore()
    store.insert_events([
        _ev(summary="USB SanDisk Cruzer"),
        _ev(summary="Service installed: defender"),
    ])
    rows = store.query_events(summary_contains="cruzer")
    assert len(rows) == 1


def test_query_sort_by_timestamp_asc_with_nulls_last() -> None:
    store = EventStore()
    store.insert_events([
        _ev(timestamp="2026-06-11T00:00:00Z", summary="b"),
        _ev(timestamp=None, summary="null"),
        _ev(timestamp="2026-06-10T00:00:00Z", summary="a"),
    ])
    rows = store.query_events(sort_by="timestamp", sort_dir="asc")
    summaries = [r["summary"] for r in rows]
    assert summaries == ["a", "b", "null"]


def test_query_rejects_bad_sort_column() -> None:
    store = EventStore()
    with pytest.raises(ValueError):
        store.query_events(sort_by="evidence_json")


def test_query_pagination() -> None:
    store = EventStore()
    store.insert_events([_ev(summary=f"row {i}") for i in range(5)])
    page1 = store.query_events(limit=2, offset=0, sort_by="summary")
    page2 = store.query_events(limit=2, offset=2, sort_by="summary")
    assert [r["summary"] for r in page1] == ["row 0", "row 1"]
    assert [r["summary"] for r in page2] == ["row 2", "row 3"]


def test_query_returns_decoded_evidence_and_raw() -> None:
    store = EventStore()
    store.insert_events([_ev(evidence={"x": 1}, raw={"y": [1, 2, 3]})])
    rows = store.query_events()
    assert rows[0]["evidence"] == {"x": 1}
    assert rows[0]["raw"] == {"y": [1, 2, 3]}

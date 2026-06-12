"""Tests for sidecar IPC ops backed by a real EventStore."""

from __future__ import annotations

from core.__main__ import build_dispatcher
from core.events import make_event
from core.store import EventStore


def test_ping_returns_versions() -> None:
    d = build_dispatcher(EventStore())
    result = d.dispatch({"op": "ping"})
    assert result["ok"] is True
    assert "sidecar_version" in result
    assert "schema_version" in result


def test_query_events_filters_and_paginates() -> None:
    store = EventStore()
    store.insert_events([
        make_event(
            host_os="windows", host_id="H", source_artifact="registry.system",
            source_path="p", event_type="usb_connection",
            summary=f"USB device #{i}", evidence={}, collection_id="col-1",
            parser_version="v",
        )
        for i in range(3)
    ])
    store.insert_events([
        make_event(
            host_os="windows", host_id="H", source_artifact="registry.system",
            source_path="p", event_type="service_install",
            summary="Service: defender", evidence={}, collection_id="col-1",
            parser_version="v",
        ),
    ])

    d = build_dispatcher(store)

    result = d.dispatch({
        "op": "query_events",
        "event_type": "usb_connection",
        "sort_by": "summary",
        "sort_dir": "asc",
    })
    assert result["ok"] is True
    assert len(result["events"]) == 3
    assert all(e["event_type"] == "usb_connection" for e in result["events"])
    assert result["total"] == 4


def test_run_triage_system_hive_requires_path() -> None:
    d = build_dispatcher(EventStore())
    result = d.dispatch({"op": "run_triage_system_hive"})
    assert result["ok"] is False
    assert "hive_path" in result["error"]


def test_run_triage_system_hive_reports_missing_file() -> None:
    d = build_dispatcher(EventStore())
    result = d.dispatch({"op": "run_triage_system_hive", "hive_path": "C:/nonexistent.hive"})
    assert result["ok"] is False
    assert "FileNotFoundError" in result["error"]

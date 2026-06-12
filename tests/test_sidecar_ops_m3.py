"""Sidecar ops added in M3."""

from __future__ import annotations

from core.__main__ import build_dispatcher
from core.store import EventStore


def test_run_triage_hive_requires_path() -> None:
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive"})
    assert r["ok"] is False
    assert "hive_path" in r["error"]


def test_run_triage_directory_requires_path() -> None:
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_directory"})
    assert r["ok"] is False
    assert "dir_path" in r["error"]


def test_run_triage_directory_reports_no_hives(tmp_path) -> None:
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is False
    assert "no registry hives" in r["error"]


def test_query_events_returns_counts() -> None:
    from core.events import make_event

    store = EventStore()
    store.insert_events([
        make_event(
            host_os="windows", host_id="H", source_artifact="registry.system",
            source_path="p", event_type="usb_connection", summary="x",
            evidence={}, collection_id="c", parser_version="v",
        ),
        make_event(
            host_os="windows", host_id="H", source_artifact="registry.software",
            source_path="p", event_type="program_install", summary="y",
            evidence={}, collection_id="c", parser_version="v",
        ),
    ])
    d = build_dispatcher(store)
    r = d.dispatch({"op": "query_events", "collection_id": "c"})
    assert r["ok"] is True
    assert r["by_event_type"] == {"usb_connection": 1, "program_install": 1}
    assert r["by_source_artifact"] == {"registry.system": 1, "registry.software": 1}

"""M3 EventStore extensions: list filters + per-type/source counts."""

from __future__ import annotations

from core.events import make_event
from core.store import EventStore


def _ev(**overrides):
    defaults = dict(
        host_os="windows",
        host_id="HOST",
        source_artifact="registry.system",
        source_path=r"C:\hive",
        event_type="usb_connection",
        summary="x",
        evidence={},
        collection_id="col-1",
        parser_version="v",
    )
    defaults.update(overrides)
    return make_event(**defaults)


def test_query_filter_event_types_list() -> None:
    store = EventStore()
    store.insert_events([
        _ev(event_type="usb_connection"),
        _ev(event_type="service_install"),
        _ev(event_type="program_execution"),
    ])
    rows = store.query_events(event_types=["usb_connection", "service_install"])
    assert sorted(r["event_type"] for r in rows) == ["service_install", "usb_connection"]


def test_query_filter_source_artifacts_list() -> None:
    store = EventStore()
    store.insert_events([
        _ev(source_artifact="registry.system", event_type="x"),
        _ev(source_artifact="registry.software", event_type="x"),
        _ev(source_artifact="registry.ntuser", event_type="x"),
    ])
    rows = store.query_events(source_artifacts=["registry.system", "registry.ntuser"])
    assert sorted(r["source_artifact"] for r in rows) == [
        "registry.ntuser",
        "registry.system",
    ]


def test_counts_by_event_type() -> None:
    store = EventStore()
    store.insert_events([
        _ev(event_type="usb_connection"),
        _ev(event_type="usb_connection"),
        _ev(event_type="service_install"),
    ])
    counts = store.counts_by_event_type()
    assert counts == {"usb_connection": 2, "service_install": 1}


def test_counts_by_source_artifact_scoped_to_collection() -> None:
    store = EventStore()
    store.insert_events([
        _ev(collection_id="col-1", source_artifact="registry.system"),
        _ev(collection_id="col-1", source_artifact="registry.software"),
        _ev(collection_id="col-other", source_artifact="registry.system"),
    ])
    counts = store.counts_by_source_artifact(collection_id="col-1")
    assert counts == {"registry.system": 1, "registry.software": 1}

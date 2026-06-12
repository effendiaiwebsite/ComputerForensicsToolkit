"""Tests for the timeline query op."""

from __future__ import annotations

from core.__main__ import _iso_to_ms, build_dispatcher
from core.events import make_event
from core.store import EventStore


def _ev(**overrides):
    defaults = dict(
        host_os="windows",
        host_id="HOST",
        source_artifact="registry.system",
        source_path="p",
        event_type="usb_connection",
        summary="x",
        evidence={},
        collection_id="col-1",
        parser_version="v",
    )
    defaults.update(overrides)
    return make_event(**defaults)


def test_iso_to_ms_handles_zulu_and_offset() -> None:
    a = _iso_to_ms("2026-06-11T12:00:00Z")
    b = _iso_to_ms("2026-06-11T12:00:00+00:00")
    assert a == b
    # 2026-06-11T12:00:00Z → known epoch
    assert a == int(
        __import__("datetime").datetime(2026, 6, 11, 12, 0, 0, tzinfo=__import__("datetime").timezone.utc).timestamp() * 1000
    )


def test_iso_to_ms_handles_fractional_seconds() -> None:
    ms = _iso_to_ms("2026-06-11T12:00:00.123456Z")
    assert ms is not None
    assert ms % 1000 == 123


def test_iso_to_ms_returns_none_for_garbage() -> None:
    assert _iso_to_ms("not a timestamp") is None
    assert _iso_to_ms(None) is None


def test_query_timeline_categories_and_points() -> None:
    store = EventStore()
    store.insert_events([
        _ev(timestamp="2026-06-11T12:00:00Z", source_artifact="registry.system", event_type="usb_connection", summary="usb"),
        _ev(timestamp="2026-06-11T13:00:00Z", source_artifact="evtx.security", event_type="logon", summary="login"),
        _ev(timestamp=None, source_artifact="registry.software", event_type="system_config_change", summary="cfg"),
    ])

    d = build_dispatcher(store)
    res = d.dispatch({"op": "query_timeline", "collection_id": "col-1"})

    assert res["ok"] is True
    assert sorted(res["categories"]) == ["evtx.security", "registry.system"]
    assert len(res["points"]) == 2
    assert res["total"] == 2
    assert res["skipped_null_ts"] == 1
    # Ascending timestamp order
    assert res["points"][0]["ts_ms"] < res["points"][1]["ts_ms"]
    # category_idx maps back to the categories list
    for p in res["points"]:
        assert res["categories"][p["category_idx"]] in {"registry.system", "evtx.security"}


def test_query_timeline_respects_event_types_filter() -> None:
    store = EventStore()
    store.insert_events([
        _ev(timestamp="2026-06-11T12:00:00Z", event_type="usb_connection"),
        _ev(timestamp="2026-06-11T13:00:00Z", event_type="logon"),
    ])
    d = build_dispatcher(store)
    res = d.dispatch({"op": "query_timeline", "event_types": ["logon"]})
    assert res["ok"] is True
    assert len(res["points"]) == 1
    assert res["points"][0]["event_type"] == "logon"


def test_get_event_returns_full_event() -> None:
    store = EventStore()
    ev = _ev(timestamp="2026-06-11T12:00:00Z", evidence={"x": 1}, raw={"y": 2})
    store.insert_events([ev])
    d = build_dispatcher(store)
    res = d.dispatch({"op": "get_event", "event_id": ev.event_id})
    assert res["ok"] is True
    assert res["event"]["event_id"] == ev.event_id
    assert res["event"]["evidence"] == {"x": 1}
    assert res["event"]["raw"] == {"y": 2}


def test_get_event_unknown_returns_error() -> None:
    d = build_dispatcher(EventStore())
    res = d.dispatch({"op": "get_event", "event_id": "nope"})
    assert res["ok"] is False
    assert "not found" in res["error"]

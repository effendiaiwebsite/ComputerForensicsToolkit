"""Tests for busy-day detection (core.activity) and its store + sidecar wiring."""

from __future__ import annotations

from core.__main__ import build_dispatcher
from core.activity import compute_activity
from core.events import make_event
from core.store import EventStore


def _daily(*pairs: tuple[str, int]) -> list[dict]:
    return [{"date": d, "count": c, "by_event_type": {"x": c}} for d, c in pairs]


# ----- pure stats -------------------------------------------------------------


def test_compute_activity_flags_spike():
    daily = _daily(("2007-07-10", 5), ("2007-07-11", 4), ("2007-07-12", 6),
                   ("2007-07-13", 5), ("2007-07-14", 80))
    res = compute_activity(daily, k=1.5)
    assert res["busy_dates"] == ["2007-07-14"]
    assert res["threshold"] > 6
    assert next(d for d in res["days"] if d["date"] == "2007-07-14")["busy"] is True


def test_compute_activity_flat_distribution_flags_nothing():
    res = compute_activity(_daily(("d1", 10), ("d2", 10), ("d3", 10)), k=1.5)
    assert res["busy_dates"] == []


def test_compute_activity_empty():
    res = compute_activity([], k=1.5)
    assert res["days"] == [] and res["busy_dates"] == [] and res["threshold"] == 0.0


# ----- store aggregation ------------------------------------------------------


def _ev(ts: str, etype: str = "program_execution"):
    return make_event(
        host_os="windows", host_id="H", source_artifact="a", source_path="p",
        event_type=etype, summary="s", evidence={}, collection_id="c",
        parser_version="v", timestamp=ts,
    )


def test_activity_by_day_groups_and_counts():
    store = EventStore()
    store.register_collection(collection_id="c", host_id="H", host_os="windows",
                              created_at="2026-01-01T00:00:00Z")
    store.insert_events([
        _ev("2007-07-14T01:00:00Z"),
        _ev("2007-07-14T09:00:00Z", "browser_visit"),
        _ev("2007-07-15T10:00:00Z"),
        _ev(None),  # undated → excluded
    ])
    daily = store.activity_by_day(collection_id="c")
    by_date = {d["date"]: d for d in daily}
    assert by_date["2007-07-14"]["count"] == 2
    assert by_date["2007-07-14"]["by_event_type"] == {"program_execution": 1, "browser_visit": 1}
    assert by_date["2007-07-15"]["count"] == 1
    # ascending order preserved
    assert [d["date"] for d in daily] == ["2007-07-14", "2007-07-15"]


# ----- sidecar op -------------------------------------------------------------


def test_query_activity_by_day_op():
    store = EventStore()
    store.register_collection(collection_id="c", host_id="H", host_os="windows",
                              created_at="2026-01-01T00:00:00Z")
    events = [_ev(f"2007-07-{day:02d}T0{h}:00:00Z") for day in range(10, 14) for h in range(2)]
    events += [_ev(f"2007-07-14T0{h}:00:00Z") for h in range(9)]  # spike day
    store.insert_events(events)
    d = build_dispatcher(store)
    r = d.dispatch({"op": "query_activity_by_day", "collection_id": "c"})
    assert r["ok"] is True
    assert "2007-07-14" in r["busy_dates"]
    assert r["k"] == 1.5

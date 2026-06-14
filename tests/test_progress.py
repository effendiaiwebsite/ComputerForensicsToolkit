"""Tests for the in-memory progress tracker."""

from __future__ import annotations

import threading

from core.progress import ProgressTracker


def test_start_update_finish() -> None:
    t = ProgressTracker()
    snap = t.start("col-1", label="copy hives", total=10)
    assert snap.phase == "running"
    assert snap.total == 10

    t.update("col-1", current_item="SYSTEM", completed_delta=1, category="registry")
    t.update("col-1", current_item="SOFTWARE", completed_delta=1, category="registry")
    snap = t.get("col-1")
    assert snap is not None
    assert snap.completed == 2
    assert snap.current_item == "SOFTWARE"
    assert snap.by_category == {"registry": 2}

    t.finish("col-1")
    snap = t.get("col-1")
    assert snap.phase == "done"
    assert snap.finished_at is not None


def test_finish_with_error() -> None:
    t = ProgressTracker()
    t.start("col-2", label="x")
    t.finish("col-2", error="boom")
    assert t.get("col-2").phase == "error"
    assert t.get("col-2").error == "boom"


def test_get_unknown_returns_none() -> None:
    assert ProgressTracker().get("nope") is None


def test_thread_safe_concurrent_updates() -> None:
    t = ProgressTracker()
    t.start("col-x", label="parallel", total=1000)

    def bump() -> None:
        for _ in range(100):
            t.update("col-x", completed_delta=1, category="cat")

    threads = [threading.Thread(target=bump) for _ in range(10)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    snap = t.get("col-x")
    assert snap.completed == 1000
    assert snap.by_category["cat"] == 1000


def test_to_dict_is_serializable() -> None:
    import json

    t = ProgressTracker()
    t.start("c", label="x", total=1)
    t.update("c", current_item="item", completed_delta=1)
    t.finish("c")
    s = t.get("c").to_dict()
    json.dumps(s)  # must not raise
    assert s["phase"] == "done"

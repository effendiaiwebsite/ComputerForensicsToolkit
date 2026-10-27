"""Sidecar ops for M9 — browser History ingest + domain rollup."""

from __future__ import annotations

from pathlib import Path

from core.__main__ import build_dispatcher
from core.store import EventStore
from tests.test_browser_parser import _build_history_db


def _chrome_history_path(root: Path) -> Path:
    chrome_dir = (
        root / "Users" / "alice" / "AppData" / "Local" / "Google" / "Chrome"
        / "User Data" / "Default"
    )
    chrome_dir.mkdir(parents=True)
    db_path = chrome_dir / "History"
    _build_history_db(db_path)
    return db_path


def test_run_triage_hive_dispatches_browser_history(tmp_path: Path) -> None:
    db = _chrome_history_path(tmp_path)
    store = EventStore()
    d = build_dispatcher(store)
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(db)})
    assert r["ok"] is True
    assert r["kind"] == "chrome.history"
    # 3 visits + 1 download + 1 search
    assert r["event_count"] == 5
    assert r["by_event_type"]["browser_visit"] == 3
    assert r["by_event_type"]["browser_download"] == 1
    assert r["by_event_type"]["browser_search"] == 1


def test_run_triage_directory_picks_up_browser_history(tmp_path: Path) -> None:
    _chrome_history_path(tmp_path)
    store = EventStore()
    d = build_dispatcher(store)
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True
    assert r["event_count"] == 5
    kinds = {a["kind"] for a in r["artifacts"]}
    assert "chrome.history" in kinds


def test_query_browser_domains_rolls_up_per_host(tmp_path: Path) -> None:
    db = _chrome_history_path(tmp_path)
    store = EventStore()
    d = build_dispatcher(store)
    ingest = d.dispatch({"op": "run_triage_hive", "hive_path": str(db)})
    cid = ingest["collection_id"]

    r = d.dispatch({"op": "query_browser_domains", "collection_id": cid})
    assert r["ok"] is True
    by_host = {row["host"]: row for row in r["domains"]}
    # example.com: 1 visit (typed)
    assert by_host["example.com"]["visit_count"] == 1
    # cdn.example.com: 0 visits, 1 download (source_host)
    assert by_host["cdn.example.com"]["download_count"] == 1
    # www.google.com: 1 visit + 1 search (joined via keyword_search_terms)
    assert by_host["www.google.com"]["visit_count"] == 1
    assert by_host["www.google.com"]["search_count"] == 1


def test_browser_kind_override_forces_classification(tmp_path: Path) -> None:
    """A History file under a non-browser path should still ingest if browser_kind is forced."""
    db = tmp_path / "History"
    _build_history_db(db)
    store = EventStore()
    d = build_dispatcher(store)
    r = d.dispatch({
        "op": "run_triage_hive",
        "hive_path": str(db),
        "browser_kind": "brave",
    })
    assert r["ok"] is True
    assert r["kind"] == "brave.history"

"""Tests for the program-execution composite query."""

from __future__ import annotations

from core.events import make_event
from core.store import EventStore


def _exec(
    *,
    source: str,
    path: str | None = None,
    program_name: str | None = None,
    executable: str | None = None,
    ts: str | None = None,
    run_count: int | None = None,
    collection_id: str = "col-1",
):
    evidence = {}
    if path is not None:
        evidence["program_path"] = path
    if program_name is not None:
        evidence["program_name"] = program_name
    if executable is not None:
        evidence["executable_filename"] = executable
    if run_count is not None:
        evidence["run_count"] = run_count
    return make_event(
        host_os="windows",
        host_id="HOST",
        source_artifact=source,
        source_path="x",
        event_type="program_execution",
        summary=f"{source}: {path or program_name or executable}",
        evidence=evidence,
        collection_id=collection_id,
        parser_version="v",
        timestamp=ts,
    )


def test_composite_groups_by_lowercased_path_across_sources() -> None:
    store = EventStore()
    store.insert_events([
        _exec(source="prefetch", path=r"C:\WINDOWS\SYSTEM32\powershell.exe", ts="2026-01-01T00:00:00Z", run_count=10),
        _exec(source="registry.amcache", path=r"C:\Windows\System32\PowerShell.exe", ts="2026-02-01T00:00:00Z"),
        _exec(source="registry.system", path=r"c:\windows\system32\POWERSHELL.EXE", ts="2026-03-01T00:00:00Z"),
    ])
    rows = store.program_execution_composite()
    assert len(rows) == 1
    r = rows[0]
    assert set(r["sources"]) == {"prefetch", "registry.amcache", "registry.system"}
    assert r["first_seen"] == "2026-01-01T00:00:00Z"
    assert r["last_seen"] == "2026-03-01T00:00:00Z"
    assert r["event_count"] == 3
    assert r["total_runs"] == 10


def test_composite_falls_back_to_executable_filename_then_program_name() -> None:
    store = EventStore()
    store.insert_events([
        _exec(source="prefetch", executable="NOTEPAD.EXE", ts="2026-01-01T00:00:00Z"),
        _exec(source="registry.ntuser", program_name="notepad.exe", ts="2026-02-01T00:00:00Z"),
    ])
    rows = store.program_execution_composite()
    assert len(rows) == 1
    assert {s for s in rows[0]["sources"]} == {"prefetch", "registry.ntuser"}


def test_composite_excludes_non_program_execution_events() -> None:
    store = EventStore()
    store.insert_events([
        _exec(source="prefetch", path=r"C:\a.exe", ts="2026-01-01T00:00:00Z"),
        make_event(
            host_os="windows", host_id="H", source_artifact="evtx.security",
            source_path="x", event_type="logon", summary="logon",
            evidence={"program_path": r"C:\a.exe"}, collection_id="col-1",
            parser_version="v",
        ),
    ])
    rows = store.program_execution_composite()
    assert len(rows) == 1
    assert rows[0]["sources"] == ["prefetch"]


def test_composite_count_matches_unique_programs() -> None:
    store = EventStore()
    store.insert_events([
        _exec(source="prefetch", path=r"C:\a.exe"),
        _exec(source="registry.amcache", path=r"C:\a.exe"),
        _exec(source="prefetch", path=r"C:\b.exe"),
    ])
    assert store.program_execution_composite_count() == 2


def test_composite_scoped_to_collection() -> None:
    store = EventStore()
    store.insert_events([
        _exec(source="prefetch", path=r"C:\a.exe", collection_id="col-1"),
        _exec(source="prefetch", path=r"C:\b.exe", collection_id="col-other"),
    ])
    rows = store.program_execution_composite(collection_id="col-1")
    assert len(rows) == 1
    assert rows[0]["program_path"] == r"C:\a.exe"

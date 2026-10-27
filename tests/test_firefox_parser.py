"""Tests for the Firefox ``places.sqlite`` parser and its sidecar wiring.

A minimal synthetic ``places.sqlite`` is built with the real Firefox schema —
no real profile bytes needed. Covers visits, the annotation-based downloads,
and bookmarks.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from core.__main__ import build_dispatcher
from core.store import EventStore
from parsers.firefox import (
    _file_uri_to_path,
    _host_from_rev,
    _unix_ms_to_iso,
    _unix_us_to_iso,
    parse_firefox_history,
)

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _to_unix_us(dt: datetime) -> int:
    return int((dt.astimezone(UTC) - _UNIX_EPOCH).total_seconds() * 1_000_000)


def _to_unix_ms(dt: datetime) -> int:
    return int((dt.astimezone(UTC) - _UNIX_EPOCH).total_seconds() * 1_000)


def _build_places_db(
    path: Path, *, include_downloads: bool = True, include_bookmarks: bool = True
) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER,
                description TEXT);
            CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER,
                place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);
            CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER,
                parent INTEGER, position INTEGER, title TEXT, dateAdded INTEGER,
                lastModified INTEGER);
            CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER,
                anno_attribute_id INTEGER, content TEXT, flags INTEGER, expiration INTEGER,
                type INTEGER, dateAdded INTEGER, lastModified INTEGER);
            """
        )
        t1 = _to_unix_us(datetime(2023, 5, 1, 12, 0, 0, tzinfo=UTC))
        t2 = _to_unix_us(datetime(2023, 5, 1, 12, 1, 0, tzinfo=UTC))
        conn.executemany(
            "INSERT INTO moz_places (id, url, title, rev_host, visit_count, hidden, typed) "
            "VALUES (?,?,?,?,?,?,?)",
            [
                (
                    1,
                    "https://www.google.com/",
                    "Google",
                    "moc.elgoog.www.",
                    5,
                    0,
                    1,
                ),
                (
                    2,
                    "https://news.example.org/article",
                    "Breaking News",
                    "gro.elpmaxe.swen.",
                    2,
                    0,
                    0,
                ),
                (
                    3,
                    "https://dl.example.com/setup.exe",
                    "setup.exe",
                    "moc.elpmaxe.ld.",
                    1,
                    0,
                    0,
                ),
            ],
        )
        conn.executemany(
            "INSERT INTO moz_historyvisits "
            "(id, from_visit, place_id, visit_date, visit_type, session) "
            "VALUES (?,?,?,?,?,?)",
            [
                (10, 0, 1, t1, 2, 0),   # typed
                (11, 10, 2, t2, 1, 0),  # link, from visit 10
            ],
        )
        if include_bookmarks:
            conn.execute(
                "INSERT INTO moz_bookmarks "
                "(id, type, fk, parent, position, title, dateAdded, lastModified) "
                "VALUES (100, 1, 1, 2, 0, 'Google bookmark', ?, ?)",
                (t1, t1),
            )
            # a folder row (type 2) must be ignored
            conn.execute(
                "INSERT INTO moz_bookmarks "
                "(id, type, fk, parent, position, title, dateAdded, lastModified) "
                "VALUES (101, 2, NULL, 1, 1, 'Toolbar', ?, ?)",
                (t1, t1),
            )
        if include_downloads:
            conn.execute(
                "INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI')"
            )
            conn.execute("INSERT INTO moz_anno_attributes VALUES (2, 'downloads/metaData')")
            conn.execute(
                "INSERT INTO moz_annos VALUES (200, 3, 1, ?, 0, 0, 3, ?, ?)",
                ("file:///C:/Users/wes/Downloads/setup.exe", t1, t1),
            )
            end_ms = _to_unix_ms(datetime(2023, 5, 1, 12, 1, 0, tzinfo=UTC))
            conn.execute(
                "INSERT INTO moz_annos VALUES (201, 3, 2, ?, 0, 0, 3, ?, ?)",
                (f'{{"state":1,"endTime":{end_ms},"fileSize":204800}}', t1, t1),
            )
        conn.commit()
    finally:
        conn.close()


# ----- helper unit tests ------------------------------------------------------


def test_unix_us_to_iso_round_trips():
    dt = datetime(2023, 5, 1, 12, 0, 0, tzinfo=UTC)
    assert _unix_us_to_iso(_to_unix_us(dt)) == "2023-05-01T12:00:00Z"


def test_unix_us_and_ms_zero_or_none_returns_none():
    assert _unix_us_to_iso(0) is None
    assert _unix_us_to_iso(None) is None
    assert _unix_ms_to_iso(0) is None
    assert _unix_ms_to_iso(None) is None


def test_host_from_rev_reverses_and_strips_dot():
    assert _host_from_rev("moc.elgoog.www.") == "www.google.com"
    assert _host_from_rev("") == ""
    assert _host_from_rev(None) == ""


def test_file_uri_to_windows_path():
    path = _file_uri_to_path("file:///C:/Users/wes/Downloads/setup.exe")
    assert path == r"C:\Users\wes\Downloads\setup.exe"
    # percent-encoding is decoded
    decoded = _file_uri_to_path("file:///C:/Users/wes/My%20Docs/a.txt")
    assert decoded == r"C:\Users\wes\My Docs\a.txt"


# ----- parser end-to-end ------------------------------------------------------


def test_parse_emits_visits_downloads_bookmarks(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db)
    events = parse_firefox_history(db, collection_id="c", host_id_hint="HOST", user_hint="wes")
    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
    assert by_type["browser_visit"] == 2
    assert by_type["browser_download"] == 1
    assert by_type["browser_bookmark"] == 1  # folder row (type 2) excluded
    assert {e.source_artifact for e in events} == {"firefox.history"}
    assert all(e.user == "wes" for e in events)


def test_parse_visit_decodes_type_and_host(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db, include_downloads=False, include_bookmarks=False)
    events = parse_firefox_history(db, collection_id="c", host_id_hint="H")
    typed = next(e for e in events if e.evidence["transition"] == "typed")
    assert typed.evidence["host"] == "www.google.com"
    assert typed.timestamp == "2023-05-01T12:00:00Z"


def test_parse_download_from_annotations(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db, include_bookmarks=False)
    dl = next(
        e for e in parse_firefox_history(db, collection_id="c", host_id_hint="H")
        if e.event_type == "browser_download"
    )
    assert dl.evidence["filename"] == "setup.exe"
    assert dl.evidence["target_path"] == r"C:\Users\wes\Downloads\setup.exe"
    assert dl.evidence["source_host"] == "dl.example.com"
    assert dl.evidence["total_bytes"] == 204800
    assert dl.evidence["state"] == 1
    assert dl.evidence["end_time"] == "2023-05-01T12:01:00Z"
    assert "setup.exe" in dl.summary


def test_parse_bookmark(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db, include_downloads=False)
    bm = next(
        e for e in parse_firefox_history(db, collection_id="c", host_id_hint="H")
        if e.event_type == "browser_bookmark"
    )
    assert bm.evidence["url"] == "https://www.google.com/"
    assert bm.evidence["title"] == "Google bookmark"
    assert bm.evidence["host"] == "www.google.com"


def test_parse_tolerates_missing_annos_tables(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db, include_downloads=False, include_bookmarks=False)
    events = parse_firefox_history(db, collection_id="c", host_id_hint="H")
    assert all(e.event_type == "browser_visit" for e in events)
    assert len(events) == 2


def test_parse_reads_rows_that_exist_only_in_the_wal(tmp_path: Path):
    """A places.sqlite copied off a running Firefox arrives with a -wal holding
    the newest visits; the parser must see them without writing to the copy."""
    live = tmp_path / "live"
    live.mkdir()
    db = live / "places.sqlite"
    _build_places_db(db, include_downloads=False, include_bookmarks=False)

    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        t3 = _to_unix_us(datetime(2023, 5, 2, 9, 0, 0, tzinfo=UTC))
        conn.execute(
            "INSERT INTO moz_places (id, url, title, rev_host, visit_count, hidden, typed) "
            "VALUES (4, 'https://only-in-wal.example/', 'WAL only', "
            "'elpmaxe.law-ni-ylno.', 1, 0, 0)"
        )
        conn.execute(
            "INSERT INTO moz_historyvisits "
            "(id, from_visit, place_id, visit_date, visit_type, session) "
            "VALUES (12, 0, 4, ?, 1, 0)",
            (t3,),
        )
        conn.commit()
        # Snapshot db + wal while the writer still holds it open, as a live
        # collector would; closing would checkpoint the WAL away.
        collected = tmp_path / "collected"
        collected.mkdir()
        for name in ("places.sqlite", "places.sqlite-wal"):
            (collected / name).write_bytes((live / name).read_bytes())
    finally:
        conn.close()

    before = sorted(p.name for p in collected.iterdir())
    events = parse_firefox_history(collected / "places.sqlite", collection_id="c", host_id_hint="H")

    urls = {e.evidence["url"] for e in events}
    assert "https://only-in-wal.example/" in urls
    assert len(events) == 3
    # No -shm or other file was created beside the collected artifact.
    assert sorted(p.name for p in collected.iterdir()) == before


def test_parse_opens_paths_with_uri_special_characters(tmp_path: Path):
    profile = tmp_path / "Profiles" / "x%20y#1.default"
    profile.mkdir(parents=True)
    db = profile / "places.sqlite"
    _build_places_db(db, include_downloads=False, include_bookmarks=False)
    events = parse_firefox_history(db, collection_id="c", host_id_hint="H")
    assert len(events) == 2


# ----- sidecar wiring ---------------------------------------------------------


def test_run_triage_hive_dispatches_firefox(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db)
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(db)})
    assert r["ok"] is True
    assert r["kind"] == "firefox.history"
    assert r["by_event_type"]["browser_visit"] == 2
    assert r["by_event_type"]["browser_download"] == 1
    assert r["by_event_type"]["browser_bookmark"] == 1


def test_run_triage_directory_picks_up_firefox(tmp_path: Path):
    roaming = tmp_path / "Users" / "wes" / "AppData" / "Roaming"
    profiles = roaming / "Mozilla" / "Firefox" / "Profiles"
    prof = profiles / "abc.default-release"
    prof.mkdir(parents=True)
    _build_places_db(prof / "places.sqlite")
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True
    kinds = {a["kind"] for a in r["artifacts"]}
    assert "firefox.history" in kinds
    # user inferred from the Users/<name> path segment
    ff = next(a for a in r["artifacts"] if a["kind"] == "firefox.history")
    assert ff["user_hint"] == "wes"


def test_browser_domains_rollup_includes_firefox(tmp_path: Path):
    db = tmp_path / "places.sqlite"
    _build_places_db(db)
    d = build_dispatcher(EventStore())
    cid = d.dispatch({"op": "run_triage_hive", "hive_path": str(db)})["collection_id"]
    rows = d.dispatch({"op": "query_browser_domains", "collection_id": cid})["domains"]
    by_host = {row["host"]: row for row in rows}
    assert by_host["www.google.com"]["visit_count"] == 1
    assert by_host["dl.example.com"]["download_count"] == 1
    assert "firefox.history" in by_host["www.google.com"]["browsers"]

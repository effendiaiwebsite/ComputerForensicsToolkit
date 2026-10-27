"""Tests for the Chromium-family browser History parser.

We synthesise a minimal SQLite DB matching the columns the parser reads —
no real Chrome bytes needed. The same fixture covers Chrome, Edge, and
Brave, since they all share the schema.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from collectors.windows.browser import collect_browser_history, detect_browser_kind
from parsers.browser import (
    _decode_transition,
    _webkit_us_to_iso,
    parse_browser_history,
)

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _to_webkit_us(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = dt.astimezone(UTC) - _WEBKIT_EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _build_history_db(
    path: Path, *, include_downloads: bool = True, include_searches: bool = True
) -> None:
    """Build a tiny Chromium-shaped History DB at ``path``."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER DEFAULT 0,
                typed_count INTEGER DEFAULT 0,
                last_visit_time INTEGER DEFAULT 0,
                hidden INTEGER DEFAULT 0
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                transition INTEGER,
                segment_id INTEGER DEFAULT 0,
                visit_duration INTEGER DEFAULT 0
            );
            """,
        )
        t1 = _to_webkit_us(datetime(2026, 6, 13, 10, 15, 0, tzinfo=UTC))
        t2 = _to_webkit_us(datetime(2026, 6, 13, 10, 16, 30, tzinfo=UTC))
        t3 = _to_webkit_us(datetime(2026, 6, 13, 10, 17, 0, tzinfo=UTC))
        conn.executemany(
            "INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (1, "https://example.com/", "Example Domain", 3, 1, t3),
                (
                    2,
                    "https://www.google.com/search?q=mitre+attack",
                    "mitre attack - Google Search",
                    2,
                    0,
                    t2,
                ),
                (3, "https://attack.mitre.org/", "MITRE ATT&CK®", 1, 0, t3),
            ],
        )
        # transitions: 1 = TYPED, 0 = LINK, 0x10000000|0x20000000 = chain start+end qualifiers
        conn.executemany(
            "INSERT INTO visits (id, url, visit_time, from_visit, transition, visit_duration) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (1, 1, t1, 0, 1 | 0x10000000 | 0x20000000, 5_000_000),
                (2, 2, t2, 0, 0x9, 3_000_000),
                (3, 3, t3, 2, 0, 4_500_000),
            ],
        )

        if include_downloads:
            conn.executescript(
                """
                CREATE TABLE downloads (
                    id INTEGER PRIMARY KEY,
                    target_path TEXT,
                    current_path TEXT,
                    start_time INTEGER,
                    end_time INTEGER,
                    received_bytes INTEGER,
                    total_bytes INTEGER,
                    state INTEGER,
                    danger_type INTEGER,
                    interrupt_reason INTEGER,
                    mime_type TEXT,
                    original_mime_type TEXT,
                    referrer TEXT,
                    site_url TEXT,
                    tab_url TEXT,
                    tab_referrer_url TEXT,
                    opened INTEGER,
                    last_modified TEXT,
                    hash BLOB
                );
                CREATE TABLE downloads_url_chains (
                    id INTEGER,
                    chain_index INTEGER,
                    url TEXT
                );
                """,
            )
            d_start = _to_webkit_us(datetime(2026, 6, 13, 10, 20, 0, tzinfo=UTC))
            d_end = _to_webkit_us(datetime(2026, 6, 13, 10, 20, 12, tzinfo=UTC))
            conn.execute(
                "INSERT INTO downloads (id, target_path, current_path, start_time, end_time, "
                "received_bytes, total_bytes, state, danger_type, interrupt_reason, mime_type, "
                "original_mime_type, referrer, site_url, tab_url, tab_referrer_url, opened) "
                "VALUES (1, ?, ?, ?, ?, ?, ?, 1, 0, 0, ?, ?, ?, ?, ?, ?, 0)",
                (
                    r"C:\Users\alice\Downloads\installer.exe",
                    r"C:\Users\alice\Downloads\installer.exe",
                    d_start, d_end, 4_500_000, 4_500_000,
                    "application/x-msdownload", "application/x-msdownload",
                    "https://example.com/downloads",
                    "https://cdn.example.com/",
                    "https://example.com/downloads",
                    "https://example.com/",
                ),
            )
            conn.executemany(
                "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?, ?, ?)",
                [
                    (1, 0, "https://example.com/installer.exe"),
                    (1, 1, "https://cdn.example.com/installer.exe"),
                ],
            )

        if include_searches:
            conn.execute(
                "CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT)"
            )
            conn.execute(
                "INSERT INTO keyword_search_terms (keyword_id, url_id, term) "
                "VALUES (1, 2, 'mitre attack')",
            )
        conn.commit()
    finally:
        conn.close()


# ----- helper unit tests ------------------------------------------------------


def test_webkit_us_to_iso_round_trips():
    dt = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    us = _to_webkit_us(dt)
    iso = _webkit_us_to_iso(us)
    assert iso == "2026-06-13T12:00:00Z"


def test_webkit_us_to_iso_zero_returns_none():
    assert _webkit_us_to_iso(0) is None
    assert _webkit_us_to_iso(None) is None


def test_decode_transition_typed_with_chain_qualifiers():
    core, qualifiers = _decode_transition(1 | 0x10000000 | 0x20000000)
    assert core == "typed"
    assert "chain_start" in qualifiers
    assert "chain_end" in qualifiers


def test_decode_transition_keyword():
    core, _ = _decode_transition(0x9)
    assert core == "keyword"


# ----- collector --------------------------------------------------------------


def test_collector_detects_browser_kind_from_path():
    local = r"C:\Users\u\AppData\Local"
    assert detect_browser_kind(local + r"\Google\Chrome\User Data\Default\History") == "chrome"
    assert detect_browser_kind(local + r"\Microsoft\Edge\User Data\Default\History") == "edge"
    brave = local + r"\BraveSoftware\Brave-Browser\User Data\Default\History"
    assert detect_browser_kind(brave) == "brave"
    assert detect_browser_kind(r"C:\somewhere\else\History") == "unknown"


def test_collect_browser_history_hashes_file(tmp_path: Path):
    p = tmp_path / "History"
    p.write_bytes(b"not a real db but bytes are bytes")
    result = collect_browser_history(p, browser_kind="chrome")
    assert result.browser_kind == "chrome"
    assert result.size_bytes == len(b"not a real db but bytes are bytes")
    assert len(result.sha256) == 64


# ----- parser end-to-end ------------------------------------------------------


def test_parse_emits_visits_downloads_and_searches(tmp_path: Path):
    db = tmp_path / "History"
    _build_history_db(db)
    events = parse_browser_history(
        db,
        collection_id="col-test",
        host_id_hint="HOST",
        user_hint="alice",
        browser_kind="chrome",
    )
    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
    assert by_type["browser_visit"] == 3
    assert by_type["browser_download"] == 1
    assert by_type["browser_search"] == 1

    # All events get source_artifact derived from browser_kind.
    assert {e.source_artifact for e in events} == {"chrome.history"}
    # User propagated through.
    assert all(e.user == "alice" for e in events)


def test_parse_visit_host_and_transition(tmp_path: Path):
    db = tmp_path / "History"
    _build_history_db(db, include_downloads=False, include_searches=False)
    events = parse_browser_history(
        db, collection_id="c", host_id_hint="H", browser_kind="chrome",
    )
    visits = [e for e in events if e.event_type == "browser_visit"]
    typed = next(e for e in visits if e.evidence["transition"] == "typed")
    assert typed.evidence["host"] == "example.com"
    assert "chain_start" in typed.evidence["transition_qualifiers"]
    assert typed.evidence["visit_duration_ms"] == 5000


def test_parse_download_extracts_filename_and_chain(tmp_path: Path):
    db = tmp_path / "History"
    _build_history_db(db, include_searches=False)
    events = parse_browser_history(
        db, collection_id="c", host_id_hint="H", browser_kind="edge",
    )
    download = next(e for e in events if e.event_type == "browser_download")
    assert download.source_artifact == "edge.history"
    assert download.evidence["filename"] == "installer.exe"
    assert download.evidence["source_url"] == "https://cdn.example.com/installer.exe"
    assert download.evidence["source_host"] == "cdn.example.com"
    assert download.evidence["url_chain"] == [
        "https://example.com/installer.exe",
        "https://cdn.example.com/installer.exe",
    ]
    assert download.evidence["total_bytes"] == 4_500_000
    assert "installer.exe" in download.summary


def test_parse_search_event(tmp_path: Path):
    db = tmp_path / "History"
    _build_history_db(db)
    events = parse_browser_history(
        db, collection_id="c", host_id_hint="H", browser_kind="chrome",
    )
    search = next(e for e in events if e.event_type == "browser_search")
    assert search.evidence["term"] == "mitre attack"
    assert search.evidence["host"] == "www.google.com"


def test_parse_opens_paths_with_uri_special_characters(tmp_path: Path):
    profile = tmp_path / "Google" / "Chrome" / "User Data" / "Profile 100%#x"
    profile.mkdir(parents=True)
    db = profile / "History"
    _build_history_db(db, include_downloads=False, include_searches=False)
    events = parse_browser_history(db, collection_id="c", host_id_hint="H")
    assert len(events) == 3
    assert all(e.source_artifact == "chrome.history" for e in events)


def test_parse_reads_visits_that_exist_only_in_the_wal(tmp_path: Path):
    live = tmp_path / "live"
    live.mkdir()
    db = live / "History"
    _build_history_db(db, include_downloads=False, include_searches=False)
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        t = _to_webkit_us(datetime(2026, 6, 14, 8, 0, 0, tzinfo=UTC))
        conn.execute(
            "INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time) "
            "VALUES (4, 'https://only-in-wal.example/', 'WAL', 1, 0, ?)",
            (t,),
        )
        conn.execute(
            "INSERT INTO visits (id, url, visit_time, from_visit, transition, visit_duration) "
            "VALUES (4, 4, ?, 0, 0, 0)",
            (t,),
        )
        conn.commit()
        collected = tmp_path / "collected"
        collected.mkdir()
        for name in ("History", "History-wal"):
            (collected / name).write_bytes((live / name).read_bytes())
    finally:
        conn.close()

    events = parse_browser_history(collected / "History", collection_id="c", host_id_hint="H")
    assert "https://only-in-wal.example/" in {e.evidence["url"] for e in events}
    assert sorted(p.name for p in collected.iterdir()) == ["History", "History-wal"]


def test_parse_handles_missing_downloads_table(tmp_path: Path):
    db = tmp_path / "History"
    _build_history_db(db, include_downloads=False, include_searches=False)
    events = parse_browser_history(
        db, collection_id="c", host_id_hint="H", browser_kind="chrome",
    )
    assert all(e.event_type == "browser_visit" for e in events)
    assert len(events) == 3


def test_parse_unknown_kind_uses_unknown_source_artifact(tmp_path: Path):
    db = tmp_path / "History"
    _build_history_db(db, include_downloads=False, include_searches=False)
    events = parse_browser_history(db, collection_id="c", host_id_hint="H")
    # No path markers in tmp_path → detect_browser_kind returns "unknown".
    assert {e.source_artifact for e in events} == {"unknown.history"}

"""Tests for the IE/legacy-Edge ``WebCacheV01.dat`` parser.

The ESE database format has no Python *writer*, so we mock the
``dissect.database.ese`` layer with fakes that mirror the real
``ESE``/``Table``/``Record`` API (``.tables()``, ``.table(name)``,
``.records()``, ``record.get(key)``) — the same shape dissect's own
``iexplore.py`` plugin consumes. The parser opens a real (dummy) file handle,
so the on-disk bytes are irrelevant; only the mocked DB matters.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest

from core.__main__ import build_dispatcher
from core.store import EventStore
from parsers.ie_webcache import parse_ie_webcache

_FILETIME_EPOCH_DELTA = 11_644_473_600  # seconds between 1601 and 1970


def _to_filetime(dt: datetime) -> int:
    unix = (dt.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)).total_seconds()
    return int((unix + _FILETIME_EPOCH_DELTA) * 10_000_000)


# ----- fakes mirroring dissect.database.ese ----------------------------------


class _FakeRecord:
    def __init__(self, fields: dict) -> None:
        self._f = fields

    def get(self, key, default=None):
        return self._f.get(key, default)


class _FakeTable:
    def __init__(self, name: str, records: list[dict]) -> None:
        self.name = name
        self._records = [_FakeRecord(r) for r in records]

    def records(self):
        return list(self._records)


class _FakeESE:
    """Constructed as ``ESE(fh)``; ignores fh, serves canned tables."""

    _TABLES: ClassVar[dict[str, list[dict]]] = {}

    def __init__(self, fh) -> None:
        self._tables = {name: _FakeTable(name, recs) for name, recs in self._TABLES.items()}

    def tables(self):
        return list(self._tables.values())

    def table(self, name: str):
        return self._tables[name]


def _make_fake_ese(tables: dict[str, list[dict]]):
    return type("_FakeESE", (_FakeESE,), {"_TABLES": tables})


_T1 = _to_filetime(datetime(2023, 5, 1, 12, 0, 0, tzinfo=UTC))
_T2 = _to_filetime(datetime(2023, 5, 1, 12, 5, 0, tzinfo=UTC))

# ResponseHeaders blob: split('\x00')[-3:-1] => (url, path)
_RESP_HEADERS = "\x00".join(
    [
        "HTTP/1.1 200 OK",
        "Content-Type: application/octet-stream",
        "https://dl.example.com/tool.exe",
        r"C:\Users\wes\Downloads\tool.exe",
        "",
    ]
).encode("utf-16-le")

_WEBCACHE_TABLES = {
    "Containers": [
        {"Name": "History\x00", "ContainerId": 1},
        {"Name": "iedownload", "ContainerId": 2},
        {"Name": "Cookies", "ContainerId": 3},
    ],
    "Container_1": [
        {
            "Url": "Visited: wes@https://www.example.com/",
            "AccessedTime": _T1,
            "AccessCount": 4,
            "EntryId": 10,
        },
        {
            "Url": "Visited: wes@https://attack.mitre.org/",
            "AccessedTime": _T2,
            "AccessCount": 1,
            "EntryId": 11,
        },
        {"Url": "", "AccessedTime": _T1, "AccessCount": 0, "EntryId": 12},  # empty → skipped
    ],
    "Container_2": [
        {"ResponseHeaders": _RESP_HEADERS, "AccessedTime": _T2, "EntryId": 20},
    ],
    "Container_3": [
        {"Url": "cookie-junk", "AccessedTime": _T1},  # never read (Cookies not handled)
    ],
}


@pytest.fixture
def webcache_file(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setattr("dissect.database.ese.ESE", _make_fake_ese(_WEBCACHE_TABLES))
    p = tmp_path / "WebCacheV01.dat"
    p.write_bytes(b"dummy-ese-bytes")
    return p


# ----- helper unit tests ------------------------------------------------------


def test_to_filetime_decodes_back_via_wintimestamp():
    from dissect.util.ts import wintimestamp

    dt = datetime(2023, 5, 1, 12, 0, 0, tzinfo=UTC)
    assert wintimestamp(_to_filetime(dt)).replace(microsecond=0) == dt


# ----- parser end-to-end ------------------------------------------------------


def test_parse_emits_visits_and_downloads(webcache_file: Path):
    events = parse_ie_webcache(
        webcache_file, collection_id="c", host_id_hint="HOST", user_hint="wes"
    )
    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
    assert by_type["browser_visit"] == 2  # empty-Url row skipped
    assert by_type["browser_download"] == 1
    assert {e.source_artifact for e in events} == {"ie.webcache"}
    assert all(e.user == "wes" for e in events)


def test_visit_strips_visited_prefix_and_decodes_time(webcache_file: Path):
    events = parse_ie_webcache(webcache_file, collection_id="c", host_id_hint="H")
    visit = next(e for e in events if e.evidence.get("url") == "https://www.example.com/")
    assert visit.evidence["host"] == "www.example.com"
    assert visit.evidence["visit_count"] == 4
    assert visit.timestamp == "2023-05-01T12:00:00Z"


def test_download_parses_response_headers(webcache_file: Path):
    events = parse_ie_webcache(webcache_file, collection_id="c", host_id_hint="H")
    dl = next(e for e in events if e.event_type == "browser_download")
    assert dl.evidence["source_url"] == "https://dl.example.com/tool.exe"
    assert dl.evidence["target_path"] == r"C:\Users\wes\Downloads\tool.exe"
    assert dl.evidence["filename"] == "tool.exe"
    assert dl.evidence["source_host"] == "dl.example.com"
    assert dl.timestamp == "2023-05-01T12:05:00Z"


def test_parse_returns_empty_on_unparsable_db(tmp_path: Path, monkeypatch):
    def _boom(_fh):
        raise ValueError("dirty shutdown")

    monkeypatch.setattr("dissect.database.ese.ESE", _boom)
    p = tmp_path / "WebCacheV01.dat"
    p.write_bytes(b"garbage")
    assert parse_ie_webcache(p, collection_id="c", host_id_hint="H") == []


def test_bad_timestamp_row_does_not_abort_the_file(tmp_path: Path, monkeypatch):
    """dissect may hand back an already-decoded datetime, and a corrupt value
    raises TypeError inside wintimestamp; either way only that row's time is lost."""
    decoded = datetime(2023, 5, 1, 12, 0, 0, tzinfo=UTC)
    tables = {
        "Containers": [{"Name": "History", "ContainerId": 1}],
        "Container_1": [
            {"Url": "Visited: wes@https://a.example/", "AccessedTime": decoded, "EntryId": 1},
            {"Url": "Visited: wes@https://b.example/", "AccessedTime": "garbage", "EntryId": 2},
            {"Url": "Visited: wes@https://c.example/", "AccessedTime": _T1, "EntryId": 3},
        ],
    }
    monkeypatch.setattr("dissect.database.ese.ESE", _make_fake_ese(tables))
    p = tmp_path / "WebCacheV01.dat"
    p.write_bytes(b"x")

    events = parse_ie_webcache(p, collection_id="c", host_id_hint="H")

    by_url = {e.evidence["url"]: e for e in events}
    assert set(by_url) == {"https://a.example/", "https://b.example/", "https://c.example/"}
    assert by_url["https://a.example/"].timestamp == "2023-05-01T12:00:00Z"
    assert by_url["https://b.example/"].timestamp is None
    assert by_url["https://c.example/"].timestamp == "2023-05-01T12:00:00Z"


def test_parse_tolerates_missing_containers_table(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("dissect.database.ese.ESE", _make_fake_ese({"SomethingElse": []}))
    p = tmp_path / "WebCacheV01.dat"
    p.write_bytes(b"x")
    assert parse_ie_webcache(p, collection_id="c", host_id_hint="H") == []


# ----- sidecar wiring ---------------------------------------------------------


def test_run_triage_hive_dispatches_webcache(webcache_file: Path):
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(webcache_file)})
    assert r["ok"] is True
    assert r["kind"] == "ie.webcache"
    assert r["by_event_type"]["browser_visit"] == 2
    assert r["by_event_type"]["browser_download"] == 1


def test_run_triage_directory_picks_up_webcache(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("dissect.database.ese.ESE", _make_fake_ese(_WEBCACHE_TABLES))
    wc_dir = tmp_path / "Users" / "wes" / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache"
    wc_dir.mkdir(parents=True)
    (wc_dir / "WebCacheV01.dat").write_bytes(b"dummy")
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True
    wc = next(a for a in r["artifacts"] if a["kind"] == "ie.webcache")
    assert wc["user_hint"] == "wes"
    assert wc["event_count"] == 3

"""Tests for the legacy IE ``index.dat`` (MSIE Cache File) parser.

``pymsiecf`` is a native C-extension over a binary format with no Python
writer, so — like the prefetch (pyscca) and LNK (LnkParse3) parser tests — we
mock the library with fakes mirroring its API (``file.open``,
``number_of_items``, ``get_item``, and ``url`` items with ``location`` /
``primary_time`` / ``number_of_hits``). The parser was additionally verified
end-to-end against the real ``History.IE5\\index.dat`` from the Mantooth image
(27 history events).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.__main__ import build_dispatcher
from core.store import EventStore
from parsers.ie_index_dat import parse_ie_index_dat

# ----- fakes mirroring pymsiecf ----------------------------------------------


# Class names are lowercase to mirror pymsiecf's own ``url``/``leak`` classes —
# the parser dispatches on ``type(item).__name__``.
class url:  # noqa: N801
    def __init__(self, **kw) -> None:
        self.location = kw.get("location")
        self.type = kw.get("type", "history")
        self.primary_time = kw.get("primary_time")
        self.secondary_time = kw.get("secondary_time")
        self.last_checked_time = kw.get("last_checked_time")
        self.number_of_hits = kw.get("number_of_hits", 1)
        self.filename = kw.get("filename")
        self.cached_file_size = kw.get("cached_file_size", 0)
        self.offset = kw.get("offset", 0)


class leak:  # noqa: N801 — a non-url item class that must be skipped
    location = "leaked"


class _FakeFile:
    def __init__(self, items: list, *, raise_on_open: bool = False) -> None:
        self._items = items
        self._raise = raise_on_open

    def open(self, _path: str) -> None:
        if self._raise:
            raise OSError("invalid file signature")

    @property
    def number_of_items(self) -> int:
        return len(self._items)

    def get_item(self, i: int):
        return self._items[i]

    def close(self) -> None:
        pass


def _install_fake(monkeypatch, items: list, *, raise_on_open: bool = False) -> None:
    import sys
    import types

    fake = types.ModuleType("pymsiecf")
    fake.file = lambda: _FakeFile(items, raise_on_open=raise_on_open)
    monkeypatch.setitem(sys.modules, "pymsiecf", fake)


_ITEMS = [
    url(
        location="Visited: Wes Mantooth@http://www.snopes.com/crime/warnings/atmcamera.asp",
        type="history",
        primary_time=datetime(2007, 7, 12, 23, 13, 16),
        secondary_time=datetime(2007, 7, 12, 23, 13, 16),
        number_of_hits=3,
    ),
    url(
        location="Visited: Wes Mantooth@http://www.google.com",
        type="history",
        primary_time=datetime(2007, 7, 12, 23, 12, 16),
        number_of_hits=1,
    ),
    url(location="", type="history"),          # empty location → skipped
    leak(),                                      # non-url class → skipped
]


# ----- parser end-to-end ------------------------------------------------------


def test_parse_emits_visits_from_url_items(tmp_path: Path, monkeypatch):
    _install_fake(monkeypatch, _ITEMS)
    p = tmp_path / "index.dat"
    p.write_bytes(b"Client UrlCache MMF Ver 5.2")
    events = parse_ie_index_dat(p, collection_id="c", host_id_hint="HOST", user_hint="Wes Mantooth")
    assert len(events) == 2  # empty + leak skipped
    assert {e.event_type for e in events} == {"browser_visit"}
    assert {e.source_artifact for e in events} == {"ie.index_dat"}
    assert all(e.user == "Wes Mantooth" for e in events)


def test_visit_strips_visited_prefix_and_decodes_time(tmp_path: Path, monkeypatch):
    _install_fake(monkeypatch, _ITEMS)
    p = tmp_path / "index.dat"
    p.write_bytes(b"x")
    events = parse_ie_index_dat(p, collection_id="c", host_id_hint="H")
    snopes = next(e for e in events if "snopes" in e.evidence["url"])
    assert snopes.evidence["url"] == "http://www.snopes.com/crime/warnings/atmcamera.asp"
    assert snopes.evidence["host"] == "www.snopes.com"
    assert snopes.evidence["record_kind"] == "history"
    assert snopes.evidence["visit_count"] == 3
    assert snopes.timestamp == "2007-07-12T23:13:16Z"


def test_open_failure_returns_empty(tmp_path: Path, monkeypatch):
    _install_fake(monkeypatch, [], raise_on_open=True)
    p = tmp_path / "index.dat"
    p.write_bytes(b"not an index.dat")
    assert parse_ie_index_dat(p, collection_id="c", host_id_hint="H") == []


# ----- sidecar wiring ---------------------------------------------------------


def test_run_triage_hive_dispatches_index_dat(tmp_path: Path, monkeypatch):
    _install_fake(monkeypatch, _ITEMS)
    p = tmp_path / "index.dat"
    p.write_bytes(b"x")
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(p)})
    assert r["ok"] is True
    assert r["kind"] == "ie.index_dat"
    assert r["by_event_type"]["browser_visit"] == 2


def test_run_triage_directory_picks_up_index_dat(tmp_path: Path, monkeypatch):
    _install_fake(monkeypatch, _ITEMS)
    hist = (
        tmp_path / "Users" / "Wes Mantooth" / "AppData" / "Local" / "Microsoft"
        / "Windows" / "History" / "History.IE5"
    )
    hist.mkdir(parents=True)
    (hist / "index.dat").write_bytes(b"x")
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True
    ix = next(a for a in r["artifacts"] if a["kind"] == "ie.index_dat")
    assert ix["user_hint"] == "Wes Mantooth"
    assert ix["event_count"] == 2

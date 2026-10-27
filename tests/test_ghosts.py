"""Ghost-reference pass tests (core/ghosts.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.events import Event, make_event
from core.ghosts import (
    annotate_missing_references,
    directory_exists_fn,
    image_root_exists_fn,
    is_checkable_path,
    referenced_path,
)
from core.store import EventStore

CID = "col-ghost"


def _ev(event_type: str, evidence: dict[str, Any], *, source: str = "lnk") -> Event:
    return make_event(
        host_os="windows", host_id="H", source_artifact=source, source_path="/p",
        event_type=event_type, summary=event_type, evidence=evidence, collection_id=CID,
        parser_version="t",
    )


def _store(*events: Event) -> EventStore:
    store = EventStore()
    store.register_collection(CID, "H", "windows", "2026-01-01T00:00:00Z")
    store.insert_events(events)
    return store


def test_annotates_checkable_paths_and_skips_unknown_verdicts() -> None:
    present = _ev("file_access", {"target_path": r"C:\Users\a\keep.docx"})
    missing = _ev("program_execution", {"program_path": r"C:\Temp\dropper.exe"},
                  source="prefetch")
    unc = _ev("file_access", {"target_path": r"\\server\share\x.docx"})
    other_drive = _ev("file_access", {"target_path": r"E:\usb\x.docx"})
    no_path = _ev("program_execution", {"executable_filename": "CMD.EXE"}, source="prefetch")
    unrelated = _ev("file_delete", {"original_path": r"C:\gone.txt"}, source="recycle_bin")
    store = _store(present, missing, unc, other_drive, no_path, unrelated)

    seen: list[str] = []

    def exists(p: str) -> bool | None:
        seen.append(p)
        if p.startswith("E:"):
            return None
        return "keep" in p

    assert annotate_missing_references(store, CID, exists) == 2
    assert store.get_event(present.event_id)["evidence"]["referenced_path_exists"] is True
    assert store.get_event(missing.event_id)["evidence"]["referenced_path_exists"] is False
    assert store.get_event(missing.event_id)["evidence"]["program_path"] == r"C:\Temp\dropper.exe"
    for e in (unc, other_drive, no_path, unrelated):
        assert "referenced_path_exists" not in store.get_event(e.event_id)["evidence"]
    assert r"\\server\share\x.docx" not in seen


def test_no_root_means_no_annotation_and_bound_is_honoured() -> None:
    events = [_ev("file_access", {"target_path": rf"C:\f{i}.txt"}) for i in range(5)]
    store = _store(*events)
    assert annotate_missing_references(store, CID, None) == 0
    assert annotate_missing_references(store, CID, lambda _p: False, max_events=2) == 2


def test_exists_callable_exceptions_are_swallowed() -> None:
    store = _store(_ev("file_access", {"target_path": r"C:\x.txt"}))

    def boom(_p: str) -> bool:
        raise RuntimeError("fs gone")

    assert annotate_missing_references(store, CID, boom) == 0


def test_referenced_path_and_checkable_rules() -> None:
    assert referenced_path({"event_type": "file_access",
                            "evidence": {"target_path": r"C:\a\b.txt"}}) == r"C:\a\b.txt"
    assert referenced_path({"event_type": "program_execution",
                            "evidence": {"program_path": r"d:\x.exe"}}) == r"d:\x.exe"
    assert referenced_path({"event_type": "file_access", "evidence": {}}) is None
    assert referenced_path({"event_type": "browser_visit",
                            "evidence": {"target_path": r"C:\a"}}) is None
    assert is_checkable_path(r"C:\Windows\explorer.exe")
    assert not is_checkable_path(r"\\host\share\f.txt")
    assert not is_checkable_path(r"\Device\HarddiskVolume2\f.txt")
    assert not is_checkable_path(r"%SystemRoot%\f.txt")
    assert not is_checkable_path(r"C:\Temp\*.log")
    assert not is_checkable_path("relative\\path.txt")


def _full_mirror(root: Path) -> None:
    (root / "Windows" / "System32").mkdir(parents=True)
    (root / "Windows" / "explorer.exe").write_bytes(b"MZ")
    (root / "Users" / "Alice" / "Desktop").mkdir(parents=True)
    (root / "Users" / "Alice" / "Desktop" / "Report.docx").write_bytes(b"x")


def test_directory_exists_fn_requires_a_full_mirror(tmp_path: Path) -> None:
    assert directory_exists_fn(tmp_path / "nope") is None
    sparse = tmp_path / "sparse"
    (sparse / "Windows" / "System32" / "config").mkdir(parents=True)
    (sparse / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    assert directory_exists_fn(sparse) is None


def test_directory_exists_fn_matches_case_insensitively(tmp_path: Path) -> None:
    _full_mirror(tmp_path)
    exists = directory_exists_fn(tmp_path)
    assert exists is not None
    assert exists(r"C:\users\ALICE\desktop\report.DOCX") is True
    assert exists(r"C:\Users\Alice\Desktop\gone.docx") is False
    assert exists(r"C:\Windows\System32\cmd.exe") is False
    assert exists(r"C:\Users\Bob\Desktop\x.docx") is None  # parent folder absent
    assert exists(r"D:\Users\Alice\Desktop\Report.docx") is None
    assert exists("C:\\") is True


class _FakeNode:
    def __init__(self, present: set[str], posix: str) -> None:
        self._present, self._posix = present, posix

    def exists(self) -> bool:
        if self._posix == "/boom":
            raise OSError("bad sector")
        return self._posix in self._present


class _FakeRoot:
    def __init__(self, present: set[str]) -> None:
        self.present = present
        self.asked: list[str] = []

    def path(self, posix: str) -> _FakeNode:
        self.asked.append(posix)
        return _FakeNode(self.present, posix)


def test_image_root_exists_fn_translates_windows_paths() -> None:
    root = _FakeRoot({"/Users/alice/a.txt", "/Windows/System32/cmd.exe"})
    exists = image_root_exists_fn(root)
    assert exists(r"C:\Users\alice\a.txt") is True
    assert exists(r"c:\Windows\System32\cmd.exe") is True
    assert exists(r"C:\Users\alice\b.txt") is False
    assert exists(r"D:\Users\alice\a.txt") is None
    assert exists(r"C:\boom") is None
    assert root.asked[0] == "/Users/alice/a.txt"

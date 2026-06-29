"""Tests for the image browser (directory-mode + export)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from core.audit import AuditLog
from core.image_browser import ImageBrowser, _entry_hidden, export_folder
from core.progress import ProgressTracker


class _SI:
    def __init__(self, file_attributes: int):
        self.file_attributes = file_attributes


class _Attrs:
    def __init__(self, file_attributes: int):
        self._fa = file_attributes

    def get(self, _code):
        return _SI(self._fa)


class _Child:
    """Mimics a dissect TargetPath enough for _entry_hidden's NTFS path:
    child.get().entry.attributes.get(STANDARD_INFORMATION).file_attributes."""

    def __init__(self, file_attributes: int):
        self._fa = file_attributes

    def get(self):
        entry = type("E", (), {"attributes": _Attrs(self._fa)})()
        return type("FsEntry", (), {"entry": entry})()


def test_entry_hidden_reads_ntfs_attribute_bit():
    # 0x26 = HIDDEN|SYSTEM|ARCHIVE (e.g. desktop.ini); 0x20 = ARCHIVE only.
    assert _entry_hidden(_Child(0x26), "desktop.ini") is True
    assert _entry_hidden(_Child(0x20), "photo.gif") is False


def test_entry_hidden_falls_back_to_name_when_not_ntfs():
    class _NoGet:
        def get(self):
            raise AttributeError("not an ntfs entry")

    assert _entry_hidden(_NoGet(), ".bashrc") is True
    assert _entry_hidden(_NoGet(), "report.txt") is False


def _seed_tree(root: Path) -> None:
    (root / "Users" / "alice" / "Documents").mkdir(parents=True)
    # write_bytes to avoid Windows \n -> \r\n translation in size assertions
    (root / "Users" / "alice" / "Documents" / "note.txt").write_bytes(b"hello\n")
    (root / "Users" / "alice" / "Documents" / "secret.pdf").write_bytes(b"\x25PDF-1.4\n" + b"x" * 1024)
    (root / "Users" / "alice" / ".bashrc").write_bytes(b"export PATH=...\n")
    (root / "Users" / "Public").mkdir(parents=True)
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"hivebytes")


def test_list_root_returns_top_level_dirs(tmp_path: Path) -> None:
    _seed_tree(tmp_path)
    browser = ImageBrowser()
    result = browser.list_dir(collection_id="c", path="/", source_path=str(tmp_path))
    names = {e.name for e in result.entries}
    assert names == {"Users", "Windows"}
    assert all(e.kind == "dir" for e in result.entries)
    assert result.source_kind == "directory"


def test_list_nested_path_returns_files_with_sizes(tmp_path: Path) -> None:
    _seed_tree(tmp_path)
    browser = ImageBrowser()
    result = browser.list_dir(
        collection_id="c",
        path="/Users/alice/Documents",
        source_path=str(tmp_path),
    )
    by_name = {e.name: e for e in result.entries}
    assert by_name["note.txt"].size == len("hello\n")
    assert by_name["secret.pdf"].size == 9 + 1024
    assert by_name["note.txt"].kind == "file"


def test_hidden_dotfile_flagged(tmp_path: Path) -> None:
    _seed_tree(tmp_path)
    browser = ImageBrowser()
    result = browser.list_dir(
        collection_id="c", path="/Users/alice", source_path=str(tmp_path),
    )
    by_name = {e.name: e for e in result.entries}
    assert by_name[".bashrc"].hidden is True
    assert by_name["Documents"].hidden is False


def test_path_escape_blocked(tmp_path: Path) -> None:
    _seed_tree(tmp_path)
    browser = ImageBrowser()
    with pytest.raises(PermissionError):
        browser.list_dir(
            collection_id="c",
            path="/../../etc/passwd",
            source_path=str(tmp_path),
        )


def test_missing_path_raises(tmp_path: Path) -> None:
    _seed_tree(tmp_path)
    browser = ImageBrowser()
    with pytest.raises(FileNotFoundError):
        browser.list_dir(
            collection_id="c", path="/nope", source_path=str(tmp_path),
        )


def test_export_folder_round_trip(tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    dest_root = tmp_path / "dest"
    src_root.mkdir()
    dest_root.mkdir()
    _seed_tree(src_root)

    browser = ImageBrowser()
    audit = AuditLog(dest_root / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("k", label="t", total=0)

    result = export_folder(
        browser,
        collection_id="c",
        src_path="/Users/alice/Documents",
        dest_dir=dest_root,
        source_path=str(src_root),
        audit=audit,
        progress=progress,
        progress_key="k",
    )

    assert result.files_copied == 2
    assert result.errors == 0
    assert (dest_root / "note.txt").exists()
    assert (dest_root / "secret.pdf").exists()

    # Audit hashes must match the destination bytes.
    records = audit.read_all()
    ok_records = [r for r in records if r["status"] == "ok"]
    assert len(ok_records) == 2
    for r in ok_records:
        dest_bytes = (dest_root / r["dest_path"]).read_bytes()
        assert hashlib.sha256(dest_bytes).hexdigest() == r["sha256"]

    snap = progress.get("k")
    assert snap.completed == snap.total == 2


def test_hash_report_text_and_csv(tmp_path: Path) -> None:
    from core.audit import generate_hash_report

    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.ok("copy", "/src/a", "a", "h1" * 32, 100, category="x")
    audit.ok("copy", "/src/b", "b", "h2" * 32, 250, category="x")
    audit.skipped("copy", "/src/c", "missing")
    audit.error("copy", "/src/d", RuntimeError("locked"))

    txt = tmp_path / "report.txt"
    rows, size = generate_hash_report(tmp_path / "audit.jsonl", txt, format="txt")
    assert rows == 2
    body = txt.read_text(encoding="utf-8")
    assert "Records: 2" in body
    assert "h1" * 32 in body
    assert "h2" * 32 in body
    # Skipped + error records must NOT appear.
    assert "missing" not in body
    assert "locked" not in body

    csv = tmp_path / "report.csv"
    rows2, _ = generate_hash_report(tmp_path / "audit.jsonl", csv, format="csv")
    assert rows2 == 2
    lines = csv.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("sha256,size_bytes,")
    assert len(lines) == 1 + 2  # header + 2 rows


def test_get_collection_returns_source_path(tmp_path: Path) -> None:
    """Regression: list_dir relies on get_collection returning source_path."""
    from core.store import EventStore

    store = EventStore()
    store.register_collection(
        collection_id="c1",
        host_id="H",
        host_os="windows",
        created_at="2026-06-28T12:00:00Z",
        note="live: /tmp/x.E01 → /tmp/dest",
        source_path="/tmp/x.E01",
    )
    coll = store.get_collection("c1")
    assert coll is not None
    assert coll["source_path"] == "/tmp/x.E01"


def test_export_events_csv_and_ndjson(tmp_path: Path) -> None:
    from core.__main__ import build_dispatcher
    from core.events import make_event
    from core.store import EventStore

    store = EventStore()
    store.insert_events([
        make_event(
            host_os="windows", host_id="H", source_artifact="prefetch",
            source_path="p", event_type="program_execution",
            summary=f"Prefetch run {i}", evidence={"i": i}, collection_id="c",
            parser_version="v", timestamp=f"2026-06-13T12:00:0{i}Z",
        )
        for i in range(3)
    ])
    d = build_dispatcher(store)

    csv_out = tmp_path / "e.csv"
    r = d.dispatch({
        "op": "export_events",
        "collection_id": "c",
        "output_path": str(csv_out),
        "format": "csv",
    })
    assert r["ok"] is True
    assert r["rows"] == 3
    lines = csv_out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("event_id,timestamp,")
    assert len(lines) == 4
    assert all("program_execution" in line for line in lines[1:])

    ndjson_out = tmp_path / "e.ndjson"
    r2 = d.dispatch({
        "op": "export_events",
        "collection_id": "c",
        "output_path": str(ndjson_out),
        "format": "ndjson",
    })
    assert r2["ok"] is True
    objs = [json.loads(line) for line in ndjson_out.read_text("utf-8").splitlines() if line]
    assert len(objs) == 3
    assert all(o["event_type"] == "program_execution" for o in objs)
    assert objs[0]["evidence"]["i"] == 0

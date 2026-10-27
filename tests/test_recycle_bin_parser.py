"""Tests for the Recycle Bin ``$I`` parser.

``$I`` is a tiny well-defined binary record, so we build both on-disk formats
synthetically. The parser was additionally verified end-to-end against the real
``$Recycle.Bin`` from the Mantooth image (9 deleted-file records, incl.
``CameraShy.exe`` and ``ValidateCreditCard.zip``).
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from core.__main__ import build_dispatcher
from core.store import EventStore
from parsers.recycle_bin import _filetime_to_iso, parse_recycle_bin

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _to_filetime(dt: datetime) -> int:
    return int((dt.astimezone(UTC) - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def _build_i_v1(path: str, size: int, dt: datetime) -> bytes:
    head = struct.pack("<qqq", 1, size, _to_filetime(dt))
    raw = (path + "\x00").encode("utf-16-le")
    raw = raw[:520].ljust(520, b"\x00")  # fixed 520-byte path field
    return head + raw


def _build_i_v2(path: str, size: int, dt: datetime) -> bytes:
    head = struct.pack("<qqq", 2, size, _to_filetime(dt))
    chars = len(path) + 1
    raw = (path + "\x00").encode("utf-16-le")
    return head + struct.pack("<I", chars) + raw


# ----- helper unit tests ------------------------------------------------------


def test_filetime_to_iso():
    dt = datetime(2007, 7, 14, 17, 55, 57, tzinfo=UTC)
    assert _filetime_to_iso(_to_filetime(dt)) == "2007-07-14T17:55:57Z"
    assert _filetime_to_iso(0) is None
    assert _filetime_to_iso(-1) is None


# ----- parser end-to-end ------------------------------------------------------


def test_parse_v1_record(tmp_path: Path):
    sid_dir = tmp_path / "$Recycle.Bin" / "S-1-5-21-3166329-3263506726-1320359247-1000"
    sid_dir.mkdir(parents=True)
    p = sid_dir / "$I61QDFF.exe"
    p.write_bytes(_build_i_v1(r"C:\Users\Wes Mantooth\Documents\CameraShy.exe", 1358848,
                              datetime(2007, 7, 14, 17, 55, 57, tzinfo=UTC)))
    events = parse_recycle_bin(p, collection_id="c", host_id_hint="HOST", user_hint="Wes Mantooth")
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "file_delete"
    assert ev.source_artifact == "recycle_bin"
    assert ev.evidence["original_path"] == r"C:\Users\Wes Mantooth\Documents\CameraShy.exe"
    assert ev.evidence["deleted_name"] == "CameraShy.exe"
    assert ev.evidence["deleted_size"] == 1358848
    assert ev.evidence["recovered_name"] == "$R61QDFF.exe"
    assert ev.evidence["sid"] == "S-1-5-21-3166329-3263506726-1320359247-1000"
    assert ev.evidence["format_version"] == 1
    assert ev.timestamp == "2007-07-14T17:55:57Z"
    assert ev.user == "Wes Mantooth"
    assert "CameraShy.exe" in ev.summary
    # Shared file_delete contract (docs/DELETIONS.md): the bin folder's SID is
    # both owner and actor; no $R sibling on disk -> recoverability unknown.
    assert ev.evidence["deletion_method"] == "recycle_bin"
    assert ev.evidence["owner_sid"] == ev.evidence["sid"]
    assert ev.evidence["actor_sid"] == ev.evidence["sid"]
    assert ev.evidence["is_directory"] is False
    assert ev.evidence["recoverable_hint"] == "unknown"
    for key in ("security_id", "mft_segment", "usn", "usn_reason",
                "last_known_modified", "last_known_created"):
        assert ev.evidence[key] is None, key


def test_r_sibling_marks_blob_recoverable(tmp_path: Path):
    sid_dir = tmp_path / "$Recycle.Bin" / "S-1-5-21-1-2-3-1000"
    sid_dir.mkdir(parents=True)
    i_file = sid_dir / "$IQWE123.txt"
    i_file.write_bytes(_build_i_v2(r"C:\Users\a\x.txt", 3, datetime(2021, 1, 1, tzinfo=UTC)))
    (sid_dir / "$RQWE123.txt").write_bytes(b"abc")
    ev = parse_recycle_bin(i_file, collection_id="c", host_id_hint="H")[0]
    assert ev.evidence["recoverable_hint"] == "recycle_bin_blob"
    assert ev.evidence["recovered_name"] == "$RQWE123.txt"
    assert ev.evidence["is_directory"] is False


def test_r_sibling_directory_marks_is_directory(tmp_path: Path):
    i_file = tmp_path / "$IDIR001"
    i_file.write_bytes(_build_i_v2(r"C:\Users\a\folder", 0, datetime(2021, 1, 1, tzinfo=UTC)))
    (tmp_path / "$RDIR001").mkdir()
    ev = parse_recycle_bin(i_file, collection_id="c", host_id_hint="H")[0]
    assert ev.evidence["recoverable_hint"] == "recycle_bin_blob"
    assert ev.evidence["is_directory"] is True


def test_parse_v2_record(tmp_path: Path):
    p = tmp_path / "$IABC123.zip"
    p.write_bytes(_build_i_v2(r"D:\loot\ValidateCreditCard.zip", 409724,
                              datetime(2021, 3, 2, 8, 0, 0, tzinfo=UTC)))
    ev = parse_recycle_bin(p, collection_id="c", host_id_hint="H")[0]
    assert ev.evidence["format_version"] == 2
    assert ev.evidence["original_path"] == r"D:\loot\ValidateCreditCard.zip"
    assert ev.evidence["deleted_name"] == "ValidateCreditCard.zip"
    assert ev.evidence["deleted_size"] == 409724
    assert ev.timestamp == "2021-03-02T08:00:00Z"


def test_parse_rejects_non_i_record(tmp_path: Path):
    # $I30 is the NTFS index attribute, not a Recycle Bin record.
    p = tmp_path / "$I30"
    p.write_bytes(b"\x00" * 64)
    assert parse_recycle_bin(p, collection_id="c", host_id_hint="H") == []


# ----- sidecar wiring ---------------------------------------------------------


def test_run_triage_hive_dispatches_recycle_bin(tmp_path: Path):
    p = tmp_path / "$IXYZ789.exe"
    p.write_bytes(_build_i_v1(r"C:\tmp\evil.exe", 1024, datetime(2007, 7, 1, tzinfo=UTC)))
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(p)})
    assert r["ok"] is True
    assert r["kind"] == "recycle_bin"
    assert r["by_event_type"]["file_delete"] == 1


def test_run_triage_directory_picks_up_recycle_bin(tmp_path: Path):
    sid = tmp_path / "$Recycle.Bin" / "S-1-5-21-1-2-3-1000"
    sid.mkdir(parents=True)
    (sid / "$IAAA111.exe").write_bytes(
        _build_i_v1(r"C:\a\one.exe", 10, datetime(2007, 7, 1, tzinfo=UTC)))
    (sid / "$IBBB222.zip").write_bytes(
        _build_i_v1(r"C:\b\two.zip", 20, datetime(2007, 7, 2, tzinfo=UTC)))
    (sid / "$I30").write_bytes(b"\x00" * 64)  # must be ignored
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True
    rb = [a for a in r["artifacts"] if a["kind"] == "recycle_bin"]
    assert len(rb) == 2  # $I30 excluded by discovery
    assert r["by_event_type"]["file_delete"] == 2

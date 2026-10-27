"""Sidecar ops for the Deleted files view, driven through the dispatcher
exactly as the Tauri shell drives them."""

from __future__ import annotations

import struct
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from core.__main__ import build_dispatcher
from core.events import Event, make_event
from core.store import EventStore

CID = "col-ops"
ALICE_SID = "S-1-5-21-1-2-3-1001"


def _ev(event_type: str, evidence: dict[str, Any], *, source: str, ts: str | None = None,
        cid: str = CID) -> Event:
    return make_event(
        host_os="windows", host_id="H", source_artifact=source, source_path="/p",
        event_type=event_type, summary=event_type, evidence=evidence, collection_id=cid,
        parser_version="t", timestamp=ts,
    )


def _delete(method: str, path: str, ts: str, **extra: Any) -> Event:
    evidence = {
        "original_path": path, "deleted_name": path.rsplit("\\", 1)[-1], "deleted_size": 3,
        "deletion_method": method, "owner_sid": None, "actor_sid": None,
        "is_directory": False, "recoverable_hint": "unknown",
    }
    evidence.update(extra)
    src = {"recycle_bin": "recycle_bin", "usn_journal": "usnjrnl", "mft_unallocated": "mft"}
    return _ev("file_delete", evidence, source=src[method], ts=ts)


def _logon(user: str, ts: str, logon_id: str) -> Event:
    return _ev("logon", {"event_id": 4624, "TargetUserName": user, "LogonType": "2",
                         "TargetLogonId": logon_id}, source="evtx.security", ts=ts)


@pytest.fixture
def populated() -> tuple[EventStore, Any]:
    store = EventStore()
    store.register_collection(CID, "H", "windows", "2026-01-01T00:00:00Z")
    store.insert_events([
        _ev("account_change", {"sid": ALICE_SID, "username": "alice"}, source="registry.sam"),
        _logon("alice", "2026-03-01T08:00:00Z", "0xA"),
        _delete("recycle_bin", r"C:\Users\alice\one.docx", "2026-03-01T09:00:00Z",
                actor_sid=ALICE_SID, owner_sid=ALICE_SID, recovered_name="$R1.docx"),
        _delete("usn_journal", r"C:\Users\alice\two.docx", "2026-03-01T10:00:00Z"),
        _delete("mft_unallocated", r"C:\Users\bob\three.docx", "2026-02-01T10:00:00Z",
                owner_sid="S-1-5-21-1-2-3-1002"),
    ])
    return store, build_dispatcher(store)


def test_ops_require_collection_id() -> None:
    d = build_dispatcher(EventStore())
    for op in ("query_deletions", "build_deletions"):
        r = d.dispatch({"op": op})
        assert r["ok"] is False
        assert "collection_id" in r["error"]
    r = d.dispatch({"op": "build_deletions", "collection_id": "nope"})
    assert r["ok"] is False
    assert "unknown collection_id" in r["error"]


def test_build_then_query_deletions_shapes(populated: tuple[EventStore, Any]) -> None:
    _store, d = populated
    built = d.dispatch({"op": "build_deletions", "collection_id": CID})
    assert built["ok"] is True
    assert built["collection_id"] == CID
    assert built["total"] == 3
    assert built["by_method"] == {"recycle_bin": 1, "usn_journal": 1, "mft_unallocated": 1}
    # The MFT row predates alice's only logon, so no session covers its bound.
    assert built["by_actor_confidence"] == {"direct": 1, "likely": 1, "unknown": 1}
    assert built["bursts"] == 0

    q = d.dispatch({"op": "query_deletions", "collection_id": CID})
    assert q["ok"] is True
    assert q["total"] == 3
    assert q["total_unfiltered"] == 3
    assert q["bursts"] == 0
    assert q["by_method"] == {"recycle_bin": 1, "usn_journal": 1, "mft_unallocated": 1}
    assert q["by_actor"] == [
        {"actor_user": "alice", "actor_confidence": "direct", "count": 1},
        {"actor_user": "alice", "actor_confidence": "likely", "count": 1},
        {"actor_user": None, "actor_confidence": "unknown", "count": 1},
    ]
    rows = q["deletions"]
    assert [r["deleted_at"] for r in rows] == [
        "2026-03-01T10:00:00Z", "2026-03-01T09:00:00Z", "2026-02-01T10:00:00Z",
    ]  # default sort: deleted_at desc
    expected_keys = {
        "deletion_id", "collection_id", "event_id", "deleted_at", "time_basis", "path",
        "name", "size", "is_directory", "method", "owner_sid", "owner_user", "actor_user",
        "actor_sid", "actor_confidence", "actor_reason", "recoverable_hint", "source_path",
    }
    assert set(rows[0]) == expected_keys
    assert rows[0]["is_directory"] is False
    assert rows[0]["size"] == 3
    # event_id opens the underlying file_delete event.
    ev = d.dispatch({"op": "get_event", "event_id": rows[0]["event_id"]})
    assert ev["ok"] is True
    assert ev["event"]["event_type"] == "file_delete"


def test_query_deletions_filters_sort_and_paging(populated: tuple[EventStore, Any]) -> None:
    _store, d = populated
    d.dispatch({"op": "build_deletions", "collection_id": CID})

    r = d.dispatch({"op": "query_deletions", "collection_id": CID, "method": "usn_journal"})
    assert r["total"] == 1 and r["total_unfiltered"] == 3
    assert r["deletions"][0]["method"] == "usn_journal"

    r = d.dispatch({"op": "query_deletions", "collection_id": CID, "actor_user": "alice",
                    "actor_confidence": "direct"})
    assert [x["name"] for x in r["deletions"]] == ["one.docx"]

    r = d.dispatch({"op": "query_deletions", "collection_id": CID, "path_contains": "\\bob\\"})
    assert [x["name"] for x in r["deletions"]] == ["three.docx"]

    r = d.dispatch({"op": "query_deletions", "collection_id": CID, "sort_by": "path",
                    "sort_dir": "asc", "limit": 2, "offset": 1})
    assert [x["name"] for x in r["deletions"]] == ["two.docx", "three.docx"]
    assert r["total"] == 3

    r = d.dispatch({"op": "query_deletions", "collection_id": CID, "sort_by": "evil"})
    assert r["ok"] is False and "sort_by" in r["error"]


def test_query_deletions_reports_bursts(populated: tuple[EventStore, Any]) -> None:
    store, d = populated
    store.insert_events([
        _delete("usn_journal", rf"C:\bulk\{i}.tmp", f"2026-03-01T11:00:{i:02d}Z")
        for i in range(30)
    ])
    built = d.dispatch({"op": "build_deletions", "collection_id": CID})
    assert built["bursts"] == 1
    q = d.dispatch({"op": "query_deletions", "collection_id": CID, "limit": 1})
    assert q["bursts"] == 1
    assert q["total"] == 33
    assert len(q["deletions"]) == 1
    burst = d.dispatch({"op": "query_events", "collection_id": CID,
                        "event_type": "file_delete_burst"})["events"]
    assert len(burst) == 1
    assert burst[0]["evidence"]["actor_user"] == "alice"


# --- triage pipeline integration ---------------------------------------------


def _build_i_v1(original_path: str, size: int, deleted: datetime) -> bytes:
    filetime = int((deleted - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000)
    path = original_path.encode("utf-16-le").ljust(520, b"\x00")
    return struct.pack("<qqq", 1, size, filetime) + path


def test_run_triage_directory_builds_deletions(tmp_path: Path) -> None:
    sid_dir = tmp_path / "$Recycle.Bin" / ALICE_SID
    sid_dir.mkdir(parents=True)
    (sid_dir / "$IAAA111.docx").write_bytes(
        _build_i_v1(r"C:\Users\alice\notes.docx", 10, datetime(2026, 3, 1, 9, tzinfo=UTC)),
    )
    store = EventStore()
    d = build_dispatcher(store)
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True
    assert r["deletions"]["total"] == 1
    assert r["deletions"]["by_actor_confidence"] == {"direct": 1}
    assert r["ghost_annotated"] == 0  # not a full volume mirror
    q = d.dispatch({"op": "query_deletions", "collection_id": r["collection_id"]})
    assert q["deletions"][0]["actor_sid"] == ALICE_SID
    assert q["deletions"][0]["actor_confidence"] == "direct"


def test_run_triage_hive_on_recycle_bin_record_builds_deletions(tmp_path: Path) -> None:
    sid_dir = tmp_path / "$Recycle.Bin" / ALICE_SID
    sid_dir.mkdir(parents=True)
    i_file = sid_dir / "$IBBB222.pdf"
    i_file.write_bytes(
        _build_i_v1(r"C:\Users\alice\x.pdf", 10, datetime(2026, 3, 1, 9, tzinfo=UTC)),
    )
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(i_file)})
    assert r["ok"] is True
    assert r["kind"] == "recycle_bin"
    assert r["deletions"]["total"] == 1


def test_run_triage_directory_dispatches_ntfs_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """$J / $MFT / $SDS discovered by the collector are routed to the parsers
    with sibling paths; the parsers are stubbed so this test does not depend on
    parsers/usnjrnl.py or parsers/mft.py existing."""
    ntfs = tmp_path / "ntfs"
    ntfs.mkdir()
    for name in ("$MFT", "$J", "$SDS"):
        (ntfs / name).write_bytes(b"\x00" * 16)

    from collectors.windows import user_hives

    monkeypatch.setattr(
        user_hives, "discover_ntfs_meta",
        lambda _root: {"mft": ntfs / "$MFT", "usnjrnl": ntfs / "$J", "sds": ntfs / "$SDS"},
        raising=False,
    )
    calls: dict[str, Any] = {}

    def fake_usn(j_path: str, *, collection_id: str, host_id_hint: str, mft_path=None,
                 sds_path=None, **_kw: Any) -> list[Event]:
        calls["usn"] = (j_path, mft_path, sds_path)
        return [make_event(
            host_os="windows", host_id=host_id_hint, source_artifact="usnjrnl",
            source_path=j_path, event_type="file_delete", summary="d",
            evidence={"original_path": r"C:\Users\alice\u.txt", "deleted_name": "u.txt",
                      "deletion_method": "usn_journal", "mft_segment": 9},
            collection_id=collection_id, parser_version="t", timestamp="2026-03-01T10:00:00Z",
        )]

    def fake_mft(mft_path: str, *, collection_id: str, host_id_hint: str, sds_path=None,
                 **_kw: Any) -> list[Event]:
        calls["mft"] = (mft_path, sds_path)
        return [make_event(
            host_os="windows", host_id=host_id_hint, source_artifact="mft",
            source_path=mft_path, event_type="file_delete", summary="d",
            evidence={"original_path": r"C:\Users\alice\u.txt", "deleted_name": "u.txt",
                      "deletion_method": "mft_unallocated", "mft_segment": 9},
            collection_id=collection_id, parser_version="t", timestamp="2026-03-01T09:00:00Z",
            timestamp_source="inferred",
        )]

    usn_mod = types.ModuleType("parsers.usnjrnl")
    usn_mod.parse_usnjrnl = fake_usn  # type: ignore[attr-defined]
    mft_mod = types.ModuleType("parsers.mft")
    mft_mod.parse_mft_deleted = fake_mft  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "parsers.usnjrnl", usn_mod)
    monkeypatch.setitem(sys.modules, "parsers.mft", mft_mod)

    store = EventStore()
    d = build_dispatcher(store)
    r = d.dispatch({"op": "run_triage_directory", "dir_path": str(tmp_path)})
    assert r["ok"] is True, r
    kinds = {a["kind"]: a for a in r["artifacts"]}
    assert set(kinds) == {"sds", "usnjrnl", "mft"}
    assert all("sha256" in a and "error" not in a for a in kinds.values())
    assert kinds["usnjrnl"]["event_count"] == 1
    assert kinds["mft"]["event_count"] == 1
    assert kinds["sds"]["event_count"] == 0
    assert r["event_count"] == 2
    assert calls["usn"] == (str(ntfs / "$J"), str(ntfs / "$MFT"), str(ntfs / "$SDS"))
    assert calls["mft"] == (str(ntfs / "$MFT"), str(ntfs / "$SDS"))
    # USN + MFT for the same segment/name collapsed into one deletion row.
    assert r["deletions"]["total"] == 1
    assert r["deletions"]["by_method"] == {"usn_journal": 1}

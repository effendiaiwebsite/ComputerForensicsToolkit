"""Attribution engine tests (core/deletions.py) over synthetic events.

Every event is built with the evidence keys from docs/DELETIONS.md; no
parser module is imported so the suite is independent of parsers/.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.deletions import (
    DERIVED_SOURCE_ARTIFACT,
    build_deletions,
    build_sessions,
    build_sid_map,
)
from core.events import Event, make_event
from core.store import EventStore

CID = "col-del"
ALICE_SID = "S-1-5-21-1-2-3-1001"
BOB_SID = "S-1-5-21-1-2-3-1002"


def _ev(event_type: str, evidence: dict[str, Any], *, source: str = "x", ts: str | None = None,
        ts_source: str | None = None, user: str | None = None) -> Event:
    return make_event(
        host_os="windows", host_id="HOST", source_artifact=source, source_path="/p",
        event_type=event_type, summary=event_type, evidence=evidence, collection_id=CID,
        parser_version="t", timestamp=ts, timestamp_source=ts_source, user=user,
    )


def _delete(method: str, path: str, ts: str | None, **extra: Any) -> Event:
    name = path.rsplit("\\", 1)[-1]
    evidence = {
        "original_path": path, "deleted_name": name, "deleted_size": 10,
        "deletion_method": method, "owner_sid": None, "actor_sid": None,
        "security_id": None, "mft_segment": None, "is_directory": False,
        "recoverable_hint": "unknown", "usn": None, "usn_reason": None,
    }
    evidence.update(extra)
    source = {"recycle_bin": "recycle_bin", "usn_journal": "usnjrnl", "mft_unallocated": "mft"}
    return _ev(
        "file_delete", evidence, source=source[method], ts=ts,
        ts_source="inferred" if method == "mft_unallocated" else None,
    )


def _logon(user: str, ts: str, *, logon_type: str = "2", logon_id: str = "0x1",
           sid: str | None = None) -> Event:
    return _ev("logon", {
        "event_id": 4624, "TargetUserName": user, "LogonType": logon_type,
        "TargetLogonId": logon_id, "TargetUserSid": sid or "S-1-0-0",
    }, source="evtx.security", ts=ts, user=user)


def _logoff(user: str, ts: str, *, logon_id: str = "0x1", event_id: int = 4634,
            logon_type: str = "2") -> Event:
    etype = "logoff" if event_id == 4634 else "security_event"
    return _ev(etype, {
        "event_id": event_id, "TargetUserName": user, "LogonType": logon_type,
        "TargetLogonId": logon_id,
    }, source="evtx.security", ts=ts, user=user)


def _sam(sid: str, username: str) -> Event:
    return _ev("account_change", {"sid": sid, "username": username}, source="registry.sam")


def _store(*events: Event) -> EventStore:
    store = EventStore()
    store.register_collection(CID, "HOST", "windows", "2026-01-01T00:00:00Z")
    store.insert_events(events)
    return store


def _rows(store: EventStore) -> list[dict[str, Any]]:
    return store.query_deletions(collection_id=CID, limit=10_000)


# --- actor attribution -------------------------------------------------------


def test_recycle_bin_record_is_direct_and_names_the_folder_owner() -> None:
    store = _store(
        _sam(ALICE_SID, "alice"),
        _delete("recycle_bin", r"C:\Users\alice\secret.docx", "2026-03-01T10:00:00Z",
                actor_sid=ALICE_SID, owner_sid=ALICE_SID, recovered_name="$RABC123.docx",
                recoverable_hint="recycle_bin_blob"),
    )
    summary = build_deletions(store, CID)
    (row,) = _rows(store)
    assert summary.total == 1
    assert row["actor_confidence"] == "direct"
    assert row["actor_user"] == "alice"
    assert row["actor_sid"] == ALICE_SID
    assert row["owner_user"] == "alice"
    assert row["time_basis"] == "exact"
    assert row["recoverable_hint"] == "recycle_bin_blob"
    assert row["actor_reason"] == f"Found in the Recycle Bin folder of {ALICE_SID} (alice)."
    assert summary.by_actor_user == {"alice": 1}
    assert summary.by_actor_confidence == {"direct": 1}


def test_recycle_bin_without_name_resolution_uses_hint_then_sid() -> None:
    store = _store(
        _delete("recycle_bin", r"C:\a.txt", "2026-03-01T10:00:00Z", actor_sid=BOB_SID),
    )
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_user"] == BOB_SID
    assert "account name not resolved" in row["actor_reason"]


def test_legacy_recycle_bin_sid_key_is_honoured() -> None:
    ev = _ev("file_delete", {
        "original_path": r"C:\old.txt", "deleted_name": "old.txt", "deleted_size": 1,
        "recovered_name": "$R1.txt", "sid": ALICE_SID, "format_version": 1,
    }, source="recycle_bin", ts="2026-03-01T10:00:00Z")
    store = _store(_sam(ALICE_SID, "alice"), ev)
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["method"] == "recycle_bin"
    assert row["actor_confidence"] == "direct"
    assert row["actor_user"] == "alice"
    assert row["recoverable_hint"] == "recycle_bin_blob"


def test_usn_delete_during_single_session_is_likely() -> None:
    store = _store(
        _logon("alice", "2015-03-24T09:12:03Z", logon_id="0xA"),
        _logoff("alice", "2015-03-24T17:40:11Z", logon_id="0xA"),
        _delete("usn_journal", r"C:\Users\alice\plan.xlsx", "2015-03-24T12:00:00Z",
                usn=123, usn_reason=["FILE_DELETE", "CLOSE"], mft_segment=5000),
    )
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "likely"
    assert row["actor_user"] == "alice"
    assert row["actor_reason"] == (
        "alice was the only interactive user logged on (4624 type 2 at "
        "2015-03-24T09:12:03Z, logoff 17:40:11Z) when the USN journal recorded the delete."
    )


def test_usn_delete_with_two_sessions_is_ambiguous_and_names_owner_when_known() -> None:
    base = [
        _sam(ALICE_SID, "alice"),
        _logon("alice", "2026-03-01T08:00:00Z", logon_id="0xA"),
        _logon("bob", "2026-03-01T09:00:00Z", logon_type="10", logon_id="0xB"),
        _logoff("bob", "2026-03-02T01:00:00Z", logon_id="0xB"),
    ]
    store = _store(*base, _delete("usn_journal", r"C:\x.txt", "2026-03-01T10:00:00Z"))
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "ambiguous"
    assert row["actor_user"] is None
    assert "2 users had sessions open" in row["actor_reason"]
    assert "alice (4624 type 2 at 2026-03-01T08:00:00Z, still logged on" in row["actor_reason"]
    assert "bob (4624 type 10 at 2026-03-01T09:00:00Z, logoff 2026-03-02T01:00:00Z)" in (
        row["actor_reason"]
    )

    store = _store(*base, _delete("usn_journal", r"C:\x.txt", "2026-03-01T10:00:00Z",
                                  owner_sid=ALICE_SID))
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "ambiguous"
    assert row["actor_user"] == "alice"
    assert row["actor_sid"] == ALICE_SID
    assert "owned by that account" in row["actor_reason"]
    assert f"File owner: alice ({ALICE_SID})." in row["actor_reason"]


def test_usn_delete_outside_any_session_is_unknown() -> None:
    store = _store(
        _logon("alice", "2026-03-01T08:00:00Z", logon_id="0xA"),
        _logoff("alice", "2026-03-01T09:00:00Z", logon_id="0xA"),
        _delete("usn_journal", r"C:\x.txt", "2026-03-01T10:00:00Z", owner_sid=BOB_SID),
    )
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "unknown"
    assert row["actor_user"] is None
    assert "No interactive logon session covers 2026-03-01T10:00:00Z" in row["actor_reason"]
    assert f"File owner SID {BOB_SID} could not be resolved" in row["actor_reason"]


def test_no_sessions_at_all_is_unknown() -> None:
    store = _store(_delete("usn_journal", r"C:\x.txt", "2026-03-01T10:00:00Z"))
    summary = build_deletions(store, CID)
    assert summary.by_actor_confidence == {"unknown": 1}


def test_undated_delete_is_unknown_with_explicit_reason() -> None:
    store = _store(
        _logon("alice", "2026-03-01T08:00:00Z"),
        _delete("usn_journal", r"C:\x.txt", None),
    )
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "unknown"
    assert "No deletion time is recorded" in row["actor_reason"]


# --- MFT upper-bound rows ----------------------------------------------------


def test_mft_row_is_upper_bound_and_never_better_than_ambiguous_by_session() -> None:
    store = _store(
        _logon("alice", "2026-03-01T08:00:00Z", logon_id="0xA"),
        _logoff("alice", "2026-03-01T18:00:00Z", logon_id="0xA"),
        _delete("mft_unallocated", r"C:\Users\alice\gone.txt", "2026-03-01T10:00:00Z",
                mft_segment=77, last_known_modified="2026-03-01T10:00:00Z"),
    )
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["time_basis"] == "upper_bound"
    assert row["actor_confidence"] == "ambiguous"
    assert row["actor_user"] is None
    assert row["actor_reason"].startswith(
        "Record time 2026-03-01T10:00:00Z is an upper bound (last $STANDARD_INFORMATION "
        "change), not the deletion time."
    )
    assert "may have been deleted later" in row["actor_reason"]


def test_mft_row_is_likely_only_when_owner_is_the_sole_interactive_user() -> None:
    events = [
        _sam(ALICE_SID, "alice"),
        _logon("alice", "2026-03-01T08:00:00Z", logon_id="0xA"),
        _delete("mft_unallocated", r"C:\gone.txt", "2026-03-01T10:00:00Z", owner_sid=ALICE_SID),
    ]
    store = _store(*events)
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "likely"
    assert row["actor_user"] == "alice"
    assert "upper bound" in row["actor_reason"]
    assert "only interactive user in the logon records" in row["actor_reason"]

    store = _store(*events, _logon("bob", "2026-03-02T08:00:00Z", logon_id="0xB"))
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "ambiguous"
    assert row["actor_user"] == "alice"  # owner among the covering sessions


def test_mft_row_without_sessions_is_unknown() -> None:
    store = _store(_delete("mft_unallocated", r"C:\gone.txt", "2026-03-01T10:00:00Z"))
    build_deletions(store, CID)
    (row,) = _rows(store)
    assert row["actor_confidence"] == "unknown"
    assert "No interactive logon session covers it" in row["actor_reason"]


# --- dedup across sources ----------------------------------------------------


def test_recycle_bin_and_usn_blob_delete_collapse_into_one_row() -> None:
    sid_dir = rf"C:\$Recycle.Bin\{ALICE_SID}"
    store = _store(
        _sam(ALICE_SID, "alice"),
        _delete("recycle_bin", r"C:\Users\alice\secret.docx", "2026-03-01T10:00:00Z",
                actor_sid=ALICE_SID, owner_sid=ALICE_SID, recovered_name="$RABC123.docx"),
        _delete("usn_journal", rf"{sid_dir}\$RABC123.docx", "2026-03-01T11:00:00Z"),
        _delete("usn_journal", rf"{sid_dir}\$IABC123.docx", "2026-03-01T11:00:01Z"),
        _delete("usn_journal", rf"{sid_dir}\$RZZZ999.pdf", "2026-03-01T11:00:02Z"),
    )
    summary = build_deletions(store, CID)
    rows = _rows(store)
    assert summary.total == 2
    merged = next(r for r in rows if r["method"] == "recycle_bin")
    assert merged["deleted_at"] == "2026-03-01T10:00:00Z"
    assert merged["actor_confidence"] == "direct"
    assert "Also recorded by the USN journal (FILE_DELETE at 2026-03-01T11:00:00Z)" in (
        merged["actor_reason"]
    )
    other = next(r for r in rows if r["method"] == "usn_journal")
    assert other["name"] == "$RZZZ999.pdf"


def test_usn_and_mft_with_same_segment_and_name_collapse() -> None:
    store = _store(
        _delete("usn_journal", r"C:\Users\alice\a.txt", "2026-03-01T10:00:00Z",
                mft_segment=4242, recoverable_hint="unknown"),
        _delete("mft_unallocated", r"C:\Users\alice\a.txt", "2026-03-01T09:30:00Z",
                mft_segment=4242, owner_sid=ALICE_SID, recoverable_hint="data_runs_present"),
        _delete("mft_unallocated", r"C:\Users\alice\b.txt", "2026-03-01T09:30:00Z",
                mft_segment=4242),  # same segment, different name: reused record
    )
    summary = build_deletions(store, CID)
    rows = _rows(store)
    assert summary.total == 2
    assert summary.by_method == {"usn_journal": 1, "mft_unallocated": 1}
    merged = next(r for r in rows if r["method"] == "usn_journal")
    assert merged["time_basis"] == "exact"
    assert merged["deleted_at"] == "2026-03-01T10:00:00Z"
    assert merged["owner_sid"] == ALICE_SID
    assert merged["recoverable_hint"] == "data_runs_present"
    assert "Also present as an unallocated MFT record (last changed 2026-03-01T09:30:00Z)" in (
        merged["actor_reason"]
    )


# --- bursts ------------------------------------------------------------------


def _many(method: str, n: int, start_s: int = 0, step_s: int = 2) -> list[Event]:
    return [
        _delete(method, rf"C:\bulk\f{i}.dat", f"2026-03-01T10:{(start_s + i * step_s) // 60:02d}:"
                f"{(start_s + i * step_s) % 60:02d}Z")
        for i in range(n)
    ]


def test_burst_emits_one_derived_event_and_is_idempotent() -> None:
    store = _store(_logon("alice", "2026-03-01T08:00:00Z"), *_many("usn_journal", 25))
    summary = build_deletions(store, CID)
    assert summary.bursts == 1
    bursts = store.query_events(collection_id=CID, event_type="file_delete_burst")
    assert len(bursts) == 1
    b = bursts[0]
    assert b["source_artifact"] == DERIVED_SOURCE_ARTIFACT
    assert b["timestamp_source"] == "inferred"
    assert b["evidence"]["count"] == 25
    assert b["evidence"]["method"] == "usn_journal"
    assert b["evidence"]["actor_user"] == "alice"
    assert b["evidence"]["window_start"] == "2026-03-01T10:00:00Z"
    assert b["evidence"]["window_end"] == "2026-03-01T10:00:48Z"
    assert len(b["evidence"]["sample_paths"]) == 10
    assert "25 files via usn_journal" in b["summary"]

    first_ids = {r["deletion_id"] for r in _rows(store)}
    again = build_deletions(store, CID)
    assert again.bursts == 1
    rebuilt = store.query_events(collection_id=CID, event_type="file_delete_burst")
    assert [r["event_id"] for r in rebuilt] == [b["event_id"]]
    assert store.count_events(collection_id=CID) == 1 + 25 + 1
    assert {r["deletion_id"] for r in _rows(store)} == first_ids
    assert store.count_deletions(collection_id=CID) == 25


def test_burst_threshold_window_and_method_boundaries() -> None:
    # 19 deletions: no burst.
    store = _store(*_many("usn_journal", 19))
    assert build_deletions(store, CID).bursts == 0
    # 20 deletions spread 10 s apart (190 s span) still fits a 120 s sliding window? No:
    # 20 within 120 s requires step <= 6 s.
    store = _store(*_many("usn_journal", 20, step_s=10))
    assert build_deletions(store, CID).bursts == 0
    store = _store(*_many("usn_journal", 20, step_s=6))
    assert build_deletions(store, CID).bursts == 1
    # Two methods with 15 each never combine.
    store = _store(*_many("usn_journal", 15), *_many("recycle_bin", 15))
    assert build_deletions(store, CID).bursts == 0
    # MFT upper-bound times are excluded.
    store = _store(*_many("mft_unallocated", 30))
    assert build_deletions(store, CID).bursts == 0


def test_two_separate_bursts_are_reported_separately() -> None:
    store = _store(*_many("usn_journal", 25), *_many("usn_journal", 25, start_s=1800))
    assert build_deletions(store, CID).bursts == 2


# --- session and SID helpers -------------------------------------------------


def test_sessions_close_by_logon_id_and_ignore_network_logoffs() -> None:
    events = [e.to_json() for e in (
        _logon("alice", "2026-03-01T08:00:00Z", logon_id="0xA"),
        _logon("alice", "2026-03-01T08:00:00Z", logon_id="0xA"),  # duplicate record
        _logon("alice", "2026-03-01T08:05:00Z", logon_type="3", logon_id="0xN"),  # network
        _logoff("alice", "2026-03-01T08:06:00Z", logon_id="0xN", logon_type="3"),
        _logon("DWM-1", "2026-03-01T08:00:00Z", logon_id="0xD"),
        _logon("WORKSTATION$", "2026-03-01T08:00:00Z", logon_id="0xM"),
        _logoff("alice", "2026-03-01T12:00:00Z", logon_id="0xA"),
        _logon("bob", "2026-03-01T13:00:00Z", logon_type="11", logon_id="0xB"),
        _logoff("bob", "2026-03-01T14:00:00Z", logon_id="0xZ", event_id=4647),
    )]
    sessions = build_sessions(events)
    assert [(s.user, s.start, s.end, s.logon_type) for s in sessions] == [
        ("alice", "2026-03-01T08:00:00Z", "2026-03-01T12:00:00Z", "2"),
        ("bob", "2026-03-01T13:00:00Z", "2026-03-01T14:00:00Z", "11"),
    ]


def test_sid_map_from_sam_profilelist_logon_and_well_known() -> None:
    events = [e.to_json() for e in (
        _sam(ALICE_SID, "alice"),
        _ev("system_config_change", {"sid": BOB_SID, "profile_path": r"C:\Users\bob"},
            source="registry.software"),
        _logon("carol", "2026-03-01T08:00:00Z", sid="S-1-5-21-1-2-3-1003"),
        _logon("SYSTEM", "2026-03-01T08:00:00Z", sid="S-1-5-18"),
    )]
    m = build_sid_map(events)
    assert m[ALICE_SID] == "alice"
    assert m[BOB_SID] == "bob"
    assert m["S-1-5-21-1-2-3-1003"] == "carol"
    assert m["S-1-5-18"] == "SYSTEM"
    assert m["S-1-5-32-544"] == "Administrators"


def test_build_deletions_on_empty_collection_clears_previous_rows() -> None:
    store = _store(_delete("usn_journal", r"C:\x.txt", "2026-03-01T10:00:00Z"))
    assert build_deletions(store, CID).total == 1
    store.delete_events_by_source(CID, "usnjrnl")
    summary = build_deletions(store, CID)
    assert summary.total == 0
    assert summary.to_dict() == {
        "total": 0, "by_method": {}, "by_actor_confidence": {}, "by_actor_user": {},
        "bursts": 0,
    }
    assert _rows(store) == []


@pytest.mark.parametrize("method", ["recycle_bin", "usn_journal", "mft_unallocated"])
def test_method_inferred_from_source_artifact_when_key_missing(method: str) -> None:
    ev = _delete(method, r"C:\x.txt", "2026-03-01T10:00:00Z")
    del ev.evidence["deletion_method"]
    store = _store(ev)
    build_deletions(store, CID)
    assert _rows(store)[0]["method"] == method

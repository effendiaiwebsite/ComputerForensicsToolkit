"""Tests for the USN change journal (``$J``) parser.

The journal is packed from real ``USN_RECORD_V2`` structures via dissect's
``c_ntfs`` definitions, laid out in 4 KiB pages with zero fill between them
and a truncated record at the tail, exactly as an extracted ``$J`` looks.
Path and owner resolution reuse the synthetic ``$MFT`` / ``$SDS`` volume from
``test_mft_parser``.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path

from dissect.ntfs import NTFS, UsnJrnl
from dissect.ntfs.c_ntfs import USN_PAGE_SIZE, c_ntfs

from parsers.usnjrnl import (
    decode_reason,
    iter_usn_records,
    parse_usnjrnl,
    parse_usnjrnl_from_target,
)
from tests.test_mft_parser import (
    SECID_ALICE,
    SECID_BOB,
    SEG_NOTES,
    SEG_OLDDIR,
    SEG_SECRET,
    SEQ_BOB_DIR,
    SEQ_SECRET,
    SID_ALICE,
    SID_BOB,
    build_volume_mft,
    build_volume_sds,
    filetime,
    write_volume,
)

R = c_ntfs.USN_REASON
FILE_DELETE = int(R.FILE_DELETE)
FILE_CREATE = int(R.FILE_CREATE)
RENAME_OLD = int(R.RENAME_OLD_NAME)
RENAME_NEW = int(R.RENAME_NEW_NAME)
DATA_EXTEND = int(R.DATA_EXTEND)
CLOSE = int(R.CLOSE)

T_DELETE = datetime(2024, 3, 6, 8, 1, 2, tzinfo=UTC)
T_RENAME = datetime(2024, 3, 6, 8, 5, 0, tzinfo=UTC)
T_CREATE = datetime(2024, 3, 6, 8, 9, 0, tzinfo=UTC)


def usn_record(
    *, usn: int, name: str, reason: int, ts: datetime = T_DELETE,
    file_ref: tuple[int, int] = (SEG_SECRET, SEQ_SECRET),
    parent_ref: tuple[int, int] = (25, SEQ_BOB_DIR),
    security_id: int = SECID_BOB, attributes: int = 0x20,
) -> bytes:
    encoded = name.encode("utf-16-le")
    length = 60 + len(encoded)
    length += -length & 7
    rec = c_ntfs.USN_RECORD_V2(
        RecordLength=length, MajorVersion=2, MinorVersion=0,
        FileReferenceNumber=c_ntfs.MFT_SEGMENT_REFERENCE(
            SegmentNumberLowPart=file_ref[0], SegmentNumberHighPart=0, SequenceNumber=file_ref[1],
        ),
        ParentFileReferenceNumber=c_ntfs.MFT_SEGMENT_REFERENCE(
            SegmentNumberLowPart=parent_ref[0], SegmentNumberHighPart=0,
            SequenceNumber=parent_ref[1],
        ),
        Usn=usn, TimeStamp=filetime(ts), Reason=R(reason), SourceInfo=c_ntfs.USN_SOURCE(0),
        SecurityId=security_id, FileAttributes=c_ntfs.FILE_ATTRIBUTE(attributes),
        FileNameLength=len(encoded), FileNameOffset=60,
    )
    out = rec.dumps() + encoded
    return out + b"\x00" * (length - len(out))


def _page(*records: bytes) -> bytes:
    data = b"".join(records)
    assert len(data) <= USN_PAGE_SIZE
    return data + b"\x00" * (USN_PAGE_SIZE - len(data))


def build_journal() -> bytes:
    """Two pages of records, a page of zeros, then a truncated trailing record."""
    page1 = _page(
        # ordinary edit of notes.txt: not interesting
        usn_record(usn=8, name="notes.txt", reason=DATA_EXTEND | CLOSE,
                   file_ref=(SEG_NOTES, 2), security_id=SECID_ALICE),
        # rename report.docx -> secret.docx (old, new, new+close)
        usn_record(usn=96, name="report.docx", reason=RENAME_OLD, ts=T_RENAME),
        usn_record(usn=184, name="secret.docx", reason=RENAME_NEW, ts=T_RENAME),
        usn_record(usn=272, name="secret.docx", reason=RENAME_NEW | CLOSE, ts=T_RENAME),
        # create temp.tmp (create, then create+extend+close)
        usn_record(usn=360, name="temp.tmp", reason=FILE_CREATE, ts=T_CREATE,
                   file_ref=(40, 1), security_id=SECID_ALICE),
        usn_record(usn=440, name="temp.tmp", reason=FILE_CREATE | DATA_EXTEND | CLOSE,
                   ts=T_CREATE, file_ref=(40, 1), security_id=SECID_ALICE),
    )
    page2 = _page(
        # delete secret.docx: FILE_DELETE then FILE_DELETE|CLOSE -> one event
        usn_record(usn=4096 + 0, name="secret.docx", reason=FILE_DELETE),
        usn_record(usn=4096 + 88, name="secret.docx", reason=FILE_DELETE | CLOSE),
        # delete a directory
        usn_record(usn=4096 + 176, name="olddir", reason=FILE_DELETE | CLOSE,
                   file_ref=(SEG_OLDDIR, 9), attributes=0x10),
        # delete whose MFT slot has since been reused (sequence mismatch)
        usn_record(usn=4096 + 256, name="gone.log", reason=FILE_DELETE | CLOSE,
                   file_ref=(SEG_NOTES, 1), security_id=0),
        # FILE_DELETE that never closes within the journal -> still emitted
        usn_record(usn=4096 + 344, name="unclosed.bin", reason=FILE_DELETE, file_ref=(41, 1)),
    )
    zero_page = b"\x00" * USN_PAGE_SIZE
    truncated = usn_record(usn=3 * 4096, name="tail-cut.txt", reason=FILE_DELETE | CLOSE)[:30]
    return page1 + page2 + zero_page + truncated


def write_journal(tmp_path: Path, data: bytes | None = None) -> Path:
    p = tmp_path / "$J"
    p.write_bytes(data if data is not None else build_journal())
    return p


# ---------- decoding --------------------------------------------------------------


def test_decode_reason() -> None:
    assert decode_reason(FILE_DELETE | CLOSE) == ["FILE_DELETE", "CLOSE"]
    assert decode_reason(RENAME_OLD) == ["RENAME_OLD_NAME"]
    assert decode_reason(0) == []
    assert decode_reason(0x08000000 | FILE_CREATE) == ["FILE_CREATE", "0x08000000"]


def test_fixture_round_trips_through_dissect() -> None:
    jrnl = UsnJrnl(io.BytesIO(build_journal()))
    names = [r.filename for r in jrnl.records()]
    assert names[:2] == ["notes.txt", "report.docx"]
    assert "unclosed.bin" in names
    assert len(list(iter_usn_records(jrnl))) == len(names)


# ---------- parser, full context --------------------------------------------------


def _by_type(events) -> dict[str, list]:
    out: dict[str, list] = {}
    for e in events:
        out.setdefault(e.event_type, []).append(e)
    return out


def test_parse_with_mft_and_sds(tmp_path: Path) -> None:
    mft, sds = write_volume(tmp_path)
    j = write_journal(tmp_path)
    events = parse_usnjrnl(
        str(j), collection_id="c", host_id_hint="HOST",
        mft_path=str(mft), sds_path=str(sds),
    )
    by_type = _by_type(events)
    assert set(by_type) == {"file_delete", "file_rename"}  # creates off by default
    assert all(e.source_artifact == "usnjrnl" for e in events)
    assert all(e.source_path == str(j.resolve()) for e in events)

    deletes = {e.evidence["deleted_name"]: e for e in by_type["file_delete"]}
    assert set(deletes) == {"secret.docx", "olddir", "gone.log", "unclosed.bin"}

    secret = deletes["secret.docx"]
    ev = secret.evidence
    assert ev["original_path"] == r"C:\Users\bob\secret.docx"
    assert ev["deleted_size"] == 12345  # from the still-unallocated MFT ghost
    assert ev["deletion_method"] == "usn_journal"
    assert ev["owner_sid"] == SID_BOB
    assert ev["actor_sid"] is None
    assert ev["security_id"] == SECID_BOB
    assert ev["mft_segment"] == SEG_SECRET
    assert ev["is_directory"] is False
    assert ev["recoverable_hint"] == "data_runs_present"
    assert ev["usn"] == 4096 + 88  # keyed on the closing record
    assert ev["usn_reason"] == ["FILE_DELETE", "CLOSE"]
    assert ev["last_known_modified"] is None and ev["last_known_created"] is None
    assert secret.timestamp == "2024-03-06T08:01:02Z"
    assert secret.timestamp_source == "direct"
    assert secret.summary == "Deleted: secret.docx (USN, 12.1 KB)"
    assert secret.raw["file_ref"] == f"{SEG_SECRET}#{SEQ_SECRET}"

    olddir = deletes["olddir"].evidence
    assert olddir["is_directory"] is True
    assert olddir["original_path"] == r"C:\Users\bob\olddir"
    assert olddir["deleted_size"] is None

    gone = deletes["gone.log"].evidence
    assert gone["deleted_size"] is None  # MFT slot reused: ghost not trusted
    assert gone["recoverable_hint"] == "unknown"
    assert gone["security_id"] is None and gone["owner_sid"] is None

    unclosed = deletes["unclosed.bin"].evidence
    assert unclosed["usn_reason"] == ["FILE_DELETE"]
    assert unclosed["original_path"] == r"C:\Users\bob\unclosed.bin"

    (rename,) = by_type["file_rename"]
    assert rename.evidence["original_path"] == r"C:\Users\bob\report.docx"
    assert rename.evidence["new_path"] == r"C:\Users\bob\secret.docx"
    assert rename.evidence["usn"] == 96
    assert rename.evidence["usn_reason"] == ["RENAME_OLD_NAME"]
    assert rename.timestamp == "2024-03-06T08:05:00Z"
    assert "report.docx" in rename.summary and "secret.docx" in rename.summary


def test_creates_and_renames_toggle(tmp_path: Path) -> None:
    j = write_journal(tmp_path)
    events = parse_usnjrnl(
        str(j), collection_id="c", host_id_hint="H", include_creates=True, include_renames=False,
    )
    by_type = _by_type(events)
    assert "file_rename" not in by_type
    (create,) = by_type["file_create"]
    assert create.evidence["original_path"] == r"C:\<unresolved>\temp.tmp"
    assert create.evidence["usn"] == 440  # one event per create, keyed on CLOSE
    assert create.evidence["usn_reason"] == ["DATA_EXTEND", "FILE_CREATE", "CLOSE"]
    assert create.timestamp == "2024-03-06T08:09:00Z"


def test_without_mft_paths_are_unresolved(tmp_path: Path) -> None:
    j = write_journal(tmp_path)
    events = parse_usnjrnl(str(j), collection_id="c", host_id_hint="H")
    deletes = {e.evidence["deleted_name"]: e.evidence for e in events
               if e.event_type == "file_delete"}
    assert deletes["secret.docx"]["original_path"] == r"C:\<unresolved>\secret.docx"
    assert deletes["secret.docx"]["deleted_size"] is None
    assert deletes["secret.docx"]["recoverable_hint"] == "unknown"
    assert deletes["secret.docx"]["owner_sid"] is None
    assert deletes["secret.docx"]["security_id"] == SECID_BOB
    assert deletes["secret.docx"]["mft_segment"] == SEG_SECRET
    rename = next(e for e in events if e.event_type == "file_rename")
    assert rename.evidence["new_path"] == r"C:\<unresolved>\secret.docx"


def test_drive_letter_absent_gives_volume_relative_path(tmp_path: Path) -> None:
    mft, _ = write_volume(tmp_path)
    j = write_journal(tmp_path)
    events = parse_usnjrnl(
        str(j), collection_id="c", host_id_hint="H", mft_path=str(mft), drive_letter="",
    )
    paths = {e.evidence["original_path"] for e in events}
    assert r"\Users\bob\secret.docx" in paths


# ---------- robustness --------------------------------------------------------------


def test_garbage_mid_page_resyncs_on_next_page(tmp_path: Path) -> None:
    good_after = usn_record(
        usn=5000, name="after.txt", reason=FILE_DELETE | CLOSE, file_ref=(50, 1),
    )
    page1 = _page(
        usn_record(usn=8, name="before.txt", reason=FILE_DELETE | CLOSE, file_ref=(49, 1)),
        b"\xff" * 64,  # implausible RecordLength 0xffffffff
        usn_record(usn=100, name="lost.txt", reason=FILE_DELETE | CLOSE, file_ref=(51, 1)),
    )
    j = write_journal(tmp_path, page1 + _page(good_after))
    names = [e.evidence["deleted_name"] for e in parse_usnjrnl(
        str(j), collection_id="c", host_id_hint="H")]
    assert names == ["before.txt", "after.txt"]  # lost.txt is behind the garbage, by design


def test_unsupported_record_version_is_skipped_by_length(tmp_path: Path) -> None:
    v9 = bytearray(usn_record(
        usn=8, name="weird.txt", reason=FILE_DELETE | CLOSE, file_ref=(60, 1),
    ))
    v9[4:6] = (9).to_bytes(2, "little")  # MajorVersion 9
    ok = usn_record(usn=200, name="fine.txt", reason=FILE_DELETE | CLOSE, file_ref=(61, 1))
    j = write_journal(tmp_path, _page(bytes(v9), ok))
    names = [e.evidence["deleted_name"] for e in parse_usnjrnl(
        str(j), collection_id="c", host_id_hint="H")]
    assert names == ["fine.txt"]


def test_bad_timestamp_yields_no_timestamp(tmp_path: Path) -> None:
    rec = bytearray(usn_record(usn=8, name="t.txt", reason=FILE_DELETE | CLOSE, file_ref=(62, 1)))
    rec[32:40] = b"\xff" * 8  # TimeStamp field
    j = write_journal(tmp_path, _page(bytes(rec)))
    (ev,) = parse_usnjrnl(str(j), collection_id="c", host_id_hint="H")
    assert ev.timestamp is None
    assert ev.timestamp_source == "none"
    assert ev.evidence["deleted_name"] == "t.txt"


def test_empty_and_missing_journal(tmp_path: Path) -> None:
    j = write_journal(tmp_path, b"")
    assert parse_usnjrnl(str(j), collection_id="c", host_id_hint="H") == []
    assert parse_usnjrnl(str(tmp_path / "nope"), collection_id="c", host_id_hint="H") == []
    # A missing $MFT alongside a good $J must not break parsing.
    j = write_journal(tmp_path)
    events = parse_usnjrnl(
        str(j), collection_id="c", host_id_hint="H", mft_path=str(tmp_path / "no-mft"),
    )
    assert events == []


# ---------- target variant ------------------------------------------------------


class _StubSecure:
    """Owner lookup that knows one id and raises KeyError otherwise (like dissect)."""

    def __init__(self, table: dict[int, str]) -> None:
        self.table = table
        self.calls: list[int] = []

    def lookup(self, security_id: int):
        self.calls.append(security_id)
        owner = self.table[security_id]
        return type("SD", (), {"owner": owner, "group": None})()


class _FakeNtfsFs:
    def __init__(self, ntfs) -> None:
        self.ntfs = ntfs


class _FakeTarget:
    def __init__(self, *filesystems) -> None:
        self.filesystems = list(filesystems)


def test_parse_from_target_with_stub_secure() -> None:
    ntfs = NTFS(mft=io.BytesIO(build_volume_mft()), usnjrnl=io.BytesIO(build_journal()))
    stub = _StubSecure({SECID_BOB: SID_BOB})
    ntfs.secure = stub
    target = _FakeTarget(_FakeNtfsFs(ntfs))
    events = parse_usnjrnl_from_target(target, 0, collection_id="c", host_id_hint="H")
    deletes = {e.evidence["deleted_name"]: e for e in events if e.event_type == "file_delete"}
    assert deletes["secret.docx"].evidence["owner_sid"] == SID_BOB
    assert deletes["secret.docx"].evidence["original_path"] == r"C:\Users\bob\secret.docx"
    assert deletes["secret.docx"].source_path == r"C:\$Extend\$UsnJrnl:$J"
    assert deletes["gone.log"].evidence["owner_sid"] is None
    assert SECID_BOB in stub.calls


def test_parse_from_target_without_journal_or_ntfs() -> None:
    ntfs = NTFS(mft=io.BytesIO(build_volume_mft()))
    assert ntfs.usnjrnl is None
    target = _FakeTarget(_FakeNtfsFs(ntfs), object())
    assert parse_usnjrnl_from_target(target, 0, collection_id="c", host_id_hint="H") == []
    assert parse_usnjrnl_from_target(target, 1, collection_id="c", host_id_hint="H") == []
    assert parse_usnjrnl_from_target(target, 7, collection_id="c", host_id_hint="H") == []


def test_parse_from_target_sds_path_overrides(tmp_path: Path) -> None:
    sds = tmp_path / "$SDS"
    sds.write_bytes(build_volume_sds())
    ntfs = NTFS(mft=io.BytesIO(build_volume_mft()), usnjrnl=io.BytesIO(build_journal()))
    events = parse_usnjrnl_from_target(
        _FakeTarget(_FakeNtfsFs(ntfs)), 0, collection_id="c", host_id_hint="H",
        sds_path=str(sds),
    )
    owners = {e.evidence["deleted_name"]: e.evidence["owner_sid"] for e in events
              if e.event_type == "file_delete"}
    assert owners["secret.docx"] == SID_BOB
    assert SID_ALICE not in owners.values()

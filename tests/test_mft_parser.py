"""Tests for the ``$MFT`` unallocated-record parser.

The fixtures are real on-disk bytes: 1 KiB ``FILE`` records with update
sequence fixups, resident ``$STANDARD_INFORMATION`` / ``$FILE_NAME`` / ``$DATA``
attributes and non-resident ``$DATA`` dataruns, parsed by ``dissect.ntfs``
exactly as a ``$MFT`` pulled off a volume would be. ``$SDS`` entries are
likewise packed as self-relative security descriptors so owner SIDs resolve
through ``dissect.ntfs.Secure`` rather than a stub.
"""

from __future__ import annotations

import io
import struct
from datetime import UTC, datetime
from pathlib import Path

from dissect.ntfs import NTFS

from parsers.mft import (
    events_from_records,
    iter_mft_records,
    parse_mft_deleted,
    parse_mft_deleted_from_target,
)

RECORD_SIZE = 1024
_EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01

IN_USE = 0x0001
IS_DIR = 0x0002
FN_NTFS = 0x01
FN_DOS = 0x02

ATTR_SI = 0x10
ATTR_FN = 0x30
ATTR_DATA = 0x80

SID_BOB = "S-1-5-21-1111-2222-3333-1001"
SID_ALICE = "S-1-5-21-1111-2222-3333-1002"
SECID_BOB = 0x105
SECID_ALICE = 0x106

T_CREATED = datetime(2024, 3, 1, 9, 0, 0, tzinfo=UTC)
T_MODIFIED = datetime(2024, 3, 2, 10, 30, 0, tzinfo=UTC)
T_CHANGED = datetime(2024, 3, 5, 14, 15, 16, tzinfo=UTC)


def filetime(dt: datetime) -> int:
    return int((dt.timestamp() + _EPOCH_DIFF) * 10_000_000)


# ---------- byte builders -------------------------------------------------------


def _ref(segment: int, seq: int) -> bytes:
    return struct.pack("<IHH", segment & 0xFFFFFFFF, segment >> 32, seq)


def _align8(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) & 7)


def _resident_attr(type_code: int, value: bytes, instance: int, name: str = "") -> bytes:
    name_bytes = name.encode("utf-16-le")
    name_offset = 24
    value_offset = 24 + len(name_bytes)
    value_offset += -value_offset & 7
    body_len = value_offset + len(value)
    body_len += -body_len & 7
    hdr = struct.pack(
        "<IIBBHHH", type_code, body_len, 0, len(name), name_offset, 0, instance,
    )
    hdr += struct.pack("<IHBB", len(value), value_offset, 0, 0)
    out = hdr + name_bytes
    out += b"\x00" * (value_offset - len(out))
    out += value
    return out + b"\x00" * (body_len - len(out))


def _nonresident_data(
    runs: list[tuple[int | None, int]], file_size: int, instance: int, cluster: int = 4096,
) -> bytes:
    total_clusters = sum(length for _, length in runs)
    mapping = b""
    prev_lcn = 0
    for lcn, length in runs:
        len_bytes = length.to_bytes(1, "little")
        if lcn is None:  # sparse run: no offset field
            mapping += bytes([0x01]) + len_bytes
            continue
        delta = lcn - prev_lcn
        off_bytes = delta.to_bytes(2, "little", signed=True)
        mapping += bytes([0x21]) + len_bytes + off_bytes
        prev_lcn = lcn
    mapping += b"\x00"
    body_len = 64 + len(mapping)
    body_len += -body_len & 7
    hdr = struct.pack("<IIBBHHH", ATTR_DATA, body_len, 1, 0, 64, 0, instance)
    hdr += struct.pack(
        "<QQHB5sqqq",
        0, max(total_clusters - 1, 0), 64, 0, b"\x00" * 5,
        total_clusters * cluster, file_size, file_size,
    )
    out = hdr + mapping
    return out + b"\x00" * (body_len - len(out))


def std_info(
    *, created: datetime = T_CREATED, modified: datetime = T_MODIFIED,
    changed: datetime = T_CHANGED, accessed: datetime = T_MODIFIED,
    attributes: int = 0x20, security_id: int = 0,
) -> bytes:
    return struct.pack(
        "<qqqqIIIIIIQQ",
        filetime(created), filetime(modified), filetime(changed), filetime(accessed),
        attributes, 0, 0, 0, 0, security_id, 0, 0,
    )


def file_name(
    name: str, parent: tuple[int, int], *, size: int = 0, flags: int = FN_NTFS,
    attributes: int = 0x20, created: datetime = T_CREATED, modified: datetime = T_MODIFIED,
    changed: datetime = T_CHANGED,
) -> bytes:
    encoded = name.encode("utf-16-le")
    return (
        _ref(*parent)
        + struct.pack(
            "<qqqqqqIIBB",
            filetime(created), filetime(modified), filetime(changed), filetime(modified),
            (size + 4095) // 4096 * 4096, size, attributes, 0, len(name), flags,
        )
        + encoded
    )


def build_record(
    *,
    seq: int,
    flags: int,
    attrs: list[bytes],
    base_record: tuple[int, int] = (0, 0),
) -> bytes:
    """One 1 KiB ``FILE`` record with a valid update-sequence array."""
    body = b"".join(_align8(a) for a in attrs) + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4
    first_attr = 56
    bytes_in_use = first_attr + len(body)
    assert bytes_in_use <= RECORD_SIZE - 8, "record too large for fixture"
    header = struct.pack(
        "<4sHHQHHHHII", b"FILE", 48, 3, 0, seq, 1, first_attr, flags, bytes_in_use, RECORD_SIZE,
    )
    header += _ref(*base_record) + struct.pack("<H", len(attrs) + 1)
    rec = bytearray(RECORD_SIZE)
    rec[: len(header)] = header
    rec[first_attr:first_attr + len(body)] = body
    sample = b"\x01\x00"
    orig = bytes(rec[510:512]) + bytes(rec[1022:1024])
    rec[48:54] = sample + orig
    rec[510:512] = sample
    rec[1022:1024] = sample
    return bytes(rec)


def build_mft(records: dict[int, bytes]) -> bytes:
    """Lay records out at ``segment * 1024``; unmentioned slots are zero (unparseable)."""
    count = max(records) + 1
    buf = bytearray(RECORD_SIZE * count)
    for segment, rec in records.items():
        buf[segment * RECORD_SIZE:(segment + 1) * RECORD_SIZE] = rec
    return bytes(buf)


def sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    assert parts[0] == "S"
    revision = int(parts[1])
    authority = int(parts[2]).to_bytes(6, "big")
    subs = [int(p) for p in parts[3:]]
    head = struct.pack("<BB", revision, len(subs)) + authority
    return head + struct.pack(f"<{len(subs)}I", *subs)


def build_sds(entries: dict[int, str]) -> bytes:
    """``{security_id: owner_sid}`` → ``$SDS`` stream (self-relative descriptors, 16-aligned)."""
    out = bytearray()
    for sec_id, owner in entries.items():
        owner_b = sid_bytes(owner)
        descriptor = struct.pack("<BBHIIII", 1, 0, 0x8000, 20, 0, 0, 0) + owner_b
        length = 20 + len(descriptor)
        header = struct.pack("<IIQI", 0xDEADBEEF, sec_id, len(out), length)
        out += header + descriptor
        out += b"\x00" * (-len(out) & 0xF)
    return bytes(out)


# ---------- a small volume ---------------------------------------------------------
#
#   5   .            (root dir)
#   0   $MFT         in use
#   24  Users\       in use, dir
#   25  Users\bob\   in use, dir
#   26  Users\bob\secret.docx   DELETED, non-resident data, DOS + NTFS names, owner bob
#   27  Users\bob\notes.txt     DELETED, resident data "hello", owner alice
#   28  (unallocated, $STANDARD_INFORMATION only -> no name -> skipped)
#   29  Users\<broken parent>\orphan.bin   DELETED, parent seq mismatch
#   30  garbage bytes                      (skipped)
#   31  Users\bob\olddir\       DELETED directory
#   32  in use file Users\bob\keep.txt     (skipped: allocated)
#   33  deleted, attribute RecordLength 0  (BrokenMftError on .attributes -> skipped)

SEG_SECRET, SEG_NOTES, SEG_NONAME, SEG_ORPHAN, SEG_GARBAGE, SEG_OLDDIR, SEG_KEEP, SEG_BROKEN = (
    26, 27, 28, 29, 30, 31, 32, 33,
)
SEQ_SECRET = 7
SEQ_BOB_DIR = 3


def build_volume_mft() -> bytes:
    root = build_record(seq=5, flags=IN_USE | IS_DIR, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name(".", (5, 5), attributes=0x10000000), 2),
    ])
    mft_file = build_record(seq=1, flags=IN_USE, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name("$MFT", (5, 5), size=34 * RECORD_SIZE), 2),
        _nonresident_data([(4, 9)], 34 * RECORD_SIZE, 3),
    ])
    users = build_record(seq=2, flags=IN_USE | IS_DIR, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name("Users", (5, 5), attributes=0x10000000), 2),
    ])
    bob = build_record(seq=SEQ_BOB_DIR, flags=IN_USE | IS_DIR, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name("bob", (24, 2), attributes=0x10000000), 2),
    ])
    secret = build_record(seq=SEQ_SECRET, flags=0, attrs=[
        _resident_attr(ATTR_SI, std_info(security_id=SECID_BOB), 1),
        _resident_attr(ATTR_FN, file_name("SECRET~1.DOC", (25, SEQ_BOB_DIR), size=12345,
                                          flags=FN_DOS), 2),
        _resident_attr(ATTR_FN, file_name("secret.docx", (25, SEQ_BOB_DIR), size=12345), 3),
        _nonresident_data([(100, 3)], 12345, 4),
    ])
    notes = build_record(seq=2, flags=0, attrs=[
        _resident_attr(ATTR_SI, std_info(security_id=SECID_ALICE,
                                         changed=datetime(2024, 4, 1, tzinfo=UTC)), 1),
        _resident_attr(ATTR_FN, file_name("notes.txt", (25, SEQ_BOB_DIR), size=5), 2),
        _resident_attr(ATTR_DATA, b"hello", 3),
    ])
    noname = build_record(seq=1, flags=0, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
    ])
    orphan = build_record(seq=4, flags=0, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name("orphan.bin", (25, SEQ_BOB_DIR + 5), size=10), 2),
        _nonresident_data([(None, 2)], 10, 3),  # sparse-only runs: nothing to recover
    ])
    garbage = b"\xde\xad" * (RECORD_SIZE // 2)
    olddir = build_record(seq=9, flags=IS_DIR, attrs=[
        _resident_attr(ATTR_SI, std_info(security_id=SECID_BOB), 1),
        _resident_attr(ATTR_FN, file_name("olddir", (25, SEQ_BOB_DIR), attributes=0x10000000), 2),
    ])
    keep = build_record(seq=1, flags=IN_USE, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name("keep.txt", (25, SEQ_BOB_DIR), size=3), 2),
        _resident_attr(ATTR_DATA, b"abc", 3),
    ])
    broken = bytearray(build_record(seq=1, flags=0, attrs=[
        _resident_attr(ATTR_SI, std_info(), 1),
        _resident_attr(ATTR_FN, file_name("broken.txt", (25, SEQ_BOB_DIR)), 2),
    ]))
    struct.pack_into("<I", broken, 56 + 4, 0)  # first attribute RecordLength = 0
    return build_mft({
        0: mft_file, 5: root, 24: users, 25: bob,
        SEG_SECRET: secret, SEG_NOTES: notes, SEG_NONAME: noname, SEG_ORPHAN: orphan,
        SEG_GARBAGE: garbage, SEG_OLDDIR: olddir, SEG_KEEP: keep, SEG_BROKEN: bytes(broken),
    })


def build_volume_sds() -> bytes:
    return build_sds({SECID_BOB: SID_BOB, SECID_ALICE: SID_ALICE})


def write_volume(tmp_path: Path) -> tuple[Path, Path]:
    mft = tmp_path / "$MFT"
    sds = tmp_path / "$SDS"
    mft.write_bytes(build_volume_mft())
    sds.write_bytes(build_volume_sds())
    return mft, sds


# ---------- fixture sanity: dissect parses what we packed ------------------------


def test_fixture_round_trips_through_dissect(tmp_path: Path) -> None:
    mft, _ = write_volume(tmp_path)
    with mft.open("rb") as fh:
        ntfs = NTFS(mft=fh)
        rec = ntfs.mft.get(SEG_SECRET)
        assert rec.header.SequenceNumber == SEQ_SECRET
        assert rec.filenames() == ["secret.docx", "SECRET~1.DOC"]
        assert rec.full_path(ignore_dos=True) == "Users\\bob\\secret.docx"
        assert rec.size() == 12345
        assert rec.dataruns() == [(100, 3)]
        assert ntfs.mft.get(SEG_NOTES).resident is True
        assert ntfs.mft.get(25).is_dir()
        assert ntfs.mft.get(0).size() == 34 * RECORD_SIZE


# ---------- parser ----------------------------------------------------------------


def _by_name(events) -> dict[str, object]:
    return {e.evidence["deleted_name"]: e for e in events}


def test_parse_mft_deleted_emits_unallocated_named_records(tmp_path: Path) -> None:
    mft, sds = write_volume(tmp_path)
    events = parse_mft_deleted(
        str(mft), collection_id="c", host_id_hint="HOST", sds_path=str(sds),
    )
    assert all(e.event_type == "file_delete" for e in events)
    assert all(e.source_artifact == "mft" for e in events)
    assert all(e.timestamp_source == "inferred" for e in events)
    by_name = _by_name(events)
    assert set(by_name) == {"secret.docx", "notes.txt", "orphan.bin", "olddir"}

    secret = by_name["secret.docx"]
    ev = secret.evidence
    assert ev["original_path"] == r"C:\Users\bob\secret.docx"
    assert ev["deleted_size"] == 12345
    assert ev["deletion_method"] == "mft_unallocated"
    assert ev["owner_sid"] == SID_BOB
    assert ev["actor_sid"] is None
    assert ev["security_id"] == SECID_BOB
    assert ev["mft_segment"] == SEG_SECRET
    assert ev["is_directory"] is False
    assert ev["recoverable_hint"] == "data_runs_present"
    assert ev["usn"] is None and ev["usn_reason"] is None
    assert ev["last_known_modified"] == "2024-03-02T10:30:00Z"
    assert ev["last_known_created"] == "2024-03-01T09:00:00Z"
    assert secret.timestamp == "2024-03-05T14:15:16Z"
    assert secret.summary == "Deleted (last existed by 2024-03-05T14:15:16Z): secret.docx (12.1 KB)"
    assert secret.raw["sequence_number"] == SEQ_SECRET
    assert secret.raw["time_basis"] == "$STANDARD_INFORMATION.LastChangeTime"

    notes = by_name["notes.txt"].evidence
    assert notes["recoverable_hint"] == "resident"
    assert notes["deleted_size"] == 5
    assert notes["owner_sid"] == SID_ALICE
    assert by_name["notes.txt"].timestamp == "2024-04-01T00:00:00Z"

    olddir = by_name["olddir"].evidence
    assert olddir["is_directory"] is True
    assert olddir["deleted_size"] is None
    assert olddir["recoverable_hint"] == "unknown"
    assert olddir["original_path"] == r"C:\Users\bob\olddir"

    orphan = by_name["orphan.bin"].evidence
    assert orphan["recoverable_hint"] == "unknown"  # only a sparse run
    assert orphan["original_path"].startswith("C:\\<broken_reference_0x19#")
    assert orphan["original_path"].endswith("\\orphan.bin")


def test_without_sds_owner_is_unknown(tmp_path: Path) -> None:
    mft, _ = write_volume(tmp_path)
    events = parse_mft_deleted(str(mft), collection_id="c", host_id_hint="H")
    assert {e.evidence["deleted_name"] for e in events} == {
        "secret.docx", "notes.txt", "orphan.bin", "olddir",
    }
    assert all(e.evidence["owner_sid"] is None for e in events)
    assert all(e.evidence["security_id"] in (SECID_BOB, SECID_ALICE, None) for e in events)


def test_unknown_security_id_does_not_crash(tmp_path: Path) -> None:
    mft = tmp_path / "$MFT"
    sds = tmp_path / "$SDS"
    mft.write_bytes(build_volume_mft())
    sds.write_bytes(build_sds({0x999: SID_ALICE}))  # none of our ids
    events = parse_mft_deleted(str(mft), collection_id="c", host_id_hint="H", sds_path=str(sds))
    assert len(events) == 4
    assert all(e.evidence["owner_sid"] is None for e in events)


def test_drive_letter_variants(tmp_path: Path) -> None:
    mft, _ = write_volume(tmp_path)
    def run(letter: str):
        return _by_name(parse_mft_deleted(
            str(mft), collection_id="c", host_id_hint="H", drive_letter=letter,
        ))

    assert run("D:")["notes.txt"].evidence["original_path"] == r"D:\Users\bob\notes.txt"
    assert run("")["notes.txt"].evidence["original_path"] == r"\Users\bob\notes.txt"


def test_in_use_system_and_broken_records_are_skipped(tmp_path: Path) -> None:
    """Garbage slot, zero-length attribute, nameless record, in-use file: none emit."""
    mft, _ = write_volume(tmp_path)
    with mft.open("rb") as fh:
        ntfs = NTFS(mft=fh)
        records = list(iter_mft_records(ntfs.mft))
        segments = {r.segment for r in records}
        # Garbage and empty slots never parse; the zero-RecordLength one parses
        # as a record but blows up on .attributes, which the event loop absorbs.
        assert SEG_GARBAGE not in segments
        assert SEG_BROKEN in segments
        events = events_from_records(
            records, secure=None, source_path="x", collection_id="c", host_id_hint="H",
        )
    segs = {e.evidence["mft_segment"] for e in events}
    assert segs == {SEG_SECRET, SEG_NOTES, SEG_ORPHAN, SEG_OLDDIR}
    assert SEG_KEEP not in segs and SEG_NONAME not in segs and SEG_BROKEN not in segs
    assert 0 not in segs and 5 not in segs


def test_missing_mft_file_returns_empty(tmp_path: Path) -> None:
    assert parse_mft_deleted(str(tmp_path / "nope"), collection_id="c", host_id_hint="H") == []


def test_truncated_mft_stops_cleanly(tmp_path: Path) -> None:
    data = build_volume_mft()
    mft = tmp_path / "$MFT"
    mft.write_bytes(data[: SEG_NOTES * RECORD_SIZE + 300])  # cut through notes.txt
    names = {e.evidence["deleted_name"] for e in
             parse_mft_deleted(str(mft), collection_id="c", host_id_hint="H")}
    assert names == {"secret.docx"}


# ---------- target variant ------------------------------------------------------


class _FakeNtfsFs:
    def __init__(self, ntfs: NTFS) -> None:
        self.ntfs = ntfs


class _FakeTarget:
    def __init__(self, *filesystems) -> None:
        self.filesystems = list(filesystems)


def test_parse_mft_deleted_from_target_uses_fs_ntfs() -> None:
    ntfs = NTFS(mft=io.BytesIO(build_volume_mft()), sds=io.BytesIO(build_volume_sds()))
    target = _FakeTarget(object(), _FakeNtfsFs(ntfs))
    events = parse_mft_deleted_from_target(
        target, 1, collection_id="c", host_id_hint="H", drive_letter="C:",
    )
    by_name = _by_name(events)
    assert by_name["secret.docx"].evidence["owner_sid"] == SID_BOB
    assert by_name["secret.docx"].source_path == r"C:\$MFT"
    # Index 0 is not NTFS; a bad index is not an error either.
    assert parse_mft_deleted_from_target(target, 0, collection_id="c", host_id_hint="H") == []
    assert parse_mft_deleted_from_target(target, 9, collection_id="c", host_id_hint="H") == []


def test_from_target_sds_path_overrides_live_secure(tmp_path: Path) -> None:
    sds = tmp_path / "$SDS"
    sds.write_bytes(build_sds({SECID_BOB: SID_ALICE}))  # deliberately swapped
    ntfs = NTFS(mft=io.BytesIO(build_volume_mft()), sds=io.BytesIO(build_volume_sds()))
    events = parse_mft_deleted_from_target(
        _FakeTarget(_FakeNtfsFs(ntfs)), 0, collection_id="c", host_id_hint="H",
        sds_path=str(sds),
    )
    assert _by_name(events)["secret.docx"].evidence["owner_sid"] == SID_ALICE

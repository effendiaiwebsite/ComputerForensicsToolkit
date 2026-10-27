"""NTFS USN change journal (``$Extend\\$UsnJrnl:$J``) parser.

The journal logs every create / rename / delete on the volume with an exact
timestamp, including Shift+Delete and programmatic deletes that never touch
the Recycle Bin. Each record names the file (not its path) plus the MFT
references of the file and its parent; with an ``$MFT`` available the parent
chain is walked to rebuild the full path, otherwise the parent is reported as
``<unresolved>``.

Emitted events:

* ``file_delete`` for ``FILE_DELETE`` records (keyed on the closing record)
* ``file_rename`` for ``RENAME_OLD_NAME`` records, paired with the following
  ``RENAME_NEW_NAME`` record of the same file reference to fill ``new_path``
* ``file_create`` for ``FILE_CREATE`` records (off by default: noisy)

Only v2 records are decoded (v3/v4 appear on ReFS / Windows 10 1709+ volumes
with 128-bit ids and are skipped by length). Owner SIDs come from
``$Secure:$SDS`` via the record's ``SecurityId``.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from dissect.ntfs import Secure, UsnJrnl, UsnRecord
from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE, USN_PAGE_SIZE, c_ntfs
from dissect.ntfs.util import segment_reference

from core.events import Event, make_event
from parsers._time import to_iso_utc
from parsers.browser import _clip, _human_bytes
from parsers.mft import (
    ntfs_of,
    open_ntfs_streams,
    owner_sid_for,
    recoverable_hint_for,
    with_drive,
)

PARSER_VERSION = "usnjrnl/0.1.0"
HOST_OS = "windows"
SOURCE_ARTIFACT = "usnjrnl"

logger = logging.getLogger(__name__)

_REASON_BITS: tuple[tuple[int, str], ...] = tuple(
    sorted(((int(m.value), m.name) for m in c_ntfs.USN_REASON), key=lambda t: t[0]),
)
_FILE_CREATE = int(c_ntfs.USN_REASON.FILE_CREATE)
_FILE_DELETE = int(c_ntfs.USN_REASON.FILE_DELETE)
_RENAME_OLD = int(c_ntfs.USN_REASON.RENAME_OLD_NAME)
_RENAME_NEW = int(c_ntfs.USN_REASON.RENAME_NEW_NAME)
_CLOSE = int(c_ntfs.USN_REASON.CLOSE)
_ATTR_DIRECTORY = int(c_ntfs.FILE_ATTRIBUTE.DIRECTORY)

_V2_HEADER_SIZE = 60  # sizeof(USN_RECORD_V2) before the file name
_COMMON_HEADER = struct.Struct("<IHH")  # RecordLength, MajorVersion, MinorVersion


def parse_usnjrnl(
    j_path: str,
    *,
    collection_id: str,
    host_id_hint: str,
    mft_path: str | None = None,
    sds_path: str | None = None,
    drive_letter: str = "C:",
    include_creates: bool = False,
    include_renames: bool = True,
) -> list[Event]:
    """Parse an extracted ``$J`` stream; ``$MFT`` / ``$SDS`` are optional helpers."""
    j_str = str(Path(j_path).resolve())
    with ExitStack() as stack:
        try:
            ntfs = open_ntfs_streams(
                stack, mft_path=mft_path, usnjrnl_path=j_str, sds_path=sds_path,
            )
        except OSError:
            logger.exception("could not open USN journal inputs (%s, %s)", j_str, mft_path)
            return []
        if ntfs.usnjrnl is None:
            return []
        return _events_from_journal(
            ntfs.usnjrnl,
            secure=ntfs.secure,
            have_mft=ntfs.mft is not None,
            source_path=j_str,
            collection_id=collection_id,
            host_id_hint=host_id_hint,
            drive_letter=drive_letter,
            include_creates=include_creates,
            include_renames=include_renames,
        )


def parse_usnjrnl_from_target(
    target: Any,
    fs_index: int,
    *,
    collection_id: str,
    host_id_hint: str,
    mft_path: str | None = None,
    sds_path: str | None = None,
    drive_letter: str = "C:",
    include_creates: bool = False,
    include_renames: bool = True,
) -> list[Event]:
    """Same as :func:`parse_usnjrnl`, reading ``target.filesystems[fs_index].ntfs.usnjrnl``.

    ``mft_path`` is ignored (the live MFT is used); ``sds_path`` overrides the
    live ``$Secure`` only when given.
    """
    ntfs = ntfs_of(target, fs_index)
    if ntfs is None or ntfs.usnjrnl is None:
        return []
    with ExitStack() as stack:
        secure = ntfs.secure
        if sds_path:
            try:
                secure = Secure(sds=stack.enter_context(Path(sds_path).open("rb")))
            except (OSError, ValueError):
                logger.exception("could not open $SDS %s", sds_path)
        return _events_from_journal(
            ntfs.usnjrnl,
            secure=secure,
            have_mft=ntfs.mft is not None,
            source_path=with_drive(drive_letter, "$Extend\\$UsnJrnl:$J"),
            collection_id=collection_id,
            host_id_hint=host_id_hint,
            drive_letter=drive_letter,
            include_creates=include_creates,
            include_renames=include_renames,
        )


# ---------- robust record iteration ---------------------------------------


def iter_usn_records(jrnl: UsnJrnl) -> Iterator[UsnRecord]:
    """Yield v2 records, resynchronising on the next 4 KiB page after garbage.

    ``UsnJrnl.records()`` aborts the whole walk on the first malformed record;
    a triage parser must keep going, so the page walk is done here and only
    plausible offsets are handed to ``UsnRecord``.
    """
    fh = jrnl.fh
    offset = _leading_sparse_bytes(fh)
    size = _stream_size(fh)
    while offset < size:
        fh.seek(offset)
        head = fh.read(_COMMON_HEADER.size)
        if len(head) < _COMMON_HEADER.size:
            break
        if head[:4] == b"\x00\x00\x00\x00":
            offset = _next_page(offset)
            continue
        length, major, _minor = _COMMON_HEADER.unpack(head)
        page_left = USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)
        if length < _COMMON_HEADER.size or length > page_left or length % 8:
            logger.debug("USN: implausible record length %d at 0x%x; skipping page", length, offset)
            offset = _next_page(offset)
            continue
        if offset + length > size:
            logger.debug("USN: truncated trailing record at 0x%x", offset)
            break
        if major == 2 and length >= _V2_HEADER_SIZE:
            try:
                yield UsnRecord(jrnl, fh, offset)
            except EOFError:
                break
            except Exception as exc:
                logger.debug("USN: unreadable record at 0x%x: %s", offset, exc)
        offset += length
        if offset % 8:
            offset += -offset & 7


def _leading_sparse_bytes(fh: Any) -> int:
    runlist = getattr(fh, "runlist", None)
    block_size = getattr(fh, "block_size", None)
    if not runlist or not block_size:
        return 0
    skipped = 0
    for run_offset, run_size in runlist:
        if run_offset is not None:
            break
        skipped += run_size * block_size
    return skipped


def _stream_size(fh: Any) -> int:
    size = getattr(fh, "size", None)
    if isinstance(size, int):
        return size
    pos = fh.tell()
    end = fh.seek(0, 2)
    fh.seek(pos)
    return end


def _next_page(offset: int) -> int:
    return offset + USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)


def decode_reason(value: int) -> list[str]:
    """``0x80000200`` → ``["FILE_DELETE", "CLOSE"]``; unknown bits become ``0x...``."""
    value = int(value)
    names: list[str] = []
    known = 0
    for bit, name in _REASON_BITS:
        if value & bit:
            names.append(name)
            known |= bit
    rest = value & ~known
    if rest:
        names.append(f"0x{rest:08x}")
    return names


# ---------- record → event -------------------------------------------------


def _events_from_journal(
    jrnl: UsnJrnl,
    *,
    secure: Any,
    have_mft: bool,
    source_path: str,
    collection_id: str,
    host_id_hint: str,
    drive_letter: str,
    include_creates: bool,
    include_renames: bool,
) -> list[Event]:
    emitter = _Emitter(
        secure=secure, have_mft=have_mft, source_path=source_path,
        collection_id=collection_id, host_id_hint=host_id_hint, drive_letter=drive_letter,
        include_creates=include_creates, include_renames=include_renames,
    )
    for record in iter_usn_records(jrnl):
        try:
            emitter.feed(record)
        except Exception:
            logger.warning("skipping broken USN record at 0x%x", record.offset, exc_info=True)
    return emitter.finish()


class _Emitter:
    def __init__(
        self, *, secure: Any, have_mft: bool, source_path: str, collection_id: str,
        host_id_hint: str, drive_letter: str, include_creates: bool, include_renames: bool,
    ) -> None:
        self._secure = secure
        self._have_mft = have_mft
        self._source_path = source_path
        self._collection_id = collection_id
        self._host_id = host_id_hint
        self._drive = drive_letter
        self._creates = include_creates
        self._renames = include_renames
        self.events: list[Event] = []
        # FILE_DELETE / FILE_CREATE without CLOSE: hold until the closing
        # record arrives (which repeats the flag) so each operation emits once.
        self._pending_delete: dict[tuple[int, int], Event] = {}
        self._pending_create: dict[tuple[int, int], Event] = {}
        # RENAME_OLD_NAME events waiting for their RENAME_NEW_NAME partner.
        self._pending_rename: dict[tuple[int, int], Event] = {}

    def feed(self, record: UsnRecord) -> None:
        reason = int(record.record.Reason)
        if not reason & (_FILE_DELETE | _FILE_CREATE | _RENAME_OLD | _RENAME_NEW):
            return
        key = _ref_key(record.record.FileReferenceNumber)
        closing = bool(reason & _CLOSE)

        if reason & _FILE_DELETE:
            ev = self._delete_event(record)
            if closing:
                self._pending_delete.pop(key, None)
                self.events.append(ev)
            else:
                self._pending_delete[key] = ev

        if self._creates and reason & _FILE_CREATE:
            ev = self._simple_event(record, "file_create", "Created")
            if closing:
                self._pending_create.pop(key, None)
                self.events.append(ev)
            else:
                self._pending_create[key] = ev

        if self._renames and reason & _RENAME_OLD:
            ev = self._simple_event(record, "file_rename", "Renamed")
            ev.evidence["new_path"] = None
            self._pending_rename[key] = ev
            self.events.append(ev)
        elif self._renames and reason & _RENAME_NEW:
            ev = self._pending_rename.pop(key, None)
            if ev is not None:
                new_path = self._path_for(record)
                ev.evidence["new_path"] = new_path
                ev.summary = (
                    f"Renamed: {_clip(ev.evidence['deleted_name'], 60)} → "
                    f"{_clip(record.filename, 60)} (USN)"
                )
                ev.raw["new_name_usn"] = int(record.record.Usn)

    def finish(self) -> list[Event]:
        self.events.extend(self._pending_delete.values())
        self.events.extend(self._pending_create.values())
        self._pending_delete.clear()
        self._pending_create.clear()
        self._pending_rename.clear()
        return self.events

    # -- builders --

    def _delete_event(self, record: UsnRecord) -> Event:
        rec = record.record
        name = record.filename
        attrs = int(rec.FileAttributes)
        is_directory = bool(attrs & _ATTR_DIRECTORY)
        size, hint = self._ghost_info(record, is_directory)
        security_id = int(rec.SecurityId) or None
        size_str = f", {_human_bytes(size)}" if size else ""
        summary = f"Deleted: {_clip(name, 90)} (USN{size_str})"
        return make_event(
            host_os=HOST_OS,
            host_id=self._host_id,
            source_artifact=SOURCE_ARTIFACT,
            source_path=self._source_path,
            event_type="file_delete",
            summary=summary,
            evidence={
                "original_path": self._path_for(record),
                "deleted_name": name,
                "deleted_size": size,
                "deletion_method": "usn_journal",
                "owner_sid": owner_sid_for(self._secure, security_id),
                "actor_sid": None,
                "security_id": security_id,
                "mft_segment": segment_reference(rec.FileReferenceNumber),
                "is_directory": is_directory,
                "recoverable_hint": hint,
                "usn": int(rec.Usn),
                "usn_reason": decode_reason(rec.Reason),
                "last_known_modified": None,
                "last_known_created": None,
            },
            collection_id=self._collection_id,
            parser_version=PARSER_VERSION,
            timestamp=_record_time(record),
            raw=_raw(record),
        )

    def _simple_event(self, record: UsnRecord, event_type: str, verb: str) -> Event:
        rec = record.record
        name = record.filename
        return make_event(
            host_os=HOST_OS,
            host_id=self._host_id,
            source_artifact=SOURCE_ARTIFACT,
            source_path=self._source_path,
            event_type=event_type,
            summary=f"{verb}: {_clip(name, 90)} (USN)",
            evidence={
                "original_path": self._path_for(record),
                "deleted_name": name,
                "usn": int(rec.Usn),
                "usn_reason": decode_reason(rec.Reason),
                "mft_segment": segment_reference(rec.FileReferenceNumber),
                "is_directory": bool(int(rec.FileAttributes) & _ATTR_DIRECTORY),
            },
            collection_id=self._collection_id,
            parser_version=PARSER_VERSION,
            timestamp=_record_time(record),
            raw=_raw(record),
        )

    def _path_for(self, record: UsnRecord) -> str:
        name = record.filename
        rel: str | None = None
        if self._have_mft:
            try:
                rel = record.full_path
            except Exception:
                rel = None
        if not rel:
            rel = f"<unresolved>\\{name}"
        rel = rel.replace("/", "\\").lstrip("\\")
        if rel.startswith(".\\"):
            rel = rel[2:]
        return with_drive(self._drive, rel)

    def _ghost_info(self, record: UsnRecord, is_directory: bool) -> tuple[int | None, str]:
        """Size and recoverability from the file's MFT record, if it is still the same ghost."""
        if not self._have_mft or is_directory:
            return None, "unknown"
        try:
            ghost = record.file
        except Exception:
            return None, "unknown"
        if ghost is None:
            return None, "unknown"
        if ghost.header.SequenceNumber != record.record.FileReferenceNumber.SequenceNumber:
            return None, "unknown"  # slot reused by another file since the delete
        if ghost.header.Flags & FILE_RECORD_SEGMENT_IN_USE:
            return None, "unknown"
        size: int | None
        try:
            size = int(ghost.size())
        except Exception:
            size = None
        try:
            hint = recoverable_hint_for(ghost)
        except Exception:
            hint = "unknown"
        return size, hint


def _ref_key(ref: Any) -> tuple[int, int]:
    return segment_reference(ref), int(ref.SequenceNumber)


def _record_time(record: UsnRecord) -> str | None:
    try:
        return to_iso_utc(record.timestamp)
    except Exception:
        logger.debug("USN: bad timestamp 0x%x", int(record.record.TimeStamp))
        return None


def _raw(record: UsnRecord) -> dict[str, Any]:
    rec = record.record
    fref, pref = rec.FileReferenceNumber, rec.ParentFileReferenceNumber
    return {
        "usn": int(rec.Usn),
        "reason": int(rec.Reason),
        "source_info": int(rec.SourceInfo),
        "file_attributes": int(rec.FileAttributes),
        "file_ref": f"{segment_reference(fref)}#{int(fref.SequenceNumber)}",
        "parent_ref": f"{segment_reference(pref)}#{int(pref.SequenceNumber)}",
        "offset": record.offset,
    }


__all__ = [
    "decode_reason",
    "iter_usn_records",
    "parse_usnjrnl",
    "parse_usnjrnl_from_target",
]

"""``$MFT`` unallocated-record parser: files that existed and whose record is now free.

When NTFS deletes a file it clears the ``IN_USE`` flag on the file's MFT
record but leaves the attributes in place until the slot is reused. Those
"ghost" records still carry ``$FILE_NAME`` (name, parent reference, size) and
``$STANDARD_INFORMATION`` (timestamps, security id), which is enough to say
*what* was deleted and *by when* it last existed - never exactly when it was
deleted. Every event is therefore ``timestamp_source="inferred"`` and the
summary says so.

Owner SIDs come from ``$Secure:$SDS`` (``security_id`` → descriptor → owner),
mirroring ``dissect.target``'s ``get_owner_and_group``.

Two entry points share one record loop: :func:`parse_mft_deleted` works on an
extracted ``$MFT`` (plus optional ``$SDS``), and
:func:`parse_mft_deleted_from_target` on the live NTFS filesystem of an open
``dissect.target.Target``.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Iterable, Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any, BinaryIO

from dissect.ntfs import NTFS, Mft, MftRecord, Secure
from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    FILE_NUMBER_MFT,
    FILE_NUMBER_ROOT,
    FILE_RECORD_SEGMENT_IN_USE,
)
from dissect.ntfs.util import segment_reference

from core.events import Event, make_event
from parsers._time import to_iso_utc
from parsers.browser import _clip, _human_bytes

PARSER_VERSION = "mft/0.1.0"
HOST_OS = "windows"
SOURCE_ARTIFACT = "mft"

logger = logging.getLogger(__name__)

# NTFS reserves the first 24 records for metadata files ($MFT, $LogFile, ...);
# a user file never lands there, so unallocated slots in that range are noise.
_FIRST_USER_SEGMENT = 24


def parse_mft_deleted(
    mft_path: str,
    *,
    collection_id: str,
    host_id_hint: str,
    sds_path: str | None = None,
    drive_letter: str = "C:",
) -> list[Event]:
    """One ``file_delete`` per unallocated MFT record that still has a ``$FILE_NAME``."""
    mft_str = str(Path(mft_path).resolve())
    with ExitStack() as stack:
        try:
            ntfs = open_ntfs_streams(stack, mft_path=mft_str, sds_path=sds_path)
        except OSError:
            logger.exception("could not open $MFT %s", mft_str)
            return []
        if ntfs.mft is None:
            return []
        return events_from_records(
            iter_mft_records(ntfs.mft),
            secure=ntfs.secure,
            source_path=mft_str,
            collection_id=collection_id,
            host_id_hint=host_id_hint,
            drive_letter=drive_letter,
        )


def parse_mft_deleted_from_target(
    target: Any,
    fs_index: int,
    *,
    collection_id: str,
    host_id_hint: str,
    sds_path: str | None = None,
    drive_letter: str = "C:",
) -> list[Event]:
    """Same as :func:`parse_mft_deleted`, reading ``target.filesystems[fs_index].ntfs``."""
    ntfs = ntfs_of(target, fs_index)
    if ntfs is None or ntfs.mft is None:
        return []
    secure = ntfs.secure
    with ExitStack() as stack:
        if sds_path:
            try:
                secure = Secure(sds=_open_rb(stack, sds_path))
            except (OSError, ValueError):
                logger.exception("could not open $SDS %s", sds_path)
        return events_from_records(
            iter_mft_records(ntfs.mft),
            secure=secure,
            source_path=with_drive(drive_letter, "$MFT"),
            collection_id=collection_id,
            host_id_hint=host_id_hint,
            drive_letter=drive_letter,
        )


# ---------- shared NTFS helpers (also used by parsers.usnjrnl) ---------------


def open_ntfs_streams(
    stack: ExitStack,
    *,
    mft_path: str | None = None,
    usnjrnl_path: str | None = None,
    sds_path: str | None = None,
) -> NTFS:
    """Build an :class:`NTFS` from loose extracted streams (no boot sector needed).

    File handles are registered on ``stack`` so the caller controls lifetime.
    A missing/unreadable optional stream degrades to ``None`` on the NTFS
    object rather than failing the whole parse.
    """
    mft_fh = _open_rb(stack, mft_path) if mft_path else None
    usn_fh = _open_rb(stack, usnjrnl_path) if usnjrnl_path else None
    sds_fh: BinaryIO | None = None
    if sds_path:
        try:
            sds_fh = _open_rb(stack, sds_path)
        except OSError:
            logger.exception("could not open $SDS %s; owner SIDs unavailable", sds_path)
    return NTFS(mft=mft_fh, usnjrnl=usn_fh, sds=sds_fh)


def _open_rb(stack: ExitStack, path: str) -> BinaryIO:
    return stack.enter_context(Path(path).open("rb"))


def ntfs_of(target: Any, fs_index: int) -> NTFS | None:
    """Return ``target.filesystems[fs_index].ntfs`` or ``None`` if that is not an NTFS fs."""
    try:
        fs = target.filesystems[fs_index]
    except (AttributeError, IndexError, TypeError):
        logger.warning("target has no filesystem at index %s", fs_index)
        return None
    ntfs = getattr(fs, "ntfs", None)
    if ntfs is None:
        logger.warning("filesystem %s is not NTFS (%s)", fs_index, type(fs).__name__)
    return ntfs


def owner_sid_for(secure: Any, security_id: int | None) -> str | None:
    """Resolve an NTFS security id to its owner SID via ``$Secure``; ``None`` when unknown."""
    if secure is None or not security_id:
        return None
    try:
        descriptor = secure.lookup(security_id)
    except Exception:  # KeyError for unknown ids; anything else is a broken $SDS
        return None
    owner = getattr(descriptor, "owner", None)
    return str(owner) if owner else None


def iter_mft_records(mft: Mft) -> Iterator[MftRecord]:
    """Yield every parseable record in ``mft``; unparseable slots are skipped."""
    record_size = mft.ntfs._record_size if mft.ntfs else 1024
    count = _record_count(mft, record_size)
    for segment in range(count):
        try:
            yield mft.get(segment)
        except EOFError:
            return
        except Exception as exc:
            logger.debug("MFT segment %d unreadable: %s", segment, exc)
            continue


def _record_count(mft: Mft, record_size: int) -> int:
    try:
        return mft.get(FILE_NUMBER_MFT).size() // record_size
    except Exception:
        pass
    fh = mft.fh
    try:
        pos = fh.tell()
        end = fh.seek(0, io.SEEK_END)
        fh.seek(pos)
        return end // record_size
    except Exception:
        return 0


# ---------- record → event -------------------------------------------------


def events_from_records(
    records: Iterable[MftRecord],
    *,
    secure: Any,
    source_path: str,
    collection_id: str,
    host_id_hint: str,
    drive_letter: str = "C:",
) -> list[Event]:
    """Unallocated records → ``file_delete`` events; broken records are logged and skipped."""
    events: list[Event] = []
    for record in records:
        try:
            ev = _event_for_record(
                record,
                secure=secure,
                source_path=source_path,
                collection_id=collection_id,
                host_id_hint=host_id_hint,
                drive_letter=drive_letter,
            )
        except Exception:
            logger.warning(
                "skipping broken MFT record %s", getattr(record, "segment", "?"),
            )
            continue
        if ev is not None:
            events.append(ev)
    return events


def _event_for_record(
    record: MftRecord,
    *,
    secure: Any,
    source_path: str,
    collection_id: str,
    host_id_hint: str,
    drive_letter: str,
) -> Event | None:
    header = record.header
    if header.Flags & FILE_RECORD_SEGMENT_IN_USE:
        return None
    if segment_reference(header.BaseFileRecordSegment) != 0:
        return None  # extension record of a multi-record file; the base record carries the name
    segment = record.segment
    if segment is not None and segment < _FIRST_USER_SEGMENT:
        return None

    file_names = record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]
    if not file_names:
        return None
    fn = _preferred_filename(file_names)
    name = fn.file_name
    if not name or name == ".":
        return None
    parent_ref = fn.attr.ParentDirectory
    if name.startswith("$") and segment_reference(parent_ref) == FILE_NUMBER_ROOT:
        return None  # $MFT, $LogFile, $Bitmap ... live in the root and are never "deleted"

    rel_path = _relative_path(fn)
    if not rel_path:
        return None
    original_path = with_drive(drive_letter, rel_path)

    std_info = record.attributes[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION]
    si = std_info[0] if std_info else None
    si_change = _ts(si, "last_change_time")
    fn_change = _ts(fn, "last_change_time")
    last_existed = si_change or fn_change
    time_basis = "$STANDARD_INFORMATION.LastChangeTime" if si_change else (
        "$FILE_NAME.LastChangeTime" if fn_change else None
    )

    security_id = (int(si.security_id) or None) if si is not None else None
    is_directory = bool(record.is_dir() or fn.is_dir())
    size = None if is_directory else _data_size(record, fn)
    hint = "unknown" if is_directory else recoverable_hint_for(record)

    when = last_existed or "time unknown"
    size_str = f" ({_human_bytes(size)})" if size else ""
    summary = f"Deleted (last existed by {when}): {_clip(name, 90)}{size_str}"

    return make_event(
        host_os=HOST_OS,
        host_id=host_id_hint,
        source_artifact=SOURCE_ARTIFACT,
        source_path=source_path,
        event_type="file_delete",
        summary=summary,
        evidence={
            "original_path": original_path,
            "deleted_name": name,
            "deleted_size": size,
            "deletion_method": "mft_unallocated",
            "owner_sid": owner_sid_for(secure, security_id),
            "actor_sid": None,
            "security_id": security_id,
            "mft_segment": segment,
            "is_directory": is_directory,
            "recoverable_hint": hint,
            "usn": None,
            "usn_reason": None,
            "last_known_modified": _ts(si, "last_modification_time"),
            "last_known_created": _ts(si, "creation_time"),
        },
        collection_id=collection_id,
        parser_version=PARSER_VERSION,
        timestamp=last_existed,
        timestamp_source="inferred" if last_existed else "none",
        raw={
            "sequence_number": int(header.SequenceNumber),
            "record_flags": int(header.Flags),
            "time_basis": time_basis,
            "filename_count": len(file_names),
            "parent_segment": segment_reference(parent_ref),
            "parent_sequence": int(parent_ref.SequenceNumber),
            "fn_times": {
                "created": _ts(fn, "creation_time"),
                "modified": _ts(fn, "last_modification_time"),
                "changed": fn_change,
                "accessed": _ts(fn, "last_access_time"),
            },
            "si_times": {
                "created": _ts(si, "creation_time"),
                "modified": _ts(si, "last_modification_time"),
                "changed": si_change,
                "accessed": _ts(si, "last_access_time"),
            },
        },
    )


def _preferred_filename(file_names: list[Any]) -> Any:
    # Flags: 1 = NTFS (long) name, 2 = DOS 8.3 name, 3 = both. Prefer long names.
    return sorted(file_names, key=lambda a: (a.flags == 2, a.flags))[0]


def _relative_path(fn: Any) -> str | None:
    try:
        path = fn.full_path()
    except Exception:
        path = None
    if not path:
        path = fn.file_name
    path = path.replace("/", "\\").lstrip("\\")
    if path.startswith(".\\"):
        path = path[2:]
    return path or None


def with_drive(drive_letter: str | None, rel_path: str) -> str:
    """``("C:", "Users\\\\x")`` → ``C:\\Users\\x``; no drive letter → ``\\Users\\x``."""
    rel = rel_path.lstrip("\\")
    if drive_letter:
        return f"{drive_letter.rstrip(chr(92))}\\{rel}"
    return f"\\{rel}"


def _ts(attr: Any, field: str) -> str | None:
    if attr is None:
        return None
    try:
        return to_iso_utc(getattr(attr, field))
    except Exception:
        return None


def _data_size(record: MftRecord, fn: Any) -> int | None:
    try:
        return int(record.size())
    except Exception:
        pass
    try:
        size = int(fn.file_size)
    except Exception:
        return None
    return size if size >= 0 else None


def recoverable_hint_for(record: MftRecord) -> str:
    """``resident`` / ``data_runs_present`` / ``unknown`` from the record's default ``$DATA``."""
    data_attrs = record.attributes.find("", ATTRIBUTE_TYPE_CODE.DATA)
    if not data_attrs:
        return "unknown"
    try:
        if data_attrs.header.resident:
            return "resident"
        runs = data_attrs.dataruns()
    except Exception:
        return "unknown"
    if any(offset is not None and length > 0 for offset, length in runs):
        return "data_runs_present"
    return "unknown"


__all__ = [
    "events_from_records",
    "iter_mft_records",
    "ntfs_of",
    "open_ntfs_streams",
    "owner_sid_for",
    "parse_mft_deleted",
    "parse_mft_deleted_from_target",
    "recoverable_hint_for",
    "with_drive",
]

"""Windows Recycle Bin ``$I`` metadata parser.

When a file is sent to the Recycle Bin on Vista+ it is split into two entries
under ``C:\\$Recycle.Bin\\<SID>\\``:

* ``$I<id>[.ext]`` — a small fixed/variable metadata record (original path,
  original size, deletion timestamp)
* ``$R<id>[.ext]`` — the recoverable file content

We parse the ``$I`` record and emit one ``file_delete`` event per deleted item.
The ``$R`` sibling name is derived so an examiner knows which blob to recover.

Two on-disk formats exist:

* **version 1** (Vista - Windows 8.1): ``[int64 version=1][int64 size]``
  ``[int64 FILETIME][520-byte fixed UTF-16LE path]`` — 544 bytes total.
* **version 2** (Windows 10 1709+): same header, then ``[uint32 path_chars]``
  ``[UTF-16LE path]`` — variable length.

Timestamps are Windows FILETIME (100 ns since 1601-01-01 UTC).
"""

from __future__ import annotations

import logging
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

from core.events import Event, make_event
from parsers.browser import _clip, _human_bytes

PARSER_VERSION = "recycle_bin/0.1.0"
HOST_OS = "windows"
SOURCE_ARTIFACT = "recycle_bin"

logger = logging.getLogger(__name__)

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_HEADER = struct.Struct("<qqq")  # version, original_size, deletion_filetime


def parse_recycle_bin(
    i_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    path_str = str(Path(i_path).resolve())
    try:
        data = Path(path_str).read_bytes()
    except OSError:
        logger.exception("could not read $I file %s", path_str)
        return []

    parsed = _parse_i_record(data)
    if parsed is None:
        logger.warning("not a recognizable $I record: %s", path_str)
        return []
    version, orig_size, del_ts, original_path = parsed

    basename = Path(path_str).name
    recovered = "$R" + basename[2:] if basename.startswith("$I") else None
    sid = _sid_from_path(path_str)
    deleted_name = _basename_of(original_path)

    size_str = f" ({_human_bytes(orig_size)})" if orig_size else ""
    summary = f"Deleted: {_clip(deleted_name or original_path, 90)}{size_str}"

    return [make_event(
        host_os=HOST_OS,
        host_id=host_id_hint,
        source_artifact=SOURCE_ARTIFACT,
        source_path=path_str,
        event_type="file_delete",
        summary=summary,
        evidence={
            "original_path": original_path,
            "deleted_name": deleted_name,
            "deleted_size": orig_size,
            "recovered_name": recovered,
            "sid": sid,
            "format_version": version,
        },
        collection_id=collection_id,
        parser_version=PARSER_VERSION,
        timestamp=del_ts,
        user=user_hint,
        raw={"i_filename": basename, "format_version": version},
    )]


def _parse_i_record(data: bytes) -> tuple[int, int, str | None, str] | None:
    if len(data) < _HEADER.size + 2:
        return None
    version, orig_size, filetime = _HEADER.unpack_from(data, 0)
    if version == 1:
        # Fixed 520-byte (260 wchar) path field follows the 24-byte header.
        path_bytes = data[24:24 + 520]
    elif version == 2:
        if len(data) < 28:
            return None
        (char_count,) = struct.unpack_from("<I", data, 24)
        path_bytes = data[28:28 + char_count * 2]
    else:
        return None
    original_path = _decode_utf16z(path_bytes)
    if not original_path:
        return None
    return version, orig_size, _filetime_to_iso(filetime), original_path


def _decode_utf16z(raw: bytes) -> str:
    try:
        text = raw.decode("utf-16-le", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""
    return text.split("\x00", 1)[0].strip()


def _filetime_to_iso(filetime: int) -> str | None:
    if not filetime or filetime <= 0:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except (OverflowError, ValueError):
        return None
    if dt.year < 1970 or dt.year > 9000:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _basename_of(original_path: str) -> str:
    if not original_path:
        return ""
    # Original paths are Windows-style (C:\...); fall back to POSIX if needed.
    name = PureWindowsPath(original_path).name
    return name or PurePosixPath(original_path).name


def _sid_from_path(path_str: str) -> str | None:
    for part in Path(path_str).parts:
        if part.upper().startswith("S-1-"):
            return part
    return None

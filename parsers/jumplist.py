"""JumpList (AutomaticDestinations) parser.

A ``*.automaticDestinations-ms`` file is an OLE compound document. Inside,
each numbered stream (``1``, ``2``, …) is a complete LNK file pointing to
a document the user recently opened with the owning application (the
filename's leading 16 hex chars are the application's well-known AppID).

The ``DestList`` stream carries per-entry sequence + last-access metadata,
but its layout differs across Windows builds. For M8 we walk the numbered
streams as LNKs (which gives target path + target MAC times) and best-
effort enrich each event with the access time from DestList when the
layout parses cleanly. If DestList fails to parse, the LNK target_modified
timestamp is still emitted so the artifact never disappears silently.
"""

from __future__ import annotations

import io
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import olefile
from LnkParse3.lnk_file import LnkFile

from core.events import Event, make_event
from parsers.lnk import _iso, _jsonable

PARSER_VERSION = "jumplist/0.1.0"
SOURCE_ARTIFACT = "jumplist"
HOST_OS = "windows"

logger = logging.getLogger(__name__)

# Map well-known JumpList AppIDs (the first 16 hex chars of the filename) to
# a friendlier app name for summaries. Far from exhaustive.
APPID_MAP: dict[str, str] = {
    "1ced32d74a95c7bc": "WordPad",
    "9b9cdc69c1c24e2b": "Notepad",
    "918e0ecb43d17e23": "Paint",
    "a7bd71699c5fdbc5": "Calculator",
    "5f7b5f1e01b83767": "Microsoft Word",
    "ad9a7321e7c47ec5": "Microsoft Excel",
    "ed27a8af1d641a16": "Microsoft PowerPoint",
}


def parse_jumplist(
    jl_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    path = Path(jl_path).resolve()
    path_str = str(path)

    app_id = path.name.split(".", 1)[0][:16].lower()
    app_name = APPID_MAP.get(app_id)

    try:
        ole = olefile.OleFileIO(path_str)
    except Exception:
        logger.exception("jumplist not an OLE container: %s", path_str)
        return []

    dest_list = _try_parse_dest_list(ole)

    events: list[Event] = []
    for stream in ole.listdir():
        if not (len(stream) == 1 and re.fullmatch(r"[0-9a-fA-F]+", stream[0])):
            continue
        try:
            entry_id = int(stream[0], 16)
        except ValueError:
            continue
        try:
            raw_bytes = ole.openstream(stream).read()
        except Exception:
            continue
        ev = _parse_embedded_lnk(
            raw_bytes,
            source_path=path_str,
            collection_id=collection_id,
            host_id_hint=host_id_hint,
            user_hint=user_hint,
            app_id=app_id,
            app_name=app_name,
            entry_id=entry_id,
            dest_list_entry=dest_list.get(entry_id),
        )
        if ev is not None:
            events.append(ev)
    return events


def _parse_embedded_lnk(
    raw_bytes: bytes,
    *,
    source_path: str,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None,
    app_id: str,
    app_name: str | None,
    entry_id: int,
    dest_list_entry: dict[str, Any] | None,
) -> Event | None:
    try:
        lnk = LnkFile(fhandle=io.BytesIO(raw_bytes))
        lnk.process()
        data = lnk.get_json()
    except Exception:
        logger.debug("could not parse jumplist LNK stream %d", entry_id, exc_info=True)
        return None

    header = data.get("header") or {}
    link_info = data.get("link_info") or {}
    location_info = link_info.get("location_info") or {}
    string_data = data.get("data") or {}

    target_path = (
        link_info.get("local_base_path")
        or link_info.get("local_base_path_unicode")
        or string_data.get("relative_path")
        or "<unknown>"
    )

    target_modified = _iso(header.get("modified_time"))
    target_accessed = _iso(header.get("accessed_time"))
    target_created = _iso(header.get("creation_time"))

    last_used = (dest_list_entry or {}).get("last_access")
    pin_status = (dest_list_entry or {}).get("pin_status")

    summary_app = app_name or f"AppID {app_id}"
    summary = f"JumpList ({summary_app}): {target_path}"

    return make_event(
        host_os=HOST_OS,
        host_id=host_id_hint,
        user=user_hint,
        source_artifact=SOURCE_ARTIFACT,
        source_path=source_path,
        event_type="file_access",
        summary=summary,
        evidence={
            "target_path": target_path,
            "app_id": app_id,
            "app_name": app_name,
            "entry_id": entry_id,
            "last_used": last_used,
            "pin_status": pin_status,
            "working_directory": string_data.get("working_directory"),
            "arguments": string_data.get("command_line_arguments"),
            "target_file_size": header.get("file_size"),
            "target_created": target_created,
            "target_modified": target_modified,
            "target_accessed": target_accessed,
            "drive_type": location_info.get("drive_type"),
            "drive_serial": location_info.get("drive_serial_number"),
            "volume_label": location_info.get("volume_label"),
        },
        collection_id=collection_id,
        parser_version=PARSER_VERSION,
        timestamp=last_used or target_modified or target_accessed or target_created,
        raw={
            "app_id": app_id,
            "entry_id": entry_id,
            "dest_list_entry": dest_list_entry,
            "lnk": _jsonable(data),
        },
    )


def _try_parse_dest_list(ole: olefile.OleFileIO) -> dict[int, dict[str, Any]]:
    """Walk the ``DestList`` stream best-effort.

    Layout differs across Windows builds; we treat the entire parse as
    untrusted and return an empty mapping on any structural surprise.
    """
    try:
        if not ole.exists("DestList"):
            return {}
        data = ole.openstream("DestList").read()
    except Exception:
        return {}
    if len(data) < 32:
        return {}

    out: dict[int, dict[str, Any]] = {}
    pos = 32
    try:
        while pos + 130 <= len(data):
            # Last 8 bytes before path (offsets are layout-dependent; this
            # follows the most common Win10 layout). On parse failure we
            # bail out — degraded gracefully back to LNK-only metadata.
            entry_id = struct.unpack_from("<I", data, pos + 88)[0]
            filetime = struct.unpack_from("<Q", data, pos + 100)[0]
            pin_status = struct.unpack_from("<i", data, pos + 108)[0]
            path_size = struct.unpack_from("<H", data, pos + 128)[0]

            access_iso = _filetime_to_iso(filetime)
            out[entry_id] = {
                "last_access": access_iso,
                "pin_status": pin_status,
            }

            entry_total = 130 + path_size * 2 + 4
            pos += entry_total
    except (struct.error, ValueError):
        # Layout drift; what we have so far is still valid.
        return out
    return out


def _filetime_to_iso(filetime: int) -> str | None:
    if filetime <= 0:
        return None
    # Windows FILETIME = 100-ns intervals since 1601-01-01 UTC.
    try:
        seconds = filetime / 10_000_000 - 11_644_473_600
        if seconds <= 0:
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None

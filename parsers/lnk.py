"""Windows .lnk (shell link) parser.

LNK files record the **target file's** MAC times at the moment the shortcut
was created and persist them even if the target is deleted — they're a
prime artifact for proving a user knew about a path. We emit one
``file_access`` event per .lnk; the event's timestamp is the target file's
last-modified time when possible (most informative for timeline use).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from LnkParse3.lnk_file import LnkFile

from core.events import Event, make_event

PARSER_VERSION = "lnk/0.1.0"
SOURCE_ARTIFACT = "lnk"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_lnk(
    lnk_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    path_str = str(Path(lnk_path).resolve())
    try:
        with open(path_str, "rb") as fh:
            lnk = LnkFile(fhandle=fh)
            lnk.process()
            data = lnk.get_json()
    except Exception:
        logger.exception("could not parse lnk %s", path_str)
        return []

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

    creation_time = _iso(header.get("creation_time"))
    modified_time = _iso(header.get("modified_time"))
    accessed_time = _iso(header.get("accessed_time"))

    return [
        make_event(
            host_os=HOST_OS,
            host_id=host_id_hint,
            user=user_hint,
            source_artifact=SOURCE_ARTIFACT,
            source_path=path_str,
            event_type="file_access",
            summary=f"LNK target: {target_path}",
            evidence={
                "target_path": target_path,
                "working_directory": string_data.get("working_directory"),
                "arguments": string_data.get("command_line_arguments"),
                "description": string_data.get("description"),
                "icon_location": string_data.get("icon_location"),
                "target_file_size": header.get("file_size"),
                "target_created": creation_time,
                "target_modified": modified_time,
                "target_accessed": accessed_time,
                "drive_type": location_info.get("drive_type"),
                "drive_serial": location_info.get("drive_serial_number"),
                "volume_label": location_info.get("volume_label"),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=modified_time or accessed_time or creation_time,
            raw=_jsonable(data),
        )
    ]


def _iso(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.strftime("%Y-%m-%dT%H:%M:%SZ")
        return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, str):
        return v
    return None


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return _iso(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return obj

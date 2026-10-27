"""Windows .lnk (shell link) parser.

LNK files record the **target file's** MAC times at the moment the shortcut
was created and persist them even if the target is deleted — they're a
prime artifact for proving a user knew about a path. We emit one
``file_access`` event per .lnk; the event's timestamp is the target file's
last-modified time when possible (most informative for timeline use).
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from LnkParse3.lnk_file import LnkFile

from core.events import Event, make_event
from parsers._time import to_iso_utc

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

    target_path = target_path_from_lnk(link_info, string_data)

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
                "network_share": location_info.get("net_name")
                or location_info.get("net_name_unicode"),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=modified_time or accessed_time or creation_time,
            raw=_jsonable(data),
        )
    ]


def target_path_from_lnk(link_info: dict[str, Any], string_data: dict[str, Any]) -> str:
    """Reconstruct the target per MS-SHLLINK 2.3: ``LocalBasePath`` +
    ``CommonPathSuffix`` for local targets, ``NetName`` (the UNC share) +
    ``CommonPathSuffix`` for network targets, else the relative path."""
    location_info = link_info.get("location_info") or {}
    suffix = (
        link_info.get("common_path_suffix_unicode")
        or link_info.get("common_path_suffix")
        or ""
    )
    base = link_info.get("local_base_path_unicode") or link_info.get("local_base_path")
    if base:
        return _join_win(base, suffix)
    share = location_info.get("net_name_unicode") or location_info.get("net_name")
    if share:
        return _join_win(share, suffix)
    return string_data.get("relative_path") or "<unknown>"


def _join_win(base: str, suffix: str) -> str:
    if not suffix:
        return base
    return base.rstrip("\\") + "\\" + suffix.lstrip("\\")


def _iso(v: Any) -> str | None:
    return to_iso_utc(v)


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

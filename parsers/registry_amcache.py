"""Amcache.hve parser.

Emits one ``program_execution`` event per entry under ``\\Root\\File`` and
``\\Root\\InventoryApplicationFile``. Each entry carries SHA-1, size, signer,
and link-date metadata, making AmCache the highest-signal source for "what
ran on this box recently."
"""

from __future__ import annotations

import logging
from pathlib import Path

from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event
from parsers._time import to_iso_utc

PARSER_VERSION = "amcache_hive/0.1.0"
SOURCE_ARTIFACT = "registry.amcache"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_amcache_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    hive: RegistryHive | None = None,
) -> list[Event]:
    hive_path_str = str(Path(hive_path).resolve())
    hive = hive or RegistryHive(hive_path_str)
    plugin = AmCachePlugin(hive, as_json=True)
    try:
        plugin.run()
    except Exception:
        logger.exception("AmCachePlugin failed")
        return []

    events: list[Event] = []
    for entry in plugin.entries or []:
        if not isinstance(entry, dict):
            continue
        # regipy snake-cases LowerCaseLongPath to lower_case_long_path.
        program_path = (
            entry.get("lower_case_long_path")
            or entry.get("low_case_long_path")
            or entry.get("full_path")
            or entry.get("file_name")
            or entry.get("name")
            or "<unknown>"
        )
        sha1 = entry.get("sha1")
        publisher = entry.get("publisher")
        link_date = to_iso_utc(entry.get("link_date"))
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id_hint,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path_str,
                event_type="program_execution",
                summary=f"AmCache: {program_path}" + (f" — {publisher}" if publisher else ""),
                evidence={
                    "program_path": program_path,
                    "sha1": sha1,
                    "size_bytes": entry.get("size"),
                    "publisher": publisher,
                    "product_name": entry.get("product_name"),
                    "product_version": entry.get("product_version"),
                    "file_version": entry.get("file_version"),
                    "is_pe_file": entry.get("is_pe_file"),
                    "is_os_component": entry.get("is_os_component"),
                    "link_date": link_date,
                    "program_id": entry.get("program_id"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=to_iso_utc(entry.get("timestamp"))
                or link_date
                or to_iso_utc(entry.get("last_modified_timestamp"))
                or to_iso_utc(entry.get("last_modified")),
                raw=entry,
            )
        )
    return events

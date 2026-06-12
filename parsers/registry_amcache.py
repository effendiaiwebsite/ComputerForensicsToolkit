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

PARSER_VERSION = "amcache_hive/0.1.0"
SOURCE_ARTIFACT = "registry.amcache"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_amcache_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
) -> list[Event]:
    hive_path_str = str(Path(hive_path).resolve())
    hive = RegistryHive(hive_path_str)
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
        program_path = (
            entry.get("low_case_long_path")
            or entry.get("full_path")
            or entry.get("file_name")
            or entry.get("name")
            or "<unknown>"
        )
        sha1 = entry.get("sha1")
        publisher = entry.get("publisher")
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
                    "link_date": entry.get("link_date"),
                    "program_id": entry.get("program_id"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=entry.get("timestamp")
                or entry.get("link_date")
                or entry.get("last_modified"),
                raw=entry,
            )
        )
    return events

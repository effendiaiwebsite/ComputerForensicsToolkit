"""NTUSER.DAT parser — per-user activity.

Emits:
- ``program_execution`` — UserAssist (ROT13-decoded program runs)
- ``persistence_entry`` — per-user Run/RunOnce
- ``shell_command`` — typed paths (Explorer address bar), typed URLs (IE), RunMRU
- ``file_access`` — RecentDocs
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from regipy.plugins.ntuser.persistence import NTUserPersistencePlugin
from regipy.plugins.ntuser.recentdocs import RecentDocsPlugin
from regipy.plugins.ntuser.runmru import RunMRUPlugin
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy.plugins.ntuser.typed_urls import TypedUrlsPlugin
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event
from parsers._regipy_utils import flatten_persistence_values, short_path
from parsers._time import to_iso_utc

PARSER_VERSION = "ntuser_hive/0.1.0"
SOURCE_ARTIFACT = "registry.ntuser"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_ntuser_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
    hive: RegistryHive | None = None,
) -> list[Event]:
    hive_path_str = str(Path(hive_path).resolve())
    hive = hive or RegistryHive(hive_path_str)
    events: list[Event] = []
    for fn in (
        _user_assist,
        _persistence,
        _typed_paths,
        _typed_urls,
        _recent_docs,
        _run_mru,
    ):
        try:
            events.extend(fn(hive, hive_path_str, collection_id, host_id_hint, user_hint))
        except Exception:
            logger.exception("%s failed", fn.__name__)
    return events


def _user_assist(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str, user: str | None,
) -> list[Event]:
    plugin = UserAssistPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for entry in plugin.entries or []:
        name = entry.get("name") or "<unknown>"
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                user=user,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="program_execution",
                summary=f"UserAssist: {name} (runs={entry.get('run_counter')})",
                evidence={
                    "program_name": name,
                    "run_counter": entry.get("run_counter"),
                    "focus_count": entry.get("focus_count"),
                    "total_focus_time_ms": entry.get("total_focus_time_ms"),
                    "session_id": entry.get("session_id"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=to_iso_utc(entry.get("timestamp")),
                raw=entry,
            )
        )
    return events


def _persistence(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str, user: str | None,
) -> list[Event]:
    plugin = NTUserPersistencePlugin(hive, as_json=True)
    plugin.run()
    return list(_emit_persistence_events(plugin.entries, hive_path, collection_id, host_id, user))


def _emit_persistence_events(payload, hive_path, collection_id, host_id, user) -> Iterator[Event]:
    for key_path, last_write_raw, values, raw_values in flatten_persistence_values(payload or {}):
        last_write = to_iso_utc(last_write_raw)
        for name, data in values.items():
            yield make_event(
                host_os=HOST_OS,
                host_id=host_id,
                user=user,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="persistence_entry",
                summary=f"{short_path(key_path)}: {name} = {data}",
                evidence={
                    "key_path": key_path,
                    "value_name": name,
                    "value_data": data,
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=last_write,
                timestamp_source="inferred" if last_write else "none",
                raw={"key_path": key_path, "last_write": last_write_raw, "values": raw_values},
            )


def _typed_paths(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str, user: str | None,
) -> list[Event]:
    plugin = TypedPathsPlugin(hive, as_json=True)
    plugin.run()
    payload = plugin.entries or {}
    last_write = to_iso_utc(payload.get("last_write")) if isinstance(payload, dict) else None
    entries = payload.get("entries") if isinstance(payload, dict) else None
    events: list[Event] = []
    for record in entries or []:
        for slot_name, path in record.items():
            events.append(
                make_event(
                    host_os=HOST_OS,
                    host_id=host_id,
                    user=user,
                    source_artifact=SOURCE_ARTIFACT,
                    source_path=hive_path,
                    event_type="shell_command",
                    summary=f"Explorer typed path: {path}",
                    evidence={"slot": slot_name, "path": path},
                    collection_id=collection_id,
                    parser_version=PARSER_VERSION,
                    timestamp=last_write,
                    timestamp_source="inferred" if last_write else "none",
                    raw={"slot": slot_name, "path": path, "last_write": last_write},
                )
            )
    return events


def _typed_urls(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str, user: str | None,
) -> list[Event]:
    plugin = TypedUrlsPlugin(hive, as_json=True)
    plugin.run()
    payload = plugin.entries or {}
    last_write = to_iso_utc(payload.get("last_write")) if isinstance(payload, dict) else None
    entries = payload.get("entries") if isinstance(payload, dict) else None
    events: list[Event] = []
    for record in entries or []:
        for slot_name, url in record.items():
            events.append(
                make_event(
                    host_os=HOST_OS,
                    host_id=host_id,
                    user=user,
                    source_artifact=SOURCE_ARTIFACT,
                    source_path=hive_path,
                    event_type="shell_command",
                    summary=f"IE typed URL: {url}",
                    evidence={"slot": slot_name, "url": url},
                    collection_id=collection_id,
                    parser_version=PARSER_VERSION,
                    timestamp=last_write,
                    timestamp_source="inferred" if last_write else "none",
                    raw={"slot": slot_name, "url": url, "last_write": last_write},
                )
            )
    return events


def _recent_docs(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str, user: str | None,
) -> list[Event]:
    """One event per document; regipy groups documents under their RecentDocs
    (sub)key as ``{key_path, last_write, extension, documents: [{index, name}]}``."""
    plugin = RecentDocsPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for entry in plugin.entries or []:
        if not isinstance(entry, dict):
            continue
        ext = entry.get("extension") or ""
        key_path = entry.get("key_path")
        last_write = to_iso_utc(entry.get("last_write"))
        for position, doc in enumerate(entry.get("documents") or []):
            filename = doc.get("name") if isinstance(doc, dict) else doc
            if not filename:
                continue
            index = doc.get("index") if isinstance(doc, dict) else None
            events.append(
                make_event(
                    host_os=HOST_OS,
                    host_id=host_id,
                    user=user,
                    source_artifact=SOURCE_ARTIFACT,
                    source_path=hive_path,
                    event_type="file_access",
                    summary=f"RecentDocs: {filename}" + (f" ({ext})" if ext else ""),
                    evidence={
                        "filename": filename,
                        "extension": ext,
                        "key_path": key_path,
                        "mru_index": index,
                        "mru_order": position,
                    },
                    collection_id=collection_id,
                    parser_version=PARSER_VERSION,
                    # Only the most-recent document is reflected by the key's
                    # last-write time; older ones are anywhere before it.
                    timestamp=last_write,
                    timestamp_source="inferred" if last_write else "none",
                    raw={
                        "key_path": key_path,
                        "last_write": entry.get("last_write"),
                        "extension": ext,
                        "index": index,
                        "name": filename,
                    },
                )
            )
    return events


def _run_mru(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str, user: str | None,
) -> list[Event]:
    """One event per Win+R command; regipy emits a list with one entry per key:
    ``{key_path, last_write, mru_order, commands: [{letter, command}]}``."""
    plugin = RunMRUPlugin(hive, as_json=True)
    plugin.run()
    entries = plugin.entries or []
    if isinstance(entries, dict):
        entries = [entries]
    events: list[Event] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        last_write = to_iso_utc(entry.get("last_write"))
        for cmd in entry.get("commands") or []:
            text = cmd.get("command") if isinstance(cmd, dict) else cmd
            slot = cmd.get("letter") if isinstance(cmd, dict) else None
            events.append(
                make_event(
                    host_os=HOST_OS,
                    host_id=host_id,
                    user=user,
                    source_artifact=SOURCE_ARTIFACT,
                    source_path=hive_path,
                    event_type="shell_command",
                    summary=f"Win+R RunMRU: {text}",
                    evidence={
                        "command": text,
                        "slot": slot,
                        "key_path": entry.get("key_path"),
                        "mru_order": entry.get("mru_order"),
                    },
                    collection_id=collection_id,
                    parser_version=PARSER_VERSION,
                    timestamp=last_write,
                    timestamp_source="inferred" if last_write else "none",
                    raw=cmd if isinstance(cmd, dict) else {"command": text},
                )
            )
    return events

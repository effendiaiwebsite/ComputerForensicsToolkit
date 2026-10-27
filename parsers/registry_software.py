"""SOFTWARE hive parser.

Emits:
- ``program_install`` — Uninstall keys (Win32 and Wow6432Node)
- ``persistence_entry`` — machine-wide Run/RunOnce/Explorer policies
- ``system_config_change`` — Windows version (one event), per-user profile
  list entries (one event per SID), network profiles (one event per WLAN)
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from regipy.plugins.software.installed_programs import InstalledProgramsSoftwarePlugin
from regipy.plugins.software.networklist import NetworkListPlugin
from regipy.plugins.software.persistence import SoftwarePersistencePlugin
from regipy.plugins.software.profilelist import ProfileListPlugin
from regipy.plugins.software.winver import WinVersionPlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event
from parsers._regipy_utils import flatten_persistence_values, short_path
from parsers._time import to_iso_utc

PARSER_VERSION = "software_hive/0.1.0"
SOURCE_ARTIFACT = "registry.software"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_software_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    hive: RegistryHive | None = None,
) -> list[Event]:
    hive_path_str = str(Path(hive_path).resolve())
    hive = hive or RegistryHive(hive_path_str)
    events: list[Event] = []
    for fn in (
        _winver,
        _installed_programs,
        _persistence,
        _profile_list,
        _network_list,
    ):
        try:
            events.extend(fn(hive, hive_path_str, collection_id, host_id_hint))
        except Exception:
            logger.exception("%s failed", fn.__name__)
    return events


def _winver(hive: RegistryHive, hive_path: str, collection_id: str, host_id: str) -> list[Event]:
    plugin = WinVersionPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for key_path, fields in (plugin.entries or {}).items():
        product = fields.get("ProductName") or "<unknown>"
        install_date = to_iso_utc(fields.get("InstallDate"))
        last_write = to_iso_utc(fields.get("last_write"))
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="system_config_change",
                summary=f"Windows: {product} (build {fields.get('CurrentBuild') or '?'})",
                evidence={
                    "product_name": product,
                    "edition_id": fields.get("EditionID"),
                    "current_version": fields.get("CurrentVersion"),
                    "current_build": fields.get("CurrentBuild"),
                    "display_version": fields.get("DisplayVersion"),
                    "install_date": install_date,
                    "registered_owner": fields.get("RegisteredOwner"),
                    "key_path": key_path,
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=install_date or last_write,
                timestamp_source=(
                    "direct" if install_date else ("inferred" if last_write else "none")
                ),
                raw=fields,
            )
        )
    return events


def _installed_programs(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str,
) -> list[Event]:
    plugin = InstalledProgramsSoftwarePlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for entry in plugin.entries or []:
        name = entry.get("DisplayName") or entry.get("service_name") or "<unknown>"
        publisher = entry.get("Publisher")
        version = entry.get("DisplayVersion")
        install_date = entry.get("InstallDate")
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="program_install",
                summary=f"Installed: {name}"
                + (f" {version}" if version else "")
                + (f" — {publisher}" if publisher else ""),
                evidence={
                    "display_name": name,
                    "publisher": publisher,
                    "display_version": version,
                    "install_location": entry.get("InstallLocation"),
                    "install_source": entry.get("InstallSource"),
                    "install_date_raw": install_date,
                    "uninstall_string": entry.get("UninstallString"),
                    "estimated_size_kb": entry.get("EstimatedSize"),
                    "registry_path": entry.get("registry_path"),
                    "key_name": entry.get("service_name"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=to_iso_utc(entry.get("timestamp")),
                raw=entry,
            )
        )
    return events


def _persistence(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str,
) -> list[Event]:
    plugin = SoftwarePersistencePlugin(hive, as_json=True)
    plugin.run()
    return list(_emit_persistence_events(plugin.entries, hive_path, collection_id, host_id))


def _emit_persistence_events(payload, hive_path, collection_id, host_id) -> Iterator[Event]:
    for key_path, last_write_raw, values, raw_values in flatten_persistence_values(payload or {}):
        last_write = to_iso_utc(last_write_raw)
        for name, data in values.items():
            yield make_event(
                host_os=HOST_OS,
                host_id=host_id,
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


def _profile_list(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str,
) -> list[Event]:
    plugin = ProfileListPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for entry in plugin.entries or []:
        path = entry.get("path") or "<no profile path>"
        sid = entry.get("sid")
        last_write = to_iso_utc(entry.get("last_write"))
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="system_config_change",
                summary=f"ProfileList: {sid} → {path}",
                evidence={
                    "sid": sid,
                    "profile_path": path,
                    "flags": entry.get("flags"),
                    "state": entry.get("state"),
                    "full_profile": entry.get("full_profile"),
                    "load_time": to_iso_utc(entry.get("load_time")),
                    "local_load_time": to_iso_utc(entry.get("local_load_time")),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=last_write,
                timestamp_source="inferred" if last_write else "none",
                raw=_jsonable(entry),
            )
        )
    return events


def _network_list(
    hive: RegistryHive, hive_path: str, collection_id: str, host_id: str,
) -> list[Event]:
    plugin = NetworkListPlugin(hive, as_json=True)
    plugin.run()
    return list(_emit_network_profile_events(plugin.entries, hive_path, collection_id, host_id))


def _emit_network_profile_events(entries, hive_path, collection_id, host_id) -> Iterator[Event]:
    """regipy's NetworkListPlugin mixes ``type == "profile"`` entries with
    ``type == "signature"`` rows (gateway MAC / DNS suffix per profile GUID);
    only profiles carry a network name and connection dates.

    ``DateCreated`` / ``DateLastConnected`` are SYSTEMTIME structs written in
    the machine's *local* time, so the event time is ``inferred`` and
    ``time_basis`` records the caveat.
    """
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get("type", "profile") != "profile":
            continue
        profile_name = entry.get("profile_name") or entry.get("ProfileName") or "<unknown network>"
        first_connect = to_iso_utc(entry.get("date_created") or entry.get("DateCreated"))
        last_connect = to_iso_utc(
            entry.get("date_last_connected") or entry.get("DateLastConnected")
        )
        timestamp = last_connect or first_connect
        yield make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=SOURCE_ARTIFACT,
            source_path=hive_path,
            event_type="system_config_change",
            summary=f"NetworkProfile: {profile_name}",
            evidence={
                "profile_name": profile_name,
                "profile_guid": entry.get("profile_guid"),
                "description": entry.get("description") or entry.get("Description"),
                "category": entry.get("category"),
                "name_type": entry.get("name_type"),
                "first_connect": first_connect,
                "last_connect": last_connect,
                "managed": entry.get("managed") or entry.get("Managed"),
                "time_basis": "local",
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=timestamp,
            timestamp_source="inferred" if timestamp else "none",
            raw=_jsonable(entry),
        )


def _jsonable(obj):
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj

"""SYSTEM hive parser — emits normalized ``Event`` objects for M2 artifacts.

Drives regipy's SYSTEM-hive plugins (ComputerName, TimezoneData, USBSTOR,
Services, ShimCache) and translates each plugin's structured output into the
schema in ``docs/EVENT_SCHEMA.md``.

The parser is deliberately defensive: a single failing plugin should not block
the rest from emitting events, because forensic hives are often partial or
malformed and a triage tool that aborts on the first error is useless.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy.plugins.system.services import ServicesPlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.plugins.system.timezone_data import TimezoneDataPlugin
from regipy.plugins.system.usbstor import USBSTORPlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event

PARSER_VERSION = "system_hive/0.1.0"
SOURCE_ARTIFACT = "registry.system"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_system_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str | None = None,
) -> list[Event]:
    """Run every SYSTEM-hive plugin we support and return the union of events.

    ``host_id_hint`` is used until we discover the real ComputerName from the
    hive, after which all events are stamped with it (including in retrospect).
    """
    hive_path_str = str(Path(hive_path).resolve())
    hive = RegistryHive(hive_path_str)

    events: list[Event] = []
    host_id = host_id_hint or "UNKNOWN"

    discovered_name, name_events = _run_computer_name(hive, hive_path_str, collection_id, host_id)
    if discovered_name:
        host_id = discovered_name
        for ev in name_events:
            ev.host_id = host_id
    events.extend(name_events)

    for fn in (_run_timezone, _run_usbstor, _run_services, _run_shimcache):
        try:
            events.extend(fn(hive, hive_path_str, collection_id, host_id))
        except Exception:
            logger.exception("plugin %s failed; continuing", fn.__name__)

    return events


def _run_computer_name(
    hive: RegistryHive,
    hive_path: str,
    collection_id: str,
    host_id: str,
) -> tuple[str | None, list[Event]]:
    plugin = ComputerNamePlugin(hive, as_json=True)
    try:
        plugin.run()
    except Exception:
        logger.exception("ComputerNamePlugin failed")
        return None, []

    events: list[Event] = []
    discovered: str | None = None
    for entry in plugin.entries or []:
        name = entry.get("name")
        if not discovered and name:
            discovered = str(name)
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=str(name) if name else host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="system_config_change",
                summary=f"ComputerName = {name}",
                evidence={"computer_name": name},
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=entry.get("timestamp"),
                raw=entry,
            )
        )
    return discovered, events


def _run_timezone(
    hive: RegistryHive,
    hive_path: str,
    collection_id: str,
    host_id: str,
) -> list[Event]:
    plugin = TimezoneDataPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for control_set_path, values in (plugin.entries or {}).items():
        flat = {v.get("name"): v.get("value") for v in values if isinstance(v, dict)}
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="system_config_change",
                summary=f"TimeZone = {flat.get('TimeZoneKeyName') or flat.get('StandardName') or '<unknown>'}",
                evidence={
                    "control_set": control_set_path,
                    "time_zone_key_name": flat.get("TimeZoneKeyName"),
                    "standard_name": flat.get("StandardName"),
                    "daylight_name": flat.get("DaylightName"),
                    "active_time_bias_minutes": flat.get("ActiveTimeBias"),
                    "bias_minutes": flat.get("Bias"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                raw={"control_set": control_set_path, "values": values},
            )
        )
    return events


def _run_usbstor(
    hive: RegistryHive,
    hive_path: str,
    collection_id: str,
    host_id: str,
) -> list[Event]:
    plugin = USBSTORPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for entry in plugin.entries or []:
        ts = (
            entry.get("last_connected")
            or entry.get("last_installed")
            or entry.get("first_installed")
            or entry.get("last_write")
        )
        manufacturer = entry.get("manufacturer") or "?"
        title = entry.get("title") or "?"
        serial = entry.get("serial_number") or "?"
        device_name = entry.get("device_name")
        summary_parts = [f"USB: {manufacturer} {title}", f"SN {serial}"]
        if device_name:
            summary_parts.insert(1, str(device_name))
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="usb_connection",
                summary=" — ".join(summary_parts),
                evidence={
                    "vendor": manufacturer,
                    "product": title,
                    "version": entry.get("version"),
                    "serial": serial,
                    "device_name": device_name,
                    "first_installed": entry.get("first_installed"),
                    "last_connected": entry.get("last_connected"),
                    "last_removed": entry.get("last_removed"),
                    "last_installed": entry.get("last_installed"),
                    "disk_guid": entry.get("disk_guid"),
                    "key_path": entry.get("key_path"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=ts,
                raw=entry,
            )
        )
    return events


def _run_services(
    hive: RegistryHive,
    hive_path: str,
    collection_id: str,
    host_id: str,
) -> list[Event]:
    plugin = ServicesPlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for control_set_path, payload in (plugin.entries or {}).items():
        for svc in payload.get("services", []) or []:
            values = {v.get("name"): v.get("value") for v in (svc.get("values") or []) if isinstance(v, dict)}
            display_name = values.get("DisplayName") or svc.get("name")
            image_path = values.get("ImagePath")
            start = values.get("Start")
            type_ = values.get("Type")
            events.append(
                make_event(
                    host_os=HOST_OS,
                    host_id=host_id,
                    source_artifact=SOURCE_ARTIFACT,
                    source_path=hive_path,
                    event_type="service_install",
                    summary=f"Service: {display_name} ({svc.get('name')}) → {image_path or '<no image>'}",
                    evidence={
                        "service_name": svc.get("name"),
                        "display_name": display_name,
                        "image_path": image_path,
                        "start_type": start,
                        "service_type": type_,
                        "control_set": control_set_path,
                    },
                    collection_id=collection_id,
                    parser_version=PARSER_VERSION,
                    timestamp=svc.get("last_modified"),
                    raw=svc,
                )
            )
    return events


def _run_shimcache(
    hive: RegistryHive,
    hive_path: str,
    collection_id: str,
    host_id: str,
) -> list[Event]:
    plugin = ShimCachePlugin(hive, as_json=True)
    plugin.run()
    events: list[Event] = []
    for entry in plugin.entries or []:
        program_path = entry.get("path") or entry.get("Path") or "<unknown>"
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path,
                event_type="program_execution",
                summary=f"ShimCache: {program_path}",
                evidence={
                    "program_path": program_path,
                    "last_modified": entry.get("last_modified"),
                    "exec_flag": entry.get("exec_flag"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=entry.get("last_modified"),
                raw=entry,
            )
        )
    return events

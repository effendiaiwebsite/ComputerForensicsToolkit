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
from pathlib import Path

from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy.plugins.system.services import ServicesPlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.plugins.system.timezone_data import TimezoneDataPlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event
from parsers._time import to_iso_utc

PARSER_VERSION = "system_hive/0.1.0"
SOURCE_ARTIFACT = "registry.system"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_system_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str | None = None,
    hive: RegistryHive | None = None,
) -> list[Event]:
    """Run every SYSTEM-hive plugin we support and return the union of events.

    ``host_id_hint`` is used until we discover the real ComputerName from the
    hive, after which all events are stamped with it (including in retrospect).
    """
    hive_path_str = str(Path(hive_path).resolve())
    hive = hive or RegistryHive(hive_path_str)

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
                timestamp=to_iso_utc(entry.get("timestamp")),
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
                summary=(
                    "TimeZone = "
                    f"{flat.get('TimeZoneKeyName') or flat.get('StandardName') or '<unknown>'}"
                ),
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


# Property-store GUIDs/keys under a USBSTOR serial's ``Properties`` subkey
# (Vista+). Stable Windows identifiers; mirrored from regipy's USBSTOR plugin.
_USB_DEVICE_NAME_GUID = "{540b947e-8b40-45bc-a8a2-6a0b894cbda2}"
_USB_DATES_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
_USB_DEVICE_NAME_KEY = "0004"
_USB_DATE_KEYS = {
    "first_installed": "0065",
    "last_connected": "0066",
    "last_removed": "0067",
    "last_installed": "0064",
}


def _walk_usbstor(hive: RegistryHive) -> list[dict]:
    """Enumerate USBSTOR devices, tolerating malformed entries.

    regipy's ``USBSTORPlugin`` looks up the ``Properties`` subkey with
    ``raise_on_missing`` defaulting to ``True``; on a Vista-era serial that has
    no ``Properties`` child it raises ``NoRegistrySubkeysException``, which
    escapes ``run()`` and drops *every* device. Here each serial is parsed
    independently — a bad one is skipped, the rest still surface.
    """
    from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException
    from regipy.utils import convert_wintime

    entries: list[dict] = []
    try:
        control_sets = hive.get_control_sets(r"Enum\USBSTOR")
    except RegistryKeyNotFoundException:
        return entries

    for cs_path in control_sets:
        try:
            devices = list(hive.get_key(cs_path).iter_subkeys())
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException):
            continue
        for device in devices:
            manufacturer, title, version = _split_device_name(device.name)
            try:
                serials = list(device.iter_subkeys())
            except NoRegistrySubkeysException:
                serials = []
            for serial in serials:
                try:
                    entries.append(_usbstor_serial_entry(
                        hive, cs_path, device.name, serial,
                        manufacturer, title, version, convert_wintime,
                    ))
                except Exception:
                    logger.exception(
                        "skipping malformed USBSTOR serial %s\\%s",
                        device.name, getattr(serial, "name", "?"),
                    )
    return entries


_USB_ID_PREFIXES = (("ven_", 0), ("prod_", 1), ("rev_", 2))


def _split_device_name(name: str) -> tuple[str | None, str | None, str | None]:
    """``Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00`` → ``("SanDisk", "Cruzer", "1.00")``."""
    parts = name.split("&")
    if len(parts) != 4:
        return None, None, None
    out: list[str | None] = [None, None, None]
    for part in parts[1:]:
        lowered = part.lower()
        for prefix, slot in _USB_ID_PREFIXES:
            if lowered.startswith(prefix):
                out[slot] = part[len(prefix):] or None
                break
    return out[0], out[1], out[2]


def _usbstor_serial_entry(
    hive, cs_path, device_name, serial, manufacturer, title, version, convert_wintime,
) -> dict:
    serial_number = serial.name
    key_path = rf"{cs_path}\{device_name}\{serial_number}"
    last_write = to_iso_utc(convert_wintime(serial.header.last_modified, as_json=False))

    disk_guid = None
    try:
        # Optional sub-value, absent on many devices.
        disk_guid = hive.get_key(rf"{key_path}\Device Parameters\Partmgr").get_value("DiskId")
    except Exception:
        disk_guid = None

    device_dev_name = None
    dates: dict[str, object] = {}
    props = serial.get_subkey("Properties", raise_on_missing=False)
    if props:
        name_guid = props.get_subkey(_USB_DEVICE_NAME_GUID, raise_on_missing=False)
        name_key = (
            name_guid.get_subkey(_USB_DEVICE_NAME_KEY, raise_on_missing=False)
            if name_guid else None
        )
        if name_key:
            try:
                device_dev_name = name_key.get_value()
            except Exception:
                device_dev_name = None
        dates_key = props.get_subkey(_USB_DATES_GUID, raise_on_missing=False)
        if dates_key:
            for field, sub in _USB_DATE_KEYS.items():
                k = dates_key.get_subkey(sub, raise_on_missing=False)
                if k:
                    try:
                        dates[field] = to_iso_utc(k.get_value(as_json=True))
                    except Exception:
                        dates[field] = None

    return {
        "last_write": last_write,
        "key_path": key_path,
        "last_connected": dates.get("last_connected"),
        "last_removed": dates.get("last_removed"),
        "first_installed": dates.get("first_installed"),
        "last_installed": dates.get("last_installed"),
        "serial_number": serial_number,
        "device_name": device_dev_name,
        "disk_guid": disk_guid,
        "manufacturer": manufacturer,
        "version": version,
        "title": title,
    }


def _run_usbstor(
    hive: RegistryHive,
    hive_path: str,
    collection_id: str,
    host_id: str,
) -> list[Event]:
    events: list[Event] = []
    for entry in _walk_usbstor(hive):
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
            values = {
                v.get("name"): v.get("value")
                for v in (svc.get("values") or [])
                if isinstance(v, dict)
            }
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
                    summary=(
                        f"Service: {display_name} ({svc.get('name')}) → "
                        f"{image_path or '<no image>'}"
                    ),
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
                    timestamp=to_iso_utc(svc.get("last_modified")),
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
        if not isinstance(entry, dict):
            continue
        program_path = entry.get("path") or entry.get("Path") or "<unknown>"
        # regipy's ShimCacheParser names the field last_mod_date (last_mod_time
        # on XP-era caches); last_modified is accepted for older forks.
        last_modified = to_iso_utc(
            entry.get("last_mod_date")
            or entry.get("last_modified")
            or entry.get("last_mod_time")
        )
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
                    "last_modified": last_modified,
                    "exec_flag": entry.get("exec_flag"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=last_modified,
                raw=entry,
            )
        )
    return events

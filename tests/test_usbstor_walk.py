"""Robustness test for the USBSTOR walk.

regipy's USBSTOR plugin aborts the entire enumeration when one serial subkey
lacks a ``Properties`` child (common on Vista-era SYSTEM hives), so the Devices
tab came up empty on real images. ``_walk_usbstor`` parses each serial
independently. We drive it with fakes mirroring regipy's ``RegistryKey`` API.
"""

from __future__ import annotations

from datetime import UTC, datetime

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException

from parsers.registry_system import _USB_DATES_GUID, _USB_DEVICE_NAME_GUID, _walk_usbstor

_USBSTOR_PATH = r"\ControlSet001\Enum\USBSTOR"


def _ft(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000)


class _Key:
    def __init__(self, name, last_modified=0, subkeys=None, values=None):
        self.name = name
        self.header = type("H", (), {"last_modified": last_modified})()
        self._subkeys = subkeys or {}
        self._values = values or {}

    def iter_subkeys(self):
        if not self._subkeys:
            raise NoRegistrySubkeysException(f"no subkeys for {self.name}")
        return list(self._subkeys.values())

    def get_subkey(self, name, raise_on_missing=True):
        if name in self._subkeys:
            return self._subkeys[name]
        if raise_on_missing:
            raise NoRegistrySubkeysException(f"No subkey {name} for {self.name}")
        return None

    def get_value(self, name=None, as_json=False):
        return self._values.get(name)


def _full_properties(name: str):
    """A Properties subtree with a device name and a last-connected date."""
    name_key = _Key("0004", values={None: name})
    name_guid = _Key(_USB_DEVICE_NAME_GUID, subkeys={"0004": name_key})
    last_connected = _Key("0066", values={None: "2007-07-14T17:58:46Z"})
    dates = _Key(_USB_DATES_GUID, subkeys={"0066": last_connected})
    return _Key("Properties", subkeys={_USB_DEVICE_NAME_GUID: name_guid, _USB_DATES_GUID: dates})


class _Hive:
    def __init__(self, usbstor: _Key):
        self._usbstor = usbstor

    def get_control_sets(self, path):
        return [_USBSTOR_PATH]

    def get_key(self, path):
        if path == _USBSTOR_PATH:
            return self._usbstor
        raise RegistryKeyNotFoundException(path)  # Partmgr / DiskId absent


def _build_hive() -> _Hive:
    ft = _ft(datetime(2007, 7, 14, 17, 56, 41, tzinfo=UTC))
    # Device 1: Cruzer with a fully-populated serial.
    cruzer_serial = _Key("SNDK3066A40516400406&0", last_modified=ft,
                         subkeys={"Properties": _full_properties("SanDisk Cruzer Mini USB Device")})
    cruzer = _Key("Disk&Ven_SanDisk&Prod_Cruzer_Mini&Rev_0.1",
                  subkeys={cruzer_serial.name: cruzer_serial})
    # Device 2: TREK with a serial that has NO Properties subkey (the crasher).
    # No Properties subkey at all — the entry that crashed regipy.
    trek_serial = _Key("10120516721518&0", last_modified=ft)
    trek = _Key("Disk&Ven_TREK&Prod_TD2SMART_G3M&Rev_1.00",
                subkeys={trek_serial.name: trek_serial})
    usbstor = _Key("USBSTOR", subkeys={cruzer.name: cruzer, trek.name: trek})
    return _Hive(usbstor)


def test_walk_usbstor_keeps_devices_when_one_lacks_properties():
    entries = _walk_usbstor(_build_hive())
    serials = {e["serial_number"]: e for e in entries}
    # Both devices survive — the Properties-less serial no longer drops the rest.
    assert "SNDK3066A40516400406&0" in serials
    assert "10120516721518&0" in serials


def test_walk_usbstor_extracts_fields_from_properties():
    entries = _walk_usbstor(_build_hive())
    cruzer = next(e for e in entries if e["serial_number"].startswith("SNDK"))
    assert cruzer["manufacturer"] == "SanDisk"
    assert cruzer["title"] == "Cruzer_Mini"
    assert cruzer["version"] == "0.1"
    assert cruzer["device_name"] == "SanDisk Cruzer Mini USB Device"
    assert cruzer["last_connected"] == "2007-07-14T17:58:46Z"


def test_walk_usbstor_propertyless_serial_has_no_dates_but_last_write():
    entries = _walk_usbstor(_build_hive())
    trek = next(e for e in entries if e["serial_number"] == "10120516721518&0")
    assert trek["device_name"] is None
    assert trek["last_connected"] is None
    assert trek["manufacturer"] == "TREK"
    assert trek["last_write"] is not None  # key last-modified still gives a timestamp


def test_walk_usbstor_no_usbstor_key_returns_empty():
    class _EmptyHive:
        def get_control_sets(self, path):
            raise RegistryKeyNotFoundException("no USBSTOR")

    assert _walk_usbstor(_EmptyHive()) == []

"""Tests for the USB devices aggregation query."""

from __future__ import annotations

from core.events import make_event
from core.store import EventStore


def _usb(serial: str, **overrides):
    evidence = {
        "vendor": overrides.pop("vendor", "SanDisk"),
        "product": overrides.pop("product", "Cruzer"),
        "device_name": overrides.pop("device_name", "SanDisk Cruzer USB Device"),
        "serial": serial,
        "first_installed": overrides.pop("first_installed", "2025-01-01T00:00:00Z"),
        "last_connected": overrides.pop("last_connected", "2025-06-11T12:00:00Z"),
        "last_removed": overrides.pop("last_removed", None),
    }
    return make_event(
        host_os="windows",
        host_id="MSI",
        source_artifact="registry.system",
        source_path=r"C:\hive",
        event_type="usb_connection",
        summary=f"USB: {evidence['vendor']} {evidence['product']} — SN {serial}",
        evidence=evidence,
        collection_id="col-1",
        parser_version="v",
        timestamp=evidence["last_connected"],
    )


def test_query_usb_devices_groups_by_serial() -> None:
    store = EventStore()
    store.insert_events([
        _usb("AAA111", last_connected="2025-06-01T00:00:00Z"),
        _usb("AAA111", last_connected="2025-06-10T00:00:00Z"),
        _usb("BBB222", last_connected="2025-05-20T00:00:00Z"),
    ])

    rows = store.query_usb_devices()
    by_serial = {r["serial"]: r for r in rows}

    assert set(by_serial) == {"AAA111", "BBB222"}
    assert by_serial["AAA111"]["event_count"] == 2
    assert by_serial["AAA111"]["last_connected"] == "2025-06-10T00:00:00Z"
    assert by_serial["BBB222"]["event_count"] == 1


def test_query_usb_devices_scoped_to_collection() -> None:
    store = EventStore()
    store.insert_events([
        _usb("AAA111"),
    ])
    other = _usb("CCC333")
    object.__setattr__(other, "collection_id", "col-other")
    store.insert_events([other])

    rows = store.query_usb_devices(collection_id="col-1")
    serials = {r["serial"] for r in rows}
    assert serials == {"AAA111"}


def test_query_usb_devices_orders_by_last_connected_desc() -> None:
    store = EventStore()
    store.insert_events([
        _usb("OLD", last_connected="2024-01-01T00:00:00Z"),
        _usb("NEW", last_connected="2026-01-01T00:00:00Z"),
        _usb("MID", last_connected="2025-01-01T00:00:00Z"),
    ])
    rows = store.query_usb_devices()
    serials = [r["serial"] for r in rows]
    assert serials == ["NEW", "MID", "OLD"]

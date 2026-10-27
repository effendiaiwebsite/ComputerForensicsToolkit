"""Regression tests for the review findings in the registry parsers.

Plugin inputs mirror the exact dict shapes regipy 6.5 emits (``as_json=True``)
rather than idealized fixtures, because mismatched key names are precisely
what the earlier suite failed to catch.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import parsers.registry as registry_module
import parsers.registry_amcache as amcache_module
import parsers.registry_ntuser as ntuser_module
import parsers.registry_sam as sam_module
import parsers.registry_system as system_module
from parsers._time import to_iso_utc
from parsers.registry_software import _emit_network_profile_events
from parsers.registry_system import _split_device_name


class _FakePlugin:
    """Stands in for a regipy ``Plugin``: constructed as ``Plugin(hive, as_json=True)``."""

    entries: object = None

    def __init__(self, hive, as_json=False):
        self.hive = hive
        self.as_json = as_json

    def run(self):
        return None


def _plugin_with(entries):
    return type("_Plugin", (_FakePlugin,), {"entries": entries})


class _UnreadableHive:
    def get_key(self, path):
        raise KeyError(path)


# ----- shared time helper -------------------------------------------------------


def test_to_iso_utc_normalizes_every_library_shape():
    assert to_iso_utc("2024-01-01T12:00:00+00:00") == "2024-01-01T12:00:00Z"  # regipy
    assert to_iso_utc("2024-01-01 12:00:00.123456") == "2024-01-01T12:00:00Z"  # python-evtx
    assert to_iso_utc("2024-01-01 12:00:00") == "2024-01-01T12:00:00Z"  # WinVer InstallDate
    assert to_iso_utc("01/15/2019 09:21:20") == "2019-01-15T09:21:20Z"  # AmCache LinkDate
    assert to_iso_utc("2026-06-11T12:00:00.000Z") == "2026-06-11T12:00:00Z"
    assert to_iso_utc(datetime(2024, 1, 1, 12, 0, 0)) == "2024-01-01T12:00:00Z"
    assert to_iso_utc(datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)) == "2024-01-01T12:00:00Z"
    assert (
        to_iso_utc("2024-01-01 12:00:00.123456", microseconds=True)
        == "2024-01-01T12:00:00.123456Z"
    )


def test_to_iso_utc_rejects_filetime_zero_and_garbage():
    assert to_iso_utc("1601-01-01T00:00:00+00:00") is None
    assert to_iso_utc(datetime(1601, 1, 1, tzinfo=UTC)) is None
    assert to_iso_utc(None) is None
    assert to_iso_utc("") is None
    assert to_iso_utc("not a date") is None
    assert to_iso_utc(12345) is None


# ----- NTUSER --------------------------------------------------------------------


def test_run_mru_emits_one_event_per_command(monkeypatch):
    entries = [{
        "key_path": r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "last_write": "2024-03-01T10:00:00+00:00",
        "mru_order": "ba",
        "commands": [
            {"letter": "b", "command": "powershell -enc AAAA"},
            {"letter": "a", "command": "cmd"},
        ],
    }]
    monkeypatch.setattr(ntuser_module, "RunMRUPlugin", _plugin_with(entries))

    events = ntuser_module._run_mru(None, r"C:\NTUSER.DAT", "c", "H", "alice")

    assert [e.evidence["command"] for e in events] == ["powershell -enc AAAA", "cmd"]
    assert [e.evidence["slot"] for e in events] == ["b", "a"]
    assert all(e.event_type == "shell_command" for e in events)
    assert all(e.timestamp == "2024-03-01T10:00:00Z" for e in events)
    assert all(e.timestamp_source == "inferred" for e in events)


def test_recent_docs_emits_one_event_per_document(monkeypatch):
    entries = [
        {
            "key_path": r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "last_write": "2024-03-01T10:00:00+00:00",
            "extension": None,
            "documents": [{"index": 3, "name": "budget.xlsx"}, {"index": 0, "name": "notes.txt"}],
        },
        {
            "key_path": r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xlsx",
            "last_write": "2024-03-01T10:00:00+00:00",
            "extension": ".xlsx",
            "documents": [{"index": 1, "name": "budget.xlsx"}],
        },
    ]
    monkeypatch.setattr(ntuser_module, "RecentDocsPlugin", _plugin_with(entries))

    events = ntuser_module._recent_docs(None, r"C:\NTUSER.DAT", "c", "H", "alice")

    assert [e.evidence["filename"] for e in events] == ["budget.xlsx", "notes.txt", "budget.xlsx"]
    assert events[2].evidence["extension"] == ".xlsx"
    assert events[0].evidence["mru_index"] == 3
    assert events[0].evidence["mru_order"] == 0
    assert all(e.timestamp == "2024-03-01T10:00:00Z" for e in events)


def test_user_assist_filetime_zero_is_not_a_timestamp(monkeypatch):
    entries = [
        {"name": "never-run.exe", "run_counter": 0, "timestamp": "1601-01-01T00:00:00+00:00"},
        {"name": "ran.exe", "run_counter": 2, "timestamp": "2024-03-01T10:00:00.5+00:00"},
    ]
    monkeypatch.setattr(ntuser_module, "UserAssistPlugin", _plugin_with(entries))

    events = ntuser_module._user_assist(None, r"C:\NTUSER.DAT", "c", "H", "alice")

    assert events[0].timestamp is None
    assert events[0].timestamp_source == "none"
    assert events[1].timestamp == "2024-03-01T10:00:00Z"
    assert events[1].timestamp_source == "direct"


# ----- SYSTEM --------------------------------------------------------------------


def test_shimcache_reads_regipy_last_mod_date(monkeypatch):
    entries = [{
        "path": r"C:\Windows\System32\cmd.exe",
        "last_mod_date": "2023-11-05T08:30:00+00:00",
        "exec_flag": "True",
    }]
    monkeypatch.setattr(system_module, "ShimCachePlugin", _plugin_with(entries))

    events = system_module._run_shimcache(None, r"C:\SYSTEM", "c", "H")

    assert events[0].timestamp == "2023-11-05T08:30:00Z"
    assert events[0].evidence["last_modified"] == "2023-11-05T08:30:00Z"
    assert events[0].evidence["program_path"] == r"C:\Windows\System32\cmd.exe"


def test_split_device_name_strips_usbstor_prefixes():
    parsed = _split_device_name("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00")
    assert parsed == ("SanDisk", "Cruzer", "1.00")
    assert _split_device_name("Disk&Ven_&Prod_USB_DISK&Rev_") == (None, "USB_DISK", None)
    assert _split_device_name("Disk&Ven_Kingston&Prod_DT") == (None, None, None)


# ----- AmCache -------------------------------------------------------------------


def test_amcache_reads_lower_case_long_path(monkeypatch):
    entries = [{
        "lower_case_long_path": r"c:\users\alice\appdata\local\temp\evil.exe",
        "sha1": "0000abc123",
        "size": 451584,
        "link_date": "01/15/2019 09:21:20",
        "timestamp": "1601-01-01T00:00:00+00:00",
    }]
    monkeypatch.setattr(amcache_module, "AmCachePlugin", _plugin_with(entries))

    events = amcache_module.parse_amcache_hive(
        __file__, collection_id="c", host_id_hint="H", hive=object(),
    )

    assert events[0].evidence["program_path"] == r"c:\users\alice\appdata\local\temp\evil.exe"
    assert events[0].evidence["link_date"] == "2019-01-15T09:21:20Z"
    assert events[0].timestamp == "2019-01-15T09:21:20Z"


# ----- SOFTWARE ------------------------------------------------------------------


def test_network_list_skips_signature_rows_and_marks_local_time():
    entries = [
        {
            "type": "profile",
            "key_path": r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}",
            "profile_guid": "{GUID}",
            "last_write": "2024-01-02T03:04:05+00:00",
            "profile_name": "CoffeeShopWiFi",
            "category": "Public",
            "name_type": "Wireless",
            "date_created": "2023-12-24T18:30:00",
            "date_last_connected": "2024-01-02T03:04:05",
        },
        {
            "type": "signature",
            "signature_type": "unmanaged",
            "key_path": (
                r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\0105"
            ),
            "signature_id": "0105",
            "last_write": "2024-01-02T03:04:05+00:00",
            "profile_guid": "{GUID}",
            "default_gateway_mac": "00:11:22:33:44:55",
        },
    ]

    events = list(_emit_network_profile_events(entries, r"C:\SOFTWARE", "c", "H"))

    assert len(events) == 1
    ev = events[0]
    assert ev.summary == "NetworkProfile: CoffeeShopWiFi"
    assert ev.timestamp == "2024-01-02T03:04:05Z"
    assert ev.timestamp_source == "inferred"
    assert ev.evidence["time_basis"] == "local"
    assert ev.evidence["first_connect"] == "2023-12-24T18:30:00Z"


# ----- SAM -----------------------------------------------------------------------


def test_sam_password_last_set_is_a_direct_timestamp(monkeypatch):
    entries = [{
        "rid": 1001,
        "key_path": r"\SAM\Domains\Account\Users\000003E9",
        "last_write": "2024-05-05T05:05:05+00:00",
        "username": "alice",
        "last_login": None,
        "password_last_set": "2024-04-04T04:04:04+00:00",
        "last_failed_login": None,
        "account_flags_parsed": ["Normal Account"],
    }]
    monkeypatch.setattr(sam_module, "SAMParsePlugin", _plugin_with(entries))

    events = sam_module.parse_sam_hive(
        __file__, collection_id="c", host_id_hint="H", hive=_UnreadableHive(),
    )

    assert events[0].timestamp == "2024-04-04T04:04:04Z"
    assert events[0].timestamp_source == "direct"
    assert events[0].evidence["password_last_set"] == "2024-04-04T04:04:04Z"
    assert events[0].evidence["username"] == "alice"


# ----- dispatcher ----------------------------------------------------------------


def test_detect_hive_kind_warns_without_traceback(tmp_path: Path, caplog):
    bogus = tmp_path / "SYSTEM"
    bogus.write_bytes(b"definitely not a hive")
    with caplog.at_level(logging.WARNING, logger="parsers.registry"):
        assert registry_module.detect_hive_kind(bogus) is None
    assert any("could not open" in r.getMessage() for r in caplog.records)
    assert "Traceback" not in caplog.text


def test_parse_hive_opens_the_hive_once_and_reuses_it(monkeypatch):
    opened: list[str] = []

    class _Hive:
        hive_type = "system"

        def __init__(self, path):
            opened.append(path)

    seen: dict[str, object] = {}

    def fake_parse_system_hive(path, *, collection_id, host_id_hint, hive=None):
        seen["hive"] = hive
        return []

    monkeypatch.setattr(registry_module, "RegistryHive", _Hive)
    monkeypatch.setattr(registry_module, "parse_system_hive", fake_parse_system_hive)

    kind, events = registry_module.parse_hive("X:/SYSTEM", collection_id="c", host_id_hint="H")

    assert kind == "system"
    assert events == []
    assert len(opened) == 1
    assert isinstance(seen["hive"], _Hive)

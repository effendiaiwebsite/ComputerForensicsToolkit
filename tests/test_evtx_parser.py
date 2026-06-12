"""Tests for the evtx parser — synthetic XML, no real .evtx file needed."""

from __future__ import annotations

from pathlib import Path

from collectors.windows.evtx import _channel_from_filename
from collectors.windows.user_hives import discover_evtx_files
from parsers.evtx import event_from_parsed_record, parse_record_xml


def _record_xml(*, channel: str, event_id: int, computer: str, data: dict[str, str]) -> str:
    data_xml = "".join(
        f"<Data Name='{name}'>{value}</Data>" for name, value in data.items()
    )
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        f"<EventID>{event_id}</EventID>"
        "<TimeCreated SystemTime='2026-06-11T12:00:00.000Z'/>"
        "<EventRecordID>42</EventRecordID>"
        f"<Channel>{channel}</Channel>"
        f"<Computer>{computer}</Computer>"
        "</System>"
        f"<EventData>{data_xml}</EventData>"
        "</Event>"
    )


def _kwargs(**overrides):
    base = dict(source_path=r"C:\Logs\Security.evtx", collection_id="col-1", host_id_hint="H")
    base.update(overrides)
    return base


def test_parse_record_xml_extracts_system_fields() -> None:
    xml = _record_xml(channel="Security", event_id=4624, computer="MSI", data={"TargetUserName": "alice"})
    rec = parse_record_xml(xml)
    assert rec is not None
    assert rec["event_id"] == 4624
    assert rec["channel"] == "Security"
    assert rec["computer"] == "MSI"
    assert rec["data"]["TargetUserName"] == "alice"
    assert rec["time_created"] == "2026-06-11T12:00:00.000Z"


def test_logon_success_maps_to_logon_event() -> None:
    rec = parse_record_xml(_record_xml(
        channel="Security",
        event_id=4624,
        computer="MSI",
        data={"TargetUserName": "alice", "LogonType": "2", "IpAddress": "10.0.0.5"},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "logon"
    assert "alice" in ev.summary
    assert "type 2" in ev.summary
    assert ev.user == "alice"
    assert ev.host_id == "MSI"
    assert ev.source_artifact == "evtx.security"


def test_logon_failed_maps_to_logon_with_status() -> None:
    rec = parse_record_xml(_record_xml(
        channel="Security",
        event_id=4625,
        computer="MSI",
        data={"TargetUserName": "bob", "SubStatus": "0xC000006A"},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "logon"
    assert "FAILED" in ev.summary
    assert "0xC000006A" in ev.summary


def test_service_install_emits_service_install_event() -> None:
    rec = parse_record_xml(_record_xml(
        channel="System",
        event_id=7045,
        computer="MSI",
        data={"ServiceName": "evilSvc", "ImagePath": r"C:\evil.exe"},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "service_install"
    assert "evilSvc" in ev.summary
    assert r"C:\evil.exe" in ev.summary


def test_log_cleared_is_security_event() -> None:
    rec = parse_record_xml(_record_xml(
        channel="Security",
        event_id=1102,
        computer="MSI",
        data={},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "security_event"
    assert "cleared" in ev.summary.lower()


def test_powershell_script_block_truncates_long_text() -> None:
    long = "Write-Host hi; " * 50
    rec = parse_record_xml(_record_xml(
        channel="Microsoft-Windows-PowerShell/Operational",
        event_id=4104,
        computer="MSI",
        data={"ScriptBlockText": long},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "shell_command"
    assert ev.summary.endswith("…")
    assert ev.source_artifact == "evtx.microsoft_windows_powershell_operational"


def test_task_registered_maps_to_scheduled_task() -> None:
    rec = parse_record_xml(_record_xml(
        channel="Microsoft-Windows-TaskScheduler/Operational",
        event_id=106,
        computer="MSI",
        data={"TaskName": "\\Foo\\Bar"},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "scheduled_task"
    assert "Bar" in ev.summary


def test_unknown_id_falls_back_to_security_event() -> None:
    rec = parse_record_xml(_record_xml(
        channel="Application",
        event_id=99999,
        computer="MSI",
        data={"Foo": "bar"},
    ))
    ev = event_from_parsed_record(rec, **_kwargs())
    assert ev.event_type == "security_event"
    assert "99999" in ev.summary


def test_channel_hint_used_when_record_lacks_channel() -> None:
    rec = parse_record_xml(_record_xml(
        channel="",
        event_id=4624,
        computer="MSI",
        data={"TargetUserName": "alice"},
    ))
    # parser hands us a record with empty channel
    ev = event_from_parsed_record(rec, channel_hint="Security", **_kwargs())
    assert ev.event_type == "logon"
    assert ev.source_artifact == "evtx.security"


def test_channel_from_filename_decodes_wevtutil_naming() -> None:
    assert _channel_from_filename("Security.evtx") == "Security"
    assert (
        _channel_from_filename("Microsoft-Windows-PowerShell%4Operational.evtx")
        == "Microsoft-Windows-PowerShell/Operational"
    )


def test_discover_evtx_files_finds_evtx_only(tmp_path: Path) -> None:
    (tmp_path / "Security.evtx").write_bytes(b"\x00")
    (tmp_path / "System.evtx").write_bytes(b"\x00")
    (tmp_path / "SYSTEM").write_bytes(b"\x00")  # registry hive, not evtx

    found = discover_evtx_files(tmp_path)
    names = sorted(f.path.name for f in found)
    assert names == ["Security.evtx", "System.evtx"]
    assert {f.channel_hint for f in found} == {"Security", "System"}

"""Windows event-log (.evtx) parser.

Decodes each record's XML, dispatches the focus EventIDs to dedicated
handlers, and falls back to a generic ``security_event`` so nothing the
analyst needs is silently dropped.

Focus channels and IDs come from ``docs/PHASE1_WINDOWS.md`` — Security
(4624/4625/4634/4672/4720/4732/1102), System (7045/7036),
``Microsoft-Windows-PowerShell/Operational`` (4104), and
``Microsoft-Windows-TaskScheduler/Operational`` (106/140/141).
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from Evtx.Evtx import Evtx

from core.events import Event, make_event
from parsers._time import to_iso_utc

PARSER_VERSION = "evtx/0.1.0"
HOST_OS = "windows"

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

logger = logging.getLogger(__name__)


def parse_evtx(
    evtx_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    channel_hint: str | None = None,
) -> list[Event]:
    """Stream events from a single ``.evtx`` file.

    ``channel_hint`` (typically from the filename) is used only when an
    individual record is missing its ``<Channel>`` element; in practice every
    well-formed record carries the channel inline.
    """
    path_str = str(Path(evtx_path).resolve())
    events: list[Event] = []
    try:
        with Evtx(path_str) as log:
            for record in log.records():
                try:
                    parsed = _parse_record_xml(record.xml())
                except ET.ParseError:
                    logger.debug("malformed XML record skipped", exc_info=True)
                    continue
                if not parsed:
                    continue
                ev = _to_event(
                    parsed,
                    hive_path=path_str,
                    collection_id=collection_id,
                    host_id_hint=host_id_hint,
                    channel_hint=channel_hint,
                )
                if ev is not None:
                    events.append(ev)
    except Exception:
        logger.exception("evtx open/iter failed for %s", path_str)
    return events


def _parse_record_xml(xml_str: str) -> dict[str, Any] | None:
    root = ET.fromstring(xml_str)
    system = root.find(f"{_NS}System")
    if system is None:
        return None

    event_id_text = system.findtext(f"{_NS}EventID")
    try:
        event_id_int = int(event_id_text) if event_id_text is not None else None
    except ValueError:
        event_id_int = None

    time_el = system.find(f"{_NS}TimeCreated")
    time_created = time_el.get("SystemTime") if time_el is not None else None

    provider_el = system.find(f"{_NS}Provider")
    provider = provider_el.get("Name") if provider_el is not None else None

    channel = system.findtext(f"{_NS}Channel")
    computer = system.findtext(f"{_NS}Computer")
    record_id_text = system.findtext(f"{_NS}EventRecordID")
    record_id = int(record_id_text) if record_id_text and record_id_text.isdigit() else None

    data: dict[str, Any] = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{_NS}Data"):
            name = d.get("Name") or f"_pos_{len(data)}"
            data[name] = d.text

    user_data = root.find(f"{_NS}UserData")
    user_data_dict: dict[str, Any] = {}
    if user_data is not None:
        for child in user_data.iter():
            tag = child.tag.split("}")[-1]
            if child.text and child.text.strip():
                user_data_dict[tag] = child.text

    return {
        "event_id": event_id_int,
        "time_created": time_created,
        "channel": channel,
        "computer": computer,
        "provider": provider,
        "record_id": record_id,
        "data": data,
        "user_data": user_data_dict,
    }


def _to_event(
    record: dict[str, Any],
    *,
    hive_path: str,
    collection_id: str,
    host_id_hint: str,
    channel_hint: str | None,
) -> Event | None:
    channel = record.get("channel") or channel_hint or "<unknown>"
    event_id_int = record.get("event_id")
    if event_id_int is None:
        return None

    host_id = record.get("computer") or host_id_hint
    data = record.get("data") or {}
    user = _user_from_data(data, event_id_int)

    handler = _HANDLERS.get((channel, event_id_int))
    if handler is None:
        event_type, summary = _generic_fallback(channel, event_id_int, record)
    else:
        event_type, summary = handler(record)

    # EventData goes in first so a record cannot shadow the fixed keys
    # (a provider is free to name a Data element "channel" or "event_id").
    evidence: dict[str, Any] = {
        **data,
        "channel": channel,
        "event_id": event_id_int,
        "provider": record.get("provider"),
        "record_id": record.get("record_id"),
    }

    return make_event(
        host_os=HOST_OS,
        host_id=host_id,
        user=user,
        source_artifact=_source_artifact(channel),
        source_path=hive_path,
        event_type=event_type,
        summary=summary,
        evidence=evidence,
        collection_id=collection_id,
        parser_version=PARSER_VERSION,
        # python-evtx renders SystemTime as ``filetime().isoformat(" ")``:
        # space-separated, no zone suffix. Sub-second precision is kept because
        # event-log ordering within one second is routinely significant.
        timestamp=to_iso_utc(record.get("time_created"), microseconds=True),
        raw=record,
    )


_NON_USERS = {"-", "ANONYMOUS LOGON", "SYSTEM"}

# Group-membership audits (4728/4732/4756 add, 4729/4733/4757 remove): here
# TargetUserName is the *group*; the account of interest is the member.
_GROUP_MEMBERSHIP_IDS = {4728, 4729, 4732, 4733, 4756, 4757}


def _user_from_data(data: dict[str, Any], event_id: int | None = None) -> str | None:
    """Best-effort user attribution from the well-known EventData fields."""
    keys: tuple[str, ...]
    if event_id in _GROUP_MEMBERSHIP_IDS:
        keys = ("MemberName", "SubjectUserName")
    else:
        keys = ("TargetUserName", "SubjectUserName", "AccountName", "UserName", "User")
    for key in keys:
        v = data.get(key)
        if v and v not in _NON_USERS:
            return _account_from_member_name(str(v)) if key == "MemberName" else str(v)
    return None


def _account_from_member_name(member: str) -> str:
    """``MemberName`` is a distinguished name on domain controllers
    (``CN=bob,CN=Users,DC=corp,DC=local``); reduce it to the leaf CN."""
    if member.upper().startswith("CN="):
        return member.split(",", 1)[0][3:]
    return member


def _source_artifact(channel: str) -> str:
    return f"evtx.{channel.lower().replace('/', '_').replace('-', '_').replace(' ', '_')}"


# --- Per-EventID handlers -------------------------------------------------

def _logon_success(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    user = d.get("TargetUserName") or "<unknown>"
    logon_type = d.get("LogonType")
    src_ip = d.get("IpAddress") or d.get("WorkstationName") or "?"
    return "logon", f"Logon success: {user} (type {logon_type}, src {src_ip})"


def _logon_failed(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    user = d.get("TargetUserName") or "<unknown>"
    sub_status = d.get("SubStatus") or d.get("Status")
    src_ip = d.get("IpAddress") or "?"
    return "logon", f"Logon FAILED: {user} (status {sub_status}, src {src_ip})"


def _logoff(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    user = d.get("TargetUserName") or "<unknown>"
    logon_type = d.get("LogonType")
    return "logoff", f"Logoff: {user} (type {logon_type})"


def _special_privs(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    user = d.get("SubjectUserName") or "<unknown>"
    return "logon", f"Special privileges assigned to logon: {user}"


def _account_create(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    new = d.get("TargetUserName") or "<unknown>"
    by = d.get("SubjectUserName") or "?"
    return "account_change", f"Account created: {new} (by {by})"


def _group_member_add(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    group = d.get("TargetUserName") or "<group>"
    member = d.get("MemberName") or d.get("MemberSid") or "?"
    return "account_change", f"Member added to group {group}: {member}"


def _log_cleared(_rec: dict[str, Any]) -> tuple[str, str]:
    return "security_event", "Audit log cleared (Security 1102)"


def _service_install(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    name = d.get("ServiceName") or "<unknown>"
    image = d.get("ImagePath") or "?"
    return "service_install", f"Service installed via SCM: {name} → {image}"


def _service_state_change(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    name = d.get("param1") or d.get("ServiceName") or "<unknown>"
    state = d.get("param2") or "?"
    return "system_config_change", f"Service state change: {name} → {state}"


def _powershell_script_block(rec: dict[str, Any]) -> tuple[str, str]:
    d = rec["data"]
    block_text = d.get("ScriptBlockText") or ""
    snippet = block_text.replace("\n", " ").strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "…"
    return "shell_command", f"PowerShell script block: {snippet or '<empty>'}"


def _task_registered(rec: dict[str, Any]) -> tuple[str, str]:
    name = _task_name(rec)
    return "scheduled_task", f"Task registered: {name}"


def _task_updated(rec: dict[str, Any]) -> tuple[str, str]:
    name = _task_name(rec)
    return "scheduled_task", f"Task updated: {name}"


def _task_deleted(rec: dict[str, Any]) -> tuple[str, str]:
    name = _task_name(rec)
    return "scheduled_task", f"Task deleted: {name}"


def _task_name(rec: dict[str, Any]) -> str:
    for key in ("TaskName", "Name"):
        v = rec["data"].get(key) or rec.get("user_data", {}).get(key)
        if v:
            return str(v)
    return "<unknown>"


def _generic_fallback(channel: str, event_id: int, _rec: dict[str, Any]) -> tuple[str, str]:
    return "security_event", f"{channel} EventID {event_id}"


_HANDLERS: dict[tuple[str, int], Callable[[dict[str, Any]], tuple[str, str]]] = {
    ("Security", 4624): _logon_success,
    ("Security", 4625): _logon_failed,
    ("Security", 4634): _logoff,
    ("Security", 4672): _special_privs,
    ("Security", 4720): _account_create,
    ("Security", 4732): _group_member_add,
    ("Security", 1102): _log_cleared,
    ("System", 7045): _service_install,
    ("System", 7036): _service_state_change,
    ("Microsoft-Windows-PowerShell/Operational", 4104): _powershell_script_block,
    ("Microsoft-Windows-TaskScheduler/Operational", 106): _task_registered,
    ("Microsoft-Windows-TaskScheduler/Operational", 140): _task_updated,
    ("Microsoft-Windows-TaskScheduler/Operational", 141): _task_deleted,
}


# --- Test helpers (also used by callers that already have a record dict) --

def event_from_parsed_record(
    record: dict[str, Any],
    *,
    source_path: str,
    collection_id: str,
    host_id_hint: str,
    channel_hint: str | None = None,
) -> Event | None:
    """Public alias of ``_to_event`` for tests that feed pre-parsed records."""
    return _to_event(
        record,
        hive_path=source_path,
        collection_id=collection_id,
        host_id_hint=host_id_hint,
        channel_hint=channel_hint,
    )


def parse_record_xml(xml_str: str) -> dict[str, Any] | None:
    """Public alias of the internal XML decoder."""
    return _parse_record_xml(xml_str)


def parse_records(records: Iterable[Any], **kwargs: Any) -> list[Event]:  # pragma: no cover
    """Drive ``_to_event`` from any iterable yielding parsed records — used in tests."""
    out: list[Event] = []
    for r in records:
        ev = _to_event(r, **kwargs)
        if ev is not None:
            out.append(ev)
    return out

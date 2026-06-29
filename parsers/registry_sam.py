"""SAM hive parser — one ``account_change`` event per local user.

regipy's ``SAMParsePlugin`` returns each account's RID and login metadata but
not the **username** (it never decodes the ``V`` structure's account-name
field). We decode it ourselves and combine the machine SID (from
``SAM\\Domains\\Account``) with each RID to produce the full account SID — the
two facts an examiner usually needs from SAM.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

from regipy.plugins.sam.samparse import SAMParsePlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event

PARSER_VERSION = "sam_hive/0.2.0"
SOURCE_ARTIFACT = "registry.sam"
HOST_OS = "windows"

logger = logging.getLogger(__name__)

# Account ``V`` structure: a header of {offset, length, ...} entries followed by
# a data section starting at 0xCC. The relevant header entries:
_V_DATA_BASE = 0xCC
_V_NAME_HEADER = 0x0C       # account name (username)
_V_FULLNAME_HEADER = 0x18   # full name


def parse_sam_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
) -> list[Event]:
    hive_path_str = str(Path(hive_path).resolve())
    hive = RegistryHive(hive_path_str)
    plugin = SAMParsePlugin(hive, as_json=True)
    try:
        plugin.run()
    except Exception:
        logger.exception("SAMParsePlugin failed")
        return []

    machine_sid = _machine_sid(hive)

    events: list[Event] = []
    for entry in plugin.entries or []:
        rid = entry.get("rid")
        decoded_name, decoded_full = _decode_account_v(hive, entry.get("key_path"))
        username = decoded_name or entry.get("username") or f"RID {rid}"
        sid = f"{machine_sid}-{rid}" if machine_sid and rid is not None else None
        last_logon = entry.get("last_logon")
        password_last_set = entry.get("password_last_set")
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id_hint,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path_str,
                event_type="account_change",
                user=username if isinstance(username, str) else None,
                summary=f"Local account: {username} (RID {rid}, SID {sid or '?'})",
                evidence={
                    "rid": rid,
                    "username": decoded_name or entry.get("username"),
                    "sid": sid,
                    "machine_sid": machine_sid,
                    "full_name": decoded_full or entry.get("full_name"),
                    "comment": entry.get("comment"),
                    "account_disabled": entry.get("account_disabled"),
                    "account_locked": entry.get("account_locked"),
                    "password_required": entry.get("password_required"),
                    "password_last_set": password_last_set,
                    "last_logon": last_logon,
                    "last_password_failure": entry.get("last_password_failure"),
                    "login_count": entry.get("login_count"),
                    "key_path": entry.get("key_path"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=last_logon or password_last_set or entry.get("last_write"),
                timestamp_source="direct" if last_logon else ("inferred" if entry.get("last_write") else "none"),
                raw=entry,
            )
        )
    return events


def _machine_sid(hive: RegistryHive) -> str | None:
    """Derive the machine SID from ``SAM\\Domains\\Account``'s ``V`` value.

    The final 12 bytes are three little-endian DWORD sub-authorities of the
    ``S-1-5-21-x-y-z`` machine SID.
    """
    try:
        v = _as_bytes(hive.get_key(r"\SAM\Domains\Account").get_value("V"))
    except Exception:  # absent/unreadable on partial hives
        return None
    if not v or len(v) < 12:
        return None
    try:
        d1, d2, d3 = struct.unpack_from("<III", v[-12:])
    except struct.error:
        return None
    return f"S-1-5-21-{d1}-{d2}-{d3}"


def _decode_account_v(hive: RegistryHive, key_path: str | None) -> tuple[str | None, str | None]:
    """Decode (username, full_name) from a user's ``V`` value."""
    if not key_path:
        return None, None
    try:
        v = _as_bytes(hive.get_key(key_path).get_value("V"))
    except Exception:
        return None, None
    if not v:
        return None, None
    return _v_string(v, _V_NAME_HEADER), _v_string(v, _V_FULLNAME_HEADER)


def _v_string(v: bytes, header_off: int) -> str | None:
    """Read a UTF-16LE string whose {offset, length} header sits at ``header_off``."""
    if len(v) < header_off + 8:
        return None
    try:
        rel_off, length = struct.unpack_from("<II", v, header_off)
    except struct.error:
        return None
    start = _V_DATA_BASE + rel_off
    if length <= 0 or start < 0 or start + length > len(v):
        return None
    text = v[start:start + length].decode("utf-16-le", errors="replace").strip("\x00")
    return text or None


def _as_bytes(value: object) -> bytes:
    if isinstance(value, bytes | bytearray):
        return bytes(value)
    return b""

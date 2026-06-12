"""SAM hive parser — one ``account_change`` event per local user."""

from __future__ import annotations

import logging
from pathlib import Path

from regipy.plugins.sam.samparse import SAMParsePlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event

PARSER_VERSION = "sam_hive/0.1.0"
SOURCE_ARTIFACT = "registry.sam"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


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

    events: list[Event] = []
    for entry in plugin.entries or []:
        username = entry.get("username") or f"RID {entry.get('rid')}"
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
                summary=f"Local account: {username} (RID {entry.get('rid')})",
                evidence={
                    "rid": entry.get("rid"),
                    "username": entry.get("username"),
                    "full_name": entry.get("full_name"),
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

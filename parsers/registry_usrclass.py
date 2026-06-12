"""UsrClass.dat parser — ShellBag entries become ``file_access`` events.

ShellBags persist every folder a user has navigated to in Explorer, even
folders that have since been deleted — a foundational source for proving
user knowledge of a path.
"""

from __future__ import annotations

import logging
from pathlib import Path

from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin
from regipy.registry import RegistryHive

from core.events import Event, make_event

PARSER_VERSION = "usrclass_hive/0.1.0"
SOURCE_ARTIFACT = "registry.usrclass"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_usrclass_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    hive_path_str = str(Path(hive_path).resolve())
    hive = RegistryHive(hive_path_str)
    plugin = ShellBagUsrclassPlugin(hive, as_json=True)
    try:
        plugin.run()
    except ModuleNotFoundError:
        logger.warning("pyfwsi not available — UsrClass shellbags skipped")
        return []
    except Exception:
        logger.exception("ShellBagUsrclassPlugin failed")
        return []

    events: list[Event] = []
    for entry in plugin.entries or []:
        path = entry.get("path") or entry.get("value") or "<unknown>"
        shell_type = entry.get("shell_type")
        events.append(
            make_event(
                host_os=HOST_OS,
                host_id=host_id_hint,
                user=user_hint,
                source_artifact=SOURCE_ARTIFACT,
                source_path=hive_path_str,
                event_type="file_access",
                summary=f"ShellBag ({shell_type}): {path}",
                evidence={
                    "path": path,
                    "shell_type": shell_type,
                    "creation_time": entry.get("creation_time"),
                    "access_time": entry.get("access_time"),
                    "modification_time": entry.get("modification_time"),
                    "mru_order_location": entry.get("mru_order_location"),
                    "reg_path": entry.get("reg_path"),
                },
                collection_id=collection_id,
                parser_version=PARSER_VERSION,
                timestamp=entry.get("modification_time")
                or entry.get("access_time")
                or entry.get("creation_time")
                or entry.get("last_write"),
                raw=entry,
            )
        )
    return events

"""Top-level registry-hive entry point.

Detects the hive type via regipy's header parser and dispatches to the
appropriate per-hive parser. The hive-kind hint (passed when the caller
already knows what it dumped) wins over auto-detection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from regipy.registry import RegistryHive

from core.events import Event
from parsers.registry_amcache import parse_amcache_hive
from parsers.registry_ntuser import parse_ntuser_hive
from parsers.registry_sam import parse_sam_hive
from parsers.registry_software import parse_software_hive
from parsers.registry_system import parse_system_hive
from parsers.registry_usrclass import parse_usrclass_hive

HiveKind = Literal["system", "software", "sam", "ntuser", "usrclass", "amcache"]

logger = logging.getLogger(__name__)


def _open_hive(hive_path: str | Path) -> RegistryHive | None:
    """regipy reads the whole file into memory on open, so a non-hive (or a
    truncated one) fails fast here; that is expected for stray files in a
    triage directory and logged without a traceback."""
    try:
        return RegistryHive(str(hive_path))
    except Exception as exc:
        logger.warning("could not open %s as a registry hive: %s", hive_path, exc)
        return None


def detect_hive_kind(hive_path: str | Path) -> str | None:
    """Return the regipy ``hive_type`` for the file, or ``None`` if not detectable."""
    hive = _open_hive(hive_path)
    return hive.hive_type if hive is not None else None


def parse_hive(
    hive_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    kind: HiveKind | None = None,
    user_hint: str | None = None,
) -> tuple[str, list[Event]]:
    """Parse any supported hive. Returns ``(kind, events)``.

    The hive is opened once; the same ``RegistryHive`` is handed to the
    per-kind parser so a SOFTWARE hive is not read into memory twice.

    Raises ``ValueError`` for unknown hive types so the IPC layer can return
    a clear error to the UI instead of silently swallowing the bytes.
    """
    hive = _open_hive(hive_path)
    detected = kind or (hive.hive_type if hive is not None else None)
    if detected is None:
        raise ValueError(f"could not detect hive type for {hive_path}")
    detected = detected.lower()

    if detected == "system":
        return detected, parse_system_hive(
            hive_path, collection_id=collection_id, host_id_hint=host_id_hint, hive=hive,
        )
    if detected == "software":
        return detected, parse_software_hive(
            hive_path, collection_id=collection_id, host_id_hint=host_id_hint, hive=hive,
        )
    if detected == "sam":
        return detected, parse_sam_hive(
            hive_path, collection_id=collection_id, host_id_hint=host_id_hint, hive=hive,
        )
    if detected == "ntuser":
        return detected, parse_ntuser_hive(
            hive_path, collection_id=collection_id, host_id_hint=host_id_hint,
            user_hint=user_hint, hive=hive,
        )
    if detected == "usrclass":
        return detected, parse_usrclass_hive(
            hive_path, collection_id=collection_id, host_id_hint=host_id_hint,
            user_hint=user_hint, hive=hive,
        )
    if detected == "amcache":
        return detected, parse_amcache_hive(
            hive_path, collection_id=collection_id, host_id_hint=host_id_hint, hive=hive,
        )

    raise ValueError(f"unsupported hive type: {detected!r}")

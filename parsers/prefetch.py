"""Windows Prefetch (.pf) parser via ``pyscca``.

One ``program_execution`` event per .pf file. The timestamp of the event is
the **most recent** run time from the file's slot array. Up to seven prior
runs (Win8+) land in evidence alongside the run counter, accessed-file list,
and per-volume metadata so the rule engine can correlate Prefetch with
AmCache and ShimCache.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyscca

from core.events import Event, make_event

PARSER_VERSION = "prefetch/0.1.0"
SOURCE_ARTIFACT = "prefetch"
HOST_OS = "windows"

logger = logging.getLogger(__name__)


def parse_prefetch(
    pf_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
) -> list[Event]:
    path_str = str(Path(pf_path).resolve())
    try:
        scca = pyscca.file()
        scca.open(path_str)
    except Exception:
        logger.exception("could not open prefetch %s", path_str)
        return []
    try:
        return [_event_from_pf(scca, path_str, collection_id, host_id_hint)]
    except Exception:
        logger.exception("could not parse prefetch %s", path_str)
        return []
    finally:
        try:
            scca.close()
        except Exception:
            pass


def _event_from_pf(
    scca: Any,
    source_path: str,
    collection_id: str,
    host_id_hint: str,
) -> Event:
    exe_name = _safe_attr(scca, "executable_filename") or "<unknown>"
    run_count = _safe_attr(scca, "run_count")
    format_version = _safe_attr(scca, "format_version")
    prefetch_hash = _safe_attr(scca, "prefetch_hash")

    run_times = _collect_run_times(scca)
    last_run = run_times[0] if run_times else None

    accessed_files = _collect_file_metrics(scca)
    program_path = _guess_program_path(exe_name, accessed_files)
    volumes = _collect_volumes(scca)

    summary = (
        f"Prefetch: {exe_name} (runs={run_count}, last={last_run or '?'})"
    )

    return make_event(
        host_os=HOST_OS,
        host_id=host_id_hint,
        source_artifact=SOURCE_ARTIFACT,
        source_path=source_path,
        event_type="program_execution",
        summary=summary,
        evidence={
            "program_path": program_path,
            "executable_filename": exe_name,
            "run_count": run_count,
            "prefetch_hash": f"0x{prefetch_hash:08X}" if isinstance(prefetch_hash, int) else prefetch_hash,
            "format_version": format_version,
            "last_run_time": last_run,
            "previous_run_times": run_times[1:] if len(run_times) > 1 else [],
            "accessed_files_count": len(accessed_files),
            "volume_count": len(volumes),
            "volumes": volumes,
        },
        collection_id=collection_id,
        parser_version=PARSER_VERSION,
        timestamp=last_run,
        raw={
            "executable_filename": exe_name,
            "run_count": run_count,
            "format_version": format_version,
            "prefetch_hash": prefetch_hash,
            "run_times": run_times,
            "accessed_files": accessed_files[:50],
            "volumes": volumes,
        },
    )


def _safe_attr(obj: Any, name: str) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return None


def _collect_run_times(scca: Any) -> list[str]:
    """Return non-empty last-run times newest-first as ISO strings (UTC).

    Prefetch v17/v23 only use slot 0; v26/v30/v31 expose up to 8 slots.
    """
    out: list[str] = []
    for i in range(8):
        try:
            dt = scca.get_last_run_time(i)
        except (IOError, OSError, ValueError):
            continue
        except Exception:
            continue
        if dt is None:
            continue
        if isinstance(dt, datetime):
            iso = _to_utc_iso(dt)
            if iso:
                out.append(iso)
    return out


def _to_utc_iso(dt: datetime) -> str | None:
    if dt.year < 1970:  # FILETIME zero translates to year ~1601; skip.
        return None
    if dt.tzinfo is None:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _collect_file_metrics(scca: Any) -> list[str]:
    out: list[str] = []
    n = _safe_attr(scca, "number_of_file_metrics_entries") or 0
    for i in range(n):
        try:
            entry = scca.get_file_metrics_entry(i)
            name = getattr(entry, "filename", None)
        except Exception:
            continue
        if name:
            out.append(str(name))
    return out


def _collect_volumes(scca: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    n = _safe_attr(scca, "number_of_volumes") or 0
    for i in range(n):
        try:
            v = scca.get_volume_information(i)
            entry: dict[str, Any] = {}
            for attr in ("device_path", "serial_number"):
                val = getattr(v, attr, None)
                if val is not None:
                    entry[attr] = (
                        f"0x{val:08X}" if attr == "serial_number" and isinstance(val, int) else val
                    )
            creation_time = getattr(v, "creation_time", None)
            if isinstance(creation_time, datetime):
                entry["creation_time"] = _to_utc_iso(creation_time)
            out.append(entry)
        except Exception:
            continue
    return out


def _guess_program_path(exe_name: str | None, accessed_files: list[str]) -> str | None:
    """Pick the accessed-file path whose basename matches the executable name."""
    if not exe_name:
        return None
    target = exe_name.upper()
    for path in accessed_files:
        if path.upper().endswith("\\" + target):
            return path
    return None

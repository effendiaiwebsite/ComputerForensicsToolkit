"""Live Windows disk collection via ``dissect.target``.

Reads forensic artifacts straight off ``\\\\.\\PhysicalDriveN`` (or a raw /
E01 image) without touching the source bytes. Each artifact is hashed
(SHA-256) and copied to a mirrored destination layout so the existing
``run_triage_directory`` flow can ingest it unchanged. Every read attempt
— success, skip, error — lands in the audit log so the chain of custody
is traceable.

Admin / root required for live ``\\\\.\\PhysicalDrive`` access. For dev
on a non-admin shell, point at a disk image instead:

    enumerate_physical_drives()      # admin only
    target.open("X:/some/image.E01")  # works without admin
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.audit import AuditLog
from core.progress import ProgressTracker

if TYPE_CHECKING:
    from dissect.target import Target
    from dissect.target.helpers.fsutil import TargetPath

logger = logging.getLogger(__name__)

_READ_CHUNK = 1024 * 1024


# ---------- drive enumeration ------------------------------------------------


@dataclass
class PhysicalDrive:
    device: str
    model: str
    size_bytes: int
    serial: str | None = None


def enumerate_physical_drives() -> list[PhysicalDrive]:
    """List ``\\\\.\\PhysicalDriveN`` devices via PowerShell ``Get-Disk``.

    Falls back to an empty list (with a logged warning) if the call fails
    — typical causes: non-Windows host, missing PowerShell, or non-admin
    where ``Get-Disk`` returns nothing.
    """
    if sys.platform != "win32":
        return []
    try:
        ps = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Disk | Select-Object Number, FriendlyName, Size, SerialNumber | "
                "ConvertTo-Json -Compress",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Get-Disk failed: %s", exc)
        return []
    if ps.returncode != 0 or not ps.stdout.strip():
        logger.warning("Get-Disk returned no data (rc=%s, stderr=%s)", ps.returncode, ps.stderr.strip())
        return []
    import json as _json

    try:
        data = _json.loads(ps.stdout)
    except _json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    out: list[PhysicalDrive] = []
    for entry in data:
        num = entry.get("Number")
        if num is None:
            continue
        out.append(PhysicalDrive(
            device=f"\\\\.\\PhysicalDrive{int(num)}",
            model=str(entry.get("FriendlyName") or "Unknown"),
            size_bytes=int(entry.get("Size") or 0),
            serial=(str(entry.get("SerialNumber")).strip() or None) if entry.get("SerialNumber") else None,
        ))
    return out


# ---------- artifact list ----------------------------------------------------


@dataclass
class ArtifactSpec:
    """Where a file lives on the source and where it goes in dest.

    ``user_relative`` paths are evaluated under each user's home directory;
    ``system_path`` paths are absolute starting from the system root.
    """
    label: str
    category: str
    system_path: str | None = None
    user_relative: str | None = None
    glob: bool = False  # treat the final path segment as a glob


_SYSTEM_ARTIFACTS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("SYSTEM hive",   "registry", system_path="/Windows/System32/config/SYSTEM"),
    ArtifactSpec("SOFTWARE hive", "registry", system_path="/Windows/System32/config/SOFTWARE"),
    ArtifactSpec("SAM hive",      "registry", system_path="/Windows/System32/config/SAM"),
    ArtifactSpec("SECURITY hive", "registry", system_path="/Windows/System32/config/SECURITY"),
    ArtifactSpec("AmCache",       "registry", system_path="/Windows/AppCompat/Programs/Amcache.hve"),
)

_SYSTEM_GLOBS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("Prefetch",      "prefetch", system_path="/Windows/Prefetch", glob=True),
    ArtifactSpec("Event logs",    "evtx",     system_path="/Windows/System32/winevt/Logs", glob=True),
)

_USER_ARTIFACTS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("NTUSER.DAT",         "registry", user_relative="NTUSER.DAT"),
    ArtifactSpec("UsrClass.dat",       "registry", user_relative="AppData/Local/Microsoft/Windows/UsrClass.dat"),
    ArtifactSpec("Chrome History",     "browser",  user_relative="AppData/Local/Google/Chrome/User Data/Default/History"),
    ArtifactSpec("Edge History",       "browser",  user_relative="AppData/Local/Microsoft/Edge/User Data/Default/History"),
    ArtifactSpec("Brave History",      "browser",  user_relative="AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History"),
)

_USER_GLOBS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("Recent LNKs",        "lnk",      user_relative="AppData/Roaming/Microsoft/Windows/Recent", glob=True),
    ArtifactSpec("JumpLists",          "jumplist", user_relative="AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations", glob=True),
)


# ---------- the collection driver -------------------------------------------


@dataclass
class LiveCollectionResult:
    collection_id: str
    source: str
    dest_dir: str
    audit_path: str
    files_collected: int
    bytes_collected: int
    errors: int


class NoWindowsVolumeError(RuntimeError):
    """Raised when none of the canonical Windows system hives are reachable.

    Triggered after the first pass over SYSTEM/SOFTWARE/SAM/SECURITY/AmCache
    if every one came back 'not present' — strong signal the image isn't a
    Windows volume (or dissect mounted it at an unexpected path), and we
    should bail before grinding through thousands of per-user skips.
    """


def collect_live(
    target: Any,  # dissect.target.Target — typed Any to keep import optional at type-check time
    *,
    collection_id: str,
    dest_dir: str | Path,
    audit: AuditLog,
    progress: ProgressTracker,
    source_label: str,
) -> LiveCollectionResult:
    """Walk ``target`` and mirror every known artifact into ``dest_dir``.

    Caller wires audit + progress. We do the file IO. Each artifact is read
    via dissect.target's filesystem (``target.fs.path``) and written
    chunk-by-chunk while updating a SHA-256, so we never load multi-GB
    hives into memory.

    Raises :class:`NoWindowsVolumeError` when the five canonical system
    hives are all missing — typical when the user pointed us at a
    non-Windows image — so the UI surfaces a clear message instead of
    hanging on the rest of the spec list.
    """
    dest_root = Path(dest_dir).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    # Phase 1: probe the system hives. If none are present, abort.
    system_specs = [
        (spec, target.fs.path(spec.system_path), spec.system_path.lstrip("/"))
        for spec in _SYSTEM_ARTIFACTS
    ]
    progress.update(collection_id, total=len(system_specs))

    counters = _Counters()
    for spec, src_path, dest_rel in system_specs:
        _process_one(
            spec, src_path, dest_root / dest_rel,
            collection_id=collection_id, audit=audit, progress=progress,
            dest_root=dest_root, counters=counters,
        )

    if counters.files == 0:
        mounts = _describe_mounts(target)
        raise NoWindowsVolumeError(
            f"None of {len(_SYSTEM_ARTIFACTS)} canonical Windows system hives were "
            f"found at the expected paths. dissect saw these mount points: "
            f"{mounts or '(none)'}. Pick a Windows disk image, or use Live local system."
        )

    # Phase 2: the rest of the spec list (system globs + per-user files + globs).
    rest = list(_enumerate_user_and_glob_specs(target))
    progress.update(collection_id, total=len(system_specs) + len(rest))
    for spec, src_path, dest_rel in rest:
        _process_one(
            spec, src_path, dest_root / dest_rel,
            collection_id=collection_id, audit=audit, progress=progress,
            dest_root=dest_root, counters=counters,
        )

    return LiveCollectionResult(
        collection_id=collection_id,
        source=source_label,
        dest_dir=str(dest_root),
        audit_path=str(audit.path),
        files_collected=counters.files,
        bytes_collected=counters.total_bytes,
        errors=counters.errors,
    )


@dataclass
class _Counters:
    files: int = 0
    total_bytes: int = 0
    errors: int = 0


def _process_one(
    spec: ArtifactSpec,
    src_path: Any,
    dest_full: Path,
    *,
    collection_id: str,
    audit: AuditLog,
    progress: ProgressTracker,
    dest_root: Path,
    counters: _Counters,
) -> None:
    progress.update(collection_id, current_item=str(src_path))
    try:
        sha, size = _stream_copy(None, src_path, dest_full)
        audit.ok(
            action="copy",
            source_path=str(src_path),
            dest_path=str(dest_full.relative_to(dest_root)),
            sha256=sha,
            size_bytes=size,
            category=spec.category,
            label=spec.label,
        )
        counters.files += 1
        counters.total_bytes += size
        progress.update(collection_id, completed_delta=1, category=spec.category)
    except FileNotFoundError:
        audit.skipped("copy", str(src_path), "not present", category=spec.category, label=spec.label)
        progress.update(collection_id, completed_delta=1)
    except Exception as exc:
        logger.exception("collection failed for %s", src_path)
        audit.error("copy", str(src_path), exc, category=spec.category, label=spec.label)
        counters.errors += 1
        progress.update(collection_id, completed_delta=1)


def _describe_mounts(target: Any) -> str:
    """Best-effort: list dissect's mount points so the user can see what it saw."""
    out: list[str] = []
    try:
        for fs in getattr(target, "filesystems", []) or []:
            mp = getattr(fs, "mountpoints", None) or [getattr(fs, "path", None)]
            for m in mp:
                if m:
                    out.append(str(m))
    except Exception:  # noqa: BLE001
        pass
    return ", ".join(sorted(set(out)))


# ---------- spec → concrete (src_path, dest_path) pairs ---------------------


def _enumerate_user_and_glob_specs(target: Any) -> Iterator[tuple[ArtifactSpec, Any, str]]:
    """Materialize all ArtifactSpecs except the system single-file hives.

    Called only after Phase 1 has confirmed at least one system hive landed,
    so we don't spend minutes walking per-user paths on a non-Windows image.
    Yields ``(spec, src_target_path, dest_rel_path_str)``.
    """
    # System-wide globbed dirs — copy every regular file under them.
    for spec in _SYSTEM_GLOBS:
        assert spec.system_path is not None
        root = target.fs.path(spec.system_path)
        for entry in _iter_files(root):
            rel = _relativize(entry, root)
            dest_rel = spec.system_path.lstrip("/") + "/" + rel
            yield spec, entry, dest_rel

    # Per-user artifacts.
    for user in _iter_users(target):
        home = user["home"]
        if home is None:
            continue
        user_dest_root = f"Users/{user['name']}"

        for spec in _USER_ARTIFACTS:
            assert spec.user_relative is not None
            src = target.fs.path(f"{home}/{spec.user_relative}")
            dest_rel = f"{user_dest_root}/{spec.user_relative}"
            yield spec, src, dest_rel

        for spec in _USER_GLOBS:
            assert spec.user_relative is not None
            root = target.fs.path(f"{home}/{spec.user_relative}")
            for entry in _iter_files(root):
                rel = _relativize(entry, root)
                dest_rel = f"{user_dest_root}/{spec.user_relative}/{rel}"
                yield spec, entry, dest_rel


def _iter_users(target: Any) -> Iterator[dict[str, Any]]:
    """Yield ``{name, home}`` per user.

    Prefers ``target.user_details.all()`` (rich plugin output); falls back
    to walking ``/Users`` directly if the plugin isn't available (which
    happens on minimal fake targets we use in tests).
    """
    try:
        for ud in target.user_details.all():
            home_value = getattr(ud, "home_path", None) or getattr(getattr(ud, "user", None), "home", None)
            name = getattr(getattr(ud, "user", None), "name", None) or getattr(ud, "name", None)
            if name:
                yield {"name": str(name), "home": str(home_value) if home_value else None}
        return
    except (AttributeError, Exception):  # noqa: BLE001 — fall through deliberately
        pass

    try:
        users_dir = target.fs.path("/Users")
        if users_dir.exists() and users_dir.is_dir():
            for entry in users_dir.iterdir():
                if entry.is_dir() and entry.name.lower() not in {"public", "default", "default user", "all users"}:
                    yield {"name": entry.name, "home": f"/Users/{entry.name}"}
    except Exception:  # noqa: BLE001
        return


def _iter_files(root: Any) -> Iterator[Any]:
    try:
        if not root.exists() or not root.is_dir():
            return
        for entry in root.rglob("*"):
            try:
                if entry.is_file():
                    yield entry
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        return


def _relativize(entry: Any, root: Any) -> str:
    try:
        return str(entry.relative_to(root)).replace("\\", "/")
    except Exception:  # noqa: BLE001
        # Path APIs across dissect versions vary; fall back to the basename.
        return str(getattr(entry, "name", "file"))


def _stream_copy(_target: Any, src_path: Any, dest_path: Path) -> tuple[str, int]:
    """Hash + copy ``src_path`` (a dissect TargetPath) to ``dest_path``."""
    if not src_path.exists():
        raise FileNotFoundError(str(src_path))
    if not src_path.is_file():
        raise FileNotFoundError(f"not a file: {src_path}")

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    size = 0
    # dissect.target file objects support a chunked read.
    with src_path.open("rb") as src_fh, dest_path.open("wb") as dst_fh:
        while True:
            chunk = src_fh.read(_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            dst_fh.write(chunk)
            size += len(chunk)
    return h.hexdigest(), size


# Re-exported for the sidecar to ergonomically open a target without importing
# dissect itself in __main__.
def open_target(source: str) -> Any:
    """Wrap ``dissect.target.Target.open`` so callers don't import dissect.

    Special-case ``"local"`` (the dissect sentinel for "the currently running
    system") and Windows device paths like ``\\\\.\\PhysicalDrive0``: both go
    through dissect's ``LocalLoader``, which enumerates mounted volumes via
    Win32 APIs. We translate ``\\\\.\\PhysicalDriveN`` to ``"local"`` because
    routing it through Target.open() triggers the VBLoader auto-detect, which
    calls ``path.joinpath("MFT_C.bin").exists()`` and trips ``WinError 31``
    on Windows device paths. Other inputs (E01 images, raw image files) pass
    through unchanged.
    """
    from dissect.target import Target

    src = source.strip()
    if src == "local" or src.startswith("\\\\.\\") or src.startswith("//./"):
        return Target.open("local")
    return Target.open(src)


__all__ = [
    "ArtifactSpec",
    "LiveCollectionResult",
    "PhysicalDrive",
    "collect_live",
    "enumerate_physical_drives",
    "open_target",
]

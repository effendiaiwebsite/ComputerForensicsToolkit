"""Filesystem browser + folder exporter for ingested images.

Backs the UI's Files tab. Given a ``collection_id``, resolves the right
filesystem root for that collection and exposes ``list_dir`` for the UI
to walk lazily. Dissect ``Target`` objects are cached per-collection so
re-opening the source on every list call is amortized across the
session.

Three source kinds, each resolved at first call and cached:

* **directory triage** — ``source_path`` is a folder on the host
  filesystem. We use Python ``pathlib.Path`` directly; no dissect.
* **disk image file** (``*.E01``, ``*.dd``, ``*.raw``, etc.) — opened
  through ``dissect.target.Target.open``. Falls through to the
  ``_resolve_windows_root`` probing we already do in the live collector,
  so partition images that don't auto-mount still browse cleanly.
* **physical drive** (``\\\\.\\PhysicalDriveN``) — same Target.open path,
  but admin-only. If the open fails we surface the error to the UI
  rather than crashing.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_READ_CHUNK = 1024 * 1024

logger = logging.getLogger(__name__)

# Names Windows marks Hidden via the FILE_ATTRIBUTE_HIDDEN bit; we don't have
# attribute access through dissect's path API uniformly, so we approximate
# hidden = name starts with "." OR is in a small set of well-known Windows
# hidden paths the examiner shouldn't be surprised by.
_WINDOWS_HIDDEN_PREFIXES = ("$",)

# Vista+ backwards-compat junctions. dissect.target's NTFS module crashes
# on these when followed (the reparse_point_record resolver loops on the
# self-referencing path). Flag them as "junction" kind so the UI shows
# them but doesn't make them clickable — the user navigates via the
# modern equivalent (e.g. /Users instead of /Documents and Settings).
_WINDOWS_LEGACY_JUNCTIONS = frozenset({
    "documents and settings",  # → Users
    "all users",               # → ProgramData
    "default user",            # → Users/Default
})


@dataclass
class FileEntry:
    name: str
    kind: str  # "dir" | "file" | "symlink" | "other"
    size: int | None
    mtime: str | None
    hidden: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "size": self.size,
            "mtime": self.mtime,
            "hidden": self.hidden,
        }


@dataclass
class ListDirResult:
    path: str  # the path the caller asked about, normalized
    parent: str | None  # the parent path, None at root
    source_kind: str  # "directory" | "image" | "device" | "unknown"
    source_path: str
    entries: list[FileEntry]


class ImageBrowser:
    """Per-process cache of opened dissect Targets keyed by collection_id."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: dict[str, Any] = {}
        self._roots: dict[str, Any] = {}

    def close_all(self) -> None:
        with self._lock:
            targets = list(self._targets.items())
            self._targets.clear()
            self._roots.clear()
        for collection_id, target in targets:
            try:
                target.close()
            except Exception:
                logger.exception("closing target for %s failed", collection_id)

    def list_dir(
        self,
        *,
        collection_id: str,
        path: str,
        source_path: str,
    ) -> ListDirResult:
        """List entries at ``path`` for the given collection.

        ``source_path`` comes from the collections table; we use it to
        pick the resolution strategy.
        """
        kind = _classify_source(source_path)
        norm = _normalize_path(path)
        if kind == "directory":
            return self._list_directory(norm, source_path)
        # Image or device → go through dissect.target with caching.
        return self._list_via_dissect(
            collection_id=collection_id,
            path=norm,
            source_path=source_path,
            kind=kind,
        )

    # ---- directory-mode (no dissect) ------------------------------------

    def _list_directory(self, path: str, source_path: str) -> ListDirResult:
        root = Path(source_path).resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"collection source is not a directory: {source_path}")
        rel = path.lstrip("/")
        target = (root / rel).resolve()
        # Guardrail: refuse to escape the collection root.
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise PermissionError(f"path escapes collection root: {path}") from exc
        if not target.exists() or not target.is_dir():
            raise FileNotFoundError(f"directory not found in collection: {path}")
        entries: list[FileEntry] = []
        for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                stat = child.stat()
                size = stat.st_size if child.is_file() else None
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            except OSError:
                size, mtime = None, None
            entries.append(FileEntry(
                name=child.name,
                kind="dir" if child.is_dir() else "file" if child.is_file() else "other",
                size=size,
                mtime=mtime,
                hidden=_is_hidden_name(child.name),
            ))
        return ListDirResult(
            path=path,
            parent=_parent(path),
            source_kind="directory",
            source_path=str(root),
            entries=entries,
        )

    # ---- dissect-backed (image / device) --------------------------------

    def _get_root(self, collection_id: str, source_path: str) -> Any:
        with self._lock:
            cached = self._roots.get(collection_id)
            if cached is not None:
                return cached
        # Opening a target can be slow; do it outside the lock.
        from collectors.windows.live_disk import _resolve_windows_root, open_target

        target = open_target(source_path)
        root = _resolve_windows_root(target)
        if root is None:
            raise FileNotFoundError(
                f"No Windows volume found on {source_path}. dissect could not locate /Windows."
            )
        with self._lock:
            self._targets[collection_id] = target
            self._roots[collection_id] = root
        return root

    def _list_via_dissect(
        self,
        *,
        collection_id: str,
        path: str,
        source_path: str,
        kind: str,
    ) -> ListDirResult:
        root = self._get_root(collection_id, source_path)
        # Refuse the known-broken Vista+ legacy junctions before dissect
        # crashes trying to resolve their reparse point.
        leaf = os.path.basename(path.rstrip("/")).lower()
        if leaf in _WINDOWS_LEGACY_JUNCTIONS:
            raise FileNotFoundError(
                f"{path!r} is a Windows backwards-compat junction; use the modern "
                f"equivalent instead (e.g. /Users for /Documents and Settings)."
            )
        node = root.path(path)
        try:
            children = list(_safe_iterdir(node))
        except Exception:
            children = []
        if not children and not (node.exists() and node.is_dir()):
            raise FileNotFoundError(f"directory not found on image: {path}")
        entries: list[FileEntry] = []
        for child in children:
            try:
                is_dir = child.is_dir()
                is_file = child.is_file() if not is_dir else False
            except Exception:
                is_dir, is_file = False, False
            size: int | None = None
            mtime: str | None = None
            if is_file:
                try:
                    stat = child.stat()
                    size = int(getattr(stat, "st_size", 0) or 0) or None
                    raw_mtime = getattr(stat, "st_mtime", None)
                    if raw_mtime:
                        mtime = datetime.fromtimestamp(float(raw_mtime), tz=UTC).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        )
                except Exception:
                    pass
            name = child.name
            entry_kind = "dir" if is_dir else "file" if is_file else "other"
            # Mark known-broken legacy junctions as "junction" so the UI
            # can render them differently and refuse the click.
            if entry_kind == "dir" and name.lower() in _WINDOWS_LEGACY_JUNCTIONS:
                entry_kind = "junction"
            entries.append(FileEntry(
                name=name,
                kind=entry_kind,
                size=size,
                mtime=mtime,
                hidden=_entry_hidden(child, name),
            ))
        entries.sort(key=lambda e: (e.kind not in ("dir", "junction"), e.name.lower()))
        return ListDirResult(
            path=path,
            parent=_parent(path),
            source_kind=kind,
            source_path=source_path,
            entries=entries,
        )


# ---- helpers ---------------------------------------------------------------


def _classify_source(source_path: str | None) -> str:
    if not source_path:
        return "unknown"
    if source_path.startswith("\\\\.\\") or source_path.startswith("\\\\?\\"):
        return "device"
    p = Path(source_path)
    if p.is_dir():
        return "directory"
    if p.is_file():
        # E01, raw, dd, vmdk, etc. — anything dissect can crack open.
        return "image"
    # Could be a device path on a host where we can't .is_dir() it.
    return "image"


def _normalize_path(path: str) -> str:
    if not path or path == "/":
        return "/"
    cleaned = path.replace("\\", "/").rstrip("/")
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return cleaned


def _parent(path: str) -> str | None:
    if path in ("", "/"):
        return None
    head = os.path.dirname(path.rstrip("/"))
    return head or "/"


def _is_hidden_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith("."):
        return True
    return any(name.startswith(p) for p in _WINDOWS_HIDDEN_PREFIXES)


_FILE_ATTRIBUTE_HIDDEN = 0x2


def _entry_hidden(child: Any, name: str) -> bool:
    """True if the entry carries the NTFS FILE_ATTRIBUTE_HIDDEN bit.

    Reads ``$STANDARD_INFORMATION.file_attributes`` from the dissect.ntfs MFT
    record (the path-level ``stat()`` doesn't expose it). Falls back to the
    name heuristic for non-NTFS sources or if the attribute can't be read — so
    e.g. ``desktop.ini`` (hidden by attribute, not by name) is counted.
    """
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE

        mft = child.get().entry
        si = mft.attributes.get(ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION)
        if si is not None:
            attrs = si if isinstance(si, list) else [si]
            for a in attrs:
                fa = getattr(a, "file_attributes", None)
                if fa is not None:
                    return bool(int(fa) & _FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass
    return _is_hidden_name(name)


def _safe_iterdir(node: Any) -> Iterator[Any]:
    try:
        yield from node.iterdir()
    except Exception:
        logger.exception("iterdir failed for %s", node)
        return


# ---- folder export ---------------------------------------------------------


@dataclass
class FolderExportResult:
    src_path: str
    dest_dir: str
    files_copied: int
    bytes_copied: int
    errors: int
    audit_path: str
    walk_error: str | None = None  # set when the source walk aborted: the export is partial


def export_dest_error(dest_dir: str | Path, source_path: str) -> str | None:
    """Why ``dest_dir`` must not be used as an export target, or ``None`` if it is safe.

    Copying a file onto itself truncates the source, so the destination may never
    be the collection source nor (for directory-mode collections) anywhere inside it.
    """
    dest_root = Path(dest_dir).resolve()
    src_root = Path(source_path).resolve()
    if dest_root == src_root:
        return f"export destination is the collection source itself: {dest_root}"
    if src_root.is_dir() and dest_root.is_relative_to(src_root):
        return f"export destination {dest_root} lies inside the collection source {src_root}"
    return None


def export_folder(
    browser: ImageBrowser,
    *,
    collection_id: str,
    src_path: str,
    dest_dir: str | Path,
    source_path: str,
    audit: Any,  # core.audit.AuditLog
    progress: Any,  # core.progress.ProgressTracker
    progress_key: str,
) -> FolderExportResult:
    """Recursively export a folder from the collection's source to ``dest_dir``.

    Each file is hashed (SHA-256) as it's copied; every read attempt -
    success / skip / error - lands in the audit log. Progress is reported
    via the supplied tracker, keyed by ``progress_key`` so the UI can poll
    a different id than the parent collection.

    Works for both directory-mode collections (stdlib walk) and image / device
    collections (dissect.target walk via the cached root).
    """
    dest_root = Path(dest_dir).resolve()
    dest_error = export_dest_error(dest_root, source_path)
    if dest_error:
        raise ValueError(dest_error)
    dest_root.mkdir(parents=True, exist_ok=True)

    kind = _classify_source(source_path)
    if kind == "directory":
        return _export_from_directory(
            src_path=src_path,
            source_path=source_path,
            dest_root=dest_root,
            audit=audit,
            progress=progress,
            progress_key=progress_key,
        )
    return _export_via_dissect(
        browser=browser,
        collection_id=collection_id,
        src_path=src_path,
        source_path=source_path,
        dest_root=dest_root,
        audit=audit,
        progress=progress,
        progress_key=progress_key,
    )


def _export_from_directory(
    *,
    src_path: str,
    source_path: str,
    dest_root: Path,
    audit: Any,
    progress: Any,
    progress_key: str,
) -> FolderExportResult:
    coll_root = Path(source_path).resolve()
    rel = src_path.lstrip("/")
    src = (coll_root / rel).resolve()
    src.relative_to(coll_root)  # guardrail: refuse escapes
    if not src.is_dir():
        raise NotADirectoryError(f"source is not a directory: {src_path}")

    files = [p for p in src.rglob("*") if p.is_file()]
    progress.update(progress_key, total=len(files))
    counters = _FolderCounters()
    for f in files:
        relative = f.relative_to(src)
        target = dest_root / relative
        progress.update(progress_key, current_item=str(f))
        try:
            sha, size = _hash_copy_local(f, target)
            audit.ok(
                action="export",
                source_path=str(f),
                dest_path=str(target.relative_to(dest_root)),
                sha256=sha,
                size_bytes=size,
                category="export",
            )
            counters.files += 1
            counters.bytes += size
            progress.update(progress_key, completed_delta=1, category="export")
        except Exception as exc:
            logger.exception("export failed for %s", f)
            audit.error("export", str(f), exc, category="export")
            counters.errors += 1
            progress.update(progress_key, completed_delta=1, errors_delta=1)
    return FolderExportResult(
        src_path=src_path,
        dest_dir=str(dest_root),
        files_copied=counters.files,
        bytes_copied=counters.bytes,
        errors=counters.errors,
        audit_path=str(audit.path),
    )


def _export_via_dissect(
    *,
    browser: ImageBrowser,
    collection_id: str,
    src_path: str,
    source_path: str,
    dest_root: Path,
    audit: Any,
    progress: Any,
    progress_key: str,
) -> FolderExportResult:
    root = browser._get_root(collection_id, source_path)
    node = root.path(src_path)
    if not node.exists() or not node.is_dir():
        raise NotADirectoryError(f"source is not a directory on image: {src_path}")

    files, walk_exc = _collect_image_files(node)
    progress.update(progress_key, total=len(files))
    counters = _FolderCounters()
    walk_error: str | None = None
    if walk_exc is not None:
        walk_error = f"{type(walk_exc).__name__}: {walk_exc}"
        audit.error("export_walk", src_path, walk_exc, category="export")
        counters.errors += 1
        progress.update(progress_key, errors_delta=1)
    for f in files:
        rel = _safe_relpath(f, node)
        target = dest_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        progress.update(progress_key, current_item=str(f))
        try:
            sha, size = _hash_copy_dissect(f, target)
            audit.ok(
                action="export",
                source_path=str(f),
                dest_path=str(target.relative_to(dest_root)),
                sha256=sha,
                size_bytes=size,
                category="export",
            )
            counters.files += 1
            counters.bytes += size
            progress.update(progress_key, completed_delta=1, category="export")
        except Exception as exc:
            logger.exception("export failed for %s", f)
            audit.error("export", str(f), exc, category="export")
            counters.errors += 1
            progress.update(progress_key, completed_delta=1, errors_delta=1)
    return FolderExportResult(
        src_path=src_path,
        dest_dir=str(dest_root),
        files_copied=counters.files,
        bytes_copied=counters.bytes,
        errors=counters.errors,
        audit_path=str(audit.path),
        walk_error=walk_error,
    )


@dataclass
class _FolderCounters:
    files: int = 0
    bytes: int = 0
    errors: int = 0


def _collect_image_files(node: Any) -> tuple[list[Any], BaseException | None]:
    """Walk ``node`` recursively; return the files found and the exception that
    aborted the walk (if any) so a partial export is never reported as complete."""
    files: list[Any] = []
    try:
        for child in node.rglob("*"):
            try:
                if child.is_file():
                    files.append(child)
            except Exception:
                continue
    except Exception as exc:
        logger.exception("rglob failed for %s", node)
        return files, exc
    return files, None


def _safe_relpath(entry: Any, root: Any) -> str:
    try:
        return str(entry.relative_to(root)).replace("\\", "/")
    except Exception:
        return str(getattr(entry, "name", "file"))


def _hash_copy_local(src: Path, dest: Path) -> tuple[str, int]:
    if src.resolve() == dest.resolve():
        raise ValueError(f"refusing to copy {src} onto itself")
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    size = 0
    with src.open("rb") as sf, dest.open("wb") as df:
        while True:
            chunk = sf.read(_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            df.write(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _hash_copy_dissect(src: Any, dest: Path) -> tuple[str, int]:
    """Same shape as _hash_copy_local, but src is a dissect TargetPath."""
    h = hashlib.sha256()
    size = 0
    with src.open("rb") as sf, dest.open("wb") as df:
        while True:
            chunk = sf.read(_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            df.write(chunk)
            size += len(chunk)
    return h.hexdigest(), size



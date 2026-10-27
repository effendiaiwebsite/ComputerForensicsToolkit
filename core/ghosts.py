"""Ghost references: artifacts that point at files which no longer exist.

LNK files, JumpLists, RecentDocs, Prefetch, ShimCache, AmCache and UserAssist
all record a path. If that path is gone from the volume, the file was deleted
(or moved) after the artifact was written — evidence of a deletion that no
Recycle Bin, USN or MFT record may still show. We annotate such events with
``evidence.referenced_path_exists`` so a YAML rule can flag the missing ones.

The volume is abstracted as an "exists" callable so the same pass works over
a dissect filesystem root (image / live disk) and over a directory that
mirrors ``C:\\``. The callable returns ``None`` when it cannot answer (path on
another drive, parent folder absent from a sparse mirror); such events are
left unannotated rather than guessed.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.store import EventStore

log = logging.getLogger(__name__)

ExistsFn = Callable[[str], bool | None]

MAX_EVENTS = 20_000
ANNOTATED_TYPES = ("file_access", "program_execution")
_PATH_KEYS: dict[str, tuple[str, ...]] = {
    "file_access": ("target_path",),
    "program_execution": ("program_path",),
}

_DRIVE_PATH = re.compile(r"^[A-Za-z]:\\")
# Files every Windows system volume has and no triage collector copies: their
# presence tells a full volume mirror apart from a sparse artifact collection.
_FULL_MIRROR_PROBES = ("Windows\\explorer.exe", "Windows\\System32\\cmd.exe")


def annotate_missing_references(
    store: EventStore,
    collection_id: str,
    root: ExistsFn | None,
    *,
    max_events: int = MAX_EVENTS,
) -> int:
    """Set ``evidence.referenced_path_exists`` on ``file_access`` /
    ``program_execution`` events whose path can be checked against ``root``.
    Returns the number of events annotated; 0 when ``root`` is ``None``."""
    if root is None:
        return 0
    events = store.query_events(
        collection_id=collection_id, event_types=list(ANNOTATED_TYPES), limit=max_events,
    )
    verdicts: dict[str, bool | None] = {}
    annotated = 0
    for ev in events:
        path = referenced_path(ev)
        if path is None:
            continue
        key = path.lower()
        if key not in verdicts:
            try:
                verdicts[key] = root(path)
            except Exception:
                log.debug("existence check failed for %s", path, exc_info=True)
                verdicts[key] = None
        verdict = verdicts[key]
        if verdict is None:
            continue
        if store.update_event_evidence(ev["event_id"], {"referenced_path_exists": bool(verdict)}):
            annotated += 1
    return annotated


def referenced_path(event: dict[str, Any]) -> str | None:
    """The checkable Windows path an event refers to, or ``None``."""
    evidence = event.get("evidence") or {}
    for key in _PATH_KEYS.get(str(event.get("event_type")), ()):
        value = evidence.get(key)
        if isinstance(value, str) and is_checkable_path(value):
            return value
    return None


def is_checkable_path(path: str) -> bool:
    """Drive-letter absolute paths only: UNC shares, ``\\Device\\…`` and
    ``\\VOLUME{…}`` forms, relative names and unexpanded ``%VAR%`` are skipped."""
    if not _DRIVE_PATH.match(path):
        return False
    return not any(ch in path for ch in "%*?\x00")


def _drive_and_parts(win_path: str) -> tuple[str, list[str]]:
    drive = win_path[0].upper()
    parts = [p for p in win_path[3:].replace("/", "\\").split("\\") if p and p != "."]
    return drive, parts


def directory_exists_fn(dir_path: str | Path) -> ExistsFn | None:
    """Exists-callable over a directory that mirrors the system volume
    (``<dir>/Users/x/file`` for ``C:\\Users\\x\\file``), matched case-insensitively.

    Returns ``None`` unless the directory is a *full* mirror (see
    ``_FULL_MIRROR_PROBES``): a sparse artifact collection would otherwise mark
    every referenced file as missing. Inside a full mirror, a path whose parent
    folder is absent still yields ``None`` rather than ``False``.
    """
    root = Path(dir_path)
    if not root.is_dir():
        return None
    listings: dict[Path, dict[str, Path]] = {}

    def children(d: Path) -> dict[str, Path]:
        cached = listings.get(d)
        if cached is None:
            try:
                cached = {c.name.lower(): c for c in d.iterdir()}
            except OSError:
                cached = {}
            listings[d] = cached
        return cached

    def resolve(parts: list[str]) -> bool | None:
        cur = root
        for seg in parts[:-1]:
            nxt = children(cur).get(seg.lower())
            if nxt is None or not nxt.is_dir():
                return None
            cur = nxt
        return parts[-1].lower() in children(cur) if parts else True

    if not any(resolve(p.split("\\")) for p in _FULL_MIRROR_PROBES):
        return None

    def exists(win_path: str) -> bool | None:
        drive, parts = _drive_and_parts(win_path)
        if drive != "C":
            return None
        return resolve(parts)

    return exists


def image_root_exists_fn(root: Any) -> ExistsFn:
    """Exists-callable over a dissect filesystem root (the Windows volume,
    i.e. the ``_FsRoot`` from ``live_disk._resolve_windows_root``)."""

    def exists(win_path: str) -> bool | None:
        drive, parts = _drive_and_parts(win_path)
        if drive != "C":
            return None
        try:
            return bool(root.path("/" + "/".join(parts)).exists())
        except Exception:
            return None

    return exists

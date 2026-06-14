"""Discover registry hives inside a directory.

Supports two conventions:

1. **Flat dump** — the user ran ``reg save`` for each hive into one folder, so
   files sit at the top level: ``SYSTEM``, ``SOFTWARE``, ``SAM``, ``SECURITY``,
   ``Amcache.hve``, ``NTUSER.DAT_<user>``, etc. We match by basename.

2. **Mirrored tree** — the directory mirrors ``C:\\`` so per-user hives live
   under ``Users\\<username>\\NTUSER.DAT`` and
   ``Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat``.

Either way, this returns one ``DiscoveredHive`` per file found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from collectors.windows.browser import BrowserKind, detect_browser_kind
from collectors.windows.hive import HiveKind

_NAME_TO_KIND: dict[str, HiveKind] = {
    "SYSTEM": "system",
    "SOFTWARE": "software",
    "SAM": "sam",
    "NTUSER.DAT": "ntuser",
    "USRCLASS.DAT": "usrclass",
    "AMCACHE.HVE": "amcache",
}

# Allow short suffixes so reg-save dumps like "SYSTEM_dump.hve" still match.
_PREFIX_TO_KIND: dict[str, HiveKind] = {
    "SYSTEM": "system",
    "SOFTWARE": "software",
    "SAM": "sam",
    "AMCACHE": "amcache",
}


@dataclass
class DiscoveredHive:
    path: Path
    kind: HiveKind
    user_hint: str | None = None


def _classify(p: Path) -> HiveKind | None:
    upper = p.name.upper()
    # Hard exclude file types that share the system-vocab prefix but aren't
    # registry hives — chiefly event logs (Security.evtx etc.).
    if p.suffix.lower() == ".evtx":
        return None
    if upper in _NAME_TO_KIND:
        return _NAME_TO_KIND[upper]
    base = re.split(r"[._]", upper, maxsplit=1)[0]
    return _PREFIX_TO_KIND.get(base)


def _user_from_path(path: Path, root: Path) -> str | None:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    parts = rel.parts
    upper = [p.upper() for p in parts]
    if "USERS" in upper:
        idx = upper.index("USERS")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def discover_hives(directory: str | Path) -> list[DiscoveredHive]:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    found: list[DiscoveredHive] = []
    for entry in root.rglob("*"):
        if not entry.is_file():
            continue
        kind = _classify(entry)
        if kind is None:
            continue
        user = _user_from_path(entry, root) if kind in {"ntuser", "usrclass"} else None
        found.append(DiscoveredHive(path=entry, kind=kind, user_hint=user))

    found.sort(key=lambda h: (_KIND_ORDER.get(h.kind, 99), str(h.path)))
    return found


@dataclass
class DiscoveredEvtx:
    path: Path
    channel_hint: str


def discover_evtx_files(directory: str | Path) -> list[DiscoveredEvtx]:
    """Find every ``*.evtx`` under the directory."""
    from collectors.windows.evtx import _channel_from_filename  # avoid import cycle

    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    found: list[DiscoveredEvtx] = []
    for entry in root.rglob("*.evtx"):
        if entry.is_file():
            found.append(
                DiscoveredEvtx(path=entry, channel_hint=_channel_from_filename(entry.name)),
            )
    found.sort(key=lambda e: str(e.path))
    return found


@dataclass
class DiscoveredPrefetch:
    path: Path


def discover_prefetch_files(directory: str | Path) -> list[DiscoveredPrefetch]:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    found = [
        DiscoveredPrefetch(path=p)
        for p in root.rglob("*.pf")
        if p.is_file()
    ]
    found.sort(key=lambda e: str(e.path))
    return found


@dataclass
class DiscoveredLnk:
    path: Path
    user_hint: str | None = None


def discover_lnk_files(directory: str | Path) -> list[DiscoveredLnk]:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    found = [
        DiscoveredLnk(path=p, user_hint=_user_from_path(p, root))
        for p in root.rglob("*.lnk")
        if p.is_file()
    ]
    found.sort(key=lambda e: str(e.path))
    return found


@dataclass
class DiscoveredJumpList:
    path: Path
    user_hint: str | None = None


def discover_jumplist_files(directory: str | Path) -> list[DiscoveredJumpList]:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    found = [
        DiscoveredJumpList(path=p, user_hint=_user_from_path(p, root))
        for p in root.rglob("*.automaticDestinations-ms")
        if p.is_file()
    ]
    found.sort(key=lambda e: str(e.path))
    return found


@dataclass
class DiscoveredBrowserHistory:
    path: Path
    browser_kind: BrowserKind
    user_hint: str | None = None


def discover_browser_histories(directory: str | Path) -> list[DiscoveredBrowserHistory]:
    """Walk the directory for Chromium-family History SQLite files.

    We match by path segment per locked decision in M9 planning — a file
    contributes only if it sits under a recognised browser path
    (``...Google\\Chrome\\...``, ``...Microsoft\\Edge\\...``,
    ``...BraveSoftware\\Brave-Browser\\...``) AND its basename is
    ``History`` (case-insensitive). This avoids false positives on
    unrelated SQLite blobs named ``History`` in other locations.
    """
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    found: list[DiscoveredBrowserHistory] = []
    for entry in root.rglob("*"):
        if not entry.is_file() or entry.name.lower() != "history":
            continue
        kind = detect_browser_kind(entry)
        if kind == "unknown":
            continue
        found.append(
            DiscoveredBrowserHistory(
                path=entry,
                browser_kind=kind,
                user_hint=_user_from_path(entry, root),
            ),
        )
    found.sort(key=lambda e: str(e.path))
    return found


# SYSTEM first so ComputerName is known before downstream parsers run.
_KIND_ORDER: dict[HiveKind, int] = {
    "system": 0,
    "software": 1,
    "sam": 2,
    "security": 3,
    "amcache": 4,
    "ntuser": 5,
    "usrclass": 6,
}

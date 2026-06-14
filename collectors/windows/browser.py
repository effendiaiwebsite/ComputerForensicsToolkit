"""Collect a single Chromium-family browser History SQLite file.

The History DB is locked while the browser runs; the examiner is expected to
copy the file out-of-band (``Copy-Item ... -Force``) and hand us the copy. We
do not modify the source. SHA-256 is recorded so a later examiner can verify
the parser saw exactly these bytes.

Browser kind is inferred from path segments — Chrome, Edge, and Brave all use
the same Chromium ``History`` schema, so one parser handles all of them; the
``browser_kind`` only feeds ``source_artifact`` (``chrome.history`` etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from collectors.windows.hive import _sha256_of_file, _utc_now_iso  # type: ignore[attr-defined]

BrowserKind = Literal["chrome", "edge", "brave", "unknown"]

_PATH_MARKERS: tuple[tuple[str, BrowserKind], ...] = (
    ("google\\chrome", "chrome"),
    ("google/chrome", "chrome"),
    ("microsoft\\edge", "edge"),
    ("microsoft/edge", "edge"),
    ("bravesoftware\\brave-browser", "brave"),
    ("bravesoftware/brave-browser", "brave"),
)


@dataclass
class CollectedBrowserHistory:
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str
    browser_kind: BrowserKind


def detect_browser_kind(path: str | Path) -> BrowserKind:
    """Infer Chrome/Edge/Brave from path segments. Returns ``"unknown"`` if none match."""
    needle = str(path).lower()
    for marker, kind in _PATH_MARKERS:
        if marker in needle:
            return kind
    return "unknown"


def collect_browser_history(
    path: str | Path,
    *,
    host_id: str | None = None,  # noqa: ARG001 — kept for symmetry with sibling collectors
    browser_kind: BrowserKind | None = None,
) -> CollectedBrowserHistory:
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"browser history not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")
    sha, size = _sha256_of_file(src)
    kind = browser_kind or detect_browser_kind(src)
    return CollectedBrowserHistory(
        source_path=str(src),
        sha256=sha,
        size_bytes=size,
        collected_at=_utc_now_iso(),
        browser_kind=kind,
    )

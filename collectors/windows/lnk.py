"""Collect a single Windows shortcut (.lnk) file."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from collectors.windows.hive import _sha256_of_file, _utc_now_iso  # type: ignore[attr-defined]


@dataclass
class CollectedLnk:
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str


def collect_lnk(
    path: str | Path,
    *,
    host_id: str | None = None,
) -> CollectedLnk:
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"lnk not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")
    sha, size = _sha256_of_file(src)
    return CollectedLnk(
        source_path=str(src),
        sha256=sha,
        size_bytes=size,
        collected_at=_utc_now_iso(),
    )

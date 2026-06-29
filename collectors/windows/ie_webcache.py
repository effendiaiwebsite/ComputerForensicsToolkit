"""Collect a single IE/legacy-Edge ``WebCacheV01.dat`` file.

Locked while the system runs (Explorer/IE/COM hold it open); the examiner
copies it out-of-band — via a live collection's raw NTFS read, a shadow copy,
or ``esentutl /y`` — and hands us the copy. We never modify the source.
SHA-256 is recorded so a later examiner can verify the parser saw exactly
these bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from collectors.windows.hive import _sha256_of_file, _utc_now_iso  # type: ignore[attr-defined]


@dataclass
class CollectedWebCache:
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str


def collect_webcache(
    path: str | Path,
    *,
    host_id: str | None = None,  # noqa: ARG001 — kept for symmetry with siblings
) -> CollectedWebCache:
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"WebCacheV01.dat not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")
    sha, size = _sha256_of_file(src)
    return CollectedWebCache(
        source_path=str(src),
        sha256=sha,
        size_bytes=size,
        collected_at=_utc_now_iso(),
    )

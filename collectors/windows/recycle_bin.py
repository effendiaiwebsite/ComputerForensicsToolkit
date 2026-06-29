"""Collect a single Recycle Bin ``$I`` metadata file.

The ``$I`` record is tiny (≤544 bytes) and never locked, but we still hash it
(SHA-256) and never modify the source, consistent with the other collectors.
The recoverable ``$R`` content blob is intentionally *not* collected here — the
triage pass only needs the metadata; an examiner recovers ``$R`` separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from collectors.windows.hive import _sha256_of_file, _utc_now_iso  # type: ignore[attr-defined]


@dataclass
class CollectedRecycleBin:
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str


def collect_recycle_bin(
    path: str | Path,
    *,
    host_id: str | None = None,  # noqa: ARG001 — kept for symmetry with siblings
) -> CollectedRecycleBin:
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"$I file not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")
    sha, size = _sha256_of_file(src)
    return CollectedRecycleBin(
        source_path=str(src),
        sha256=sha,
        size_bytes=size,
        collected_at=_utc_now_iso(),
    )

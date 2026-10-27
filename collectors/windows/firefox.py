"""Collect a single Firefox ``places.sqlite`` file.

Locked while Firefox runs; the examiner copies it out-of-band and hands us the
copy. We never modify the source. SHA-256 is recorded so a later examiner can
verify the parser saw exactly these bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from collectors.windows.hive import _sha256_of_file, _utc_now_iso  # type: ignore[attr-defined]


@dataclass
class CollectedFirefoxHistory:
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str


def collect_firefox_history(
    path: str | Path,
    *,
    host_id: str | None = None,
) -> CollectedFirefoxHistory:
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"places.sqlite not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")
    sha, size = _sha256_of_file(src)
    return CollectedFirefoxHistory(
        source_path=str(src),
        sha256=sha,
        size_bytes=size,
        collected_at=_utc_now_iso(),
    )

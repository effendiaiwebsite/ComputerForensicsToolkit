"""Collect a single ``.evtx`` file.

Mirrors the hive collector — hash + size + collected_at — but for Windows
event-log files. Channel name is derived from the filename so the parser can
short-circuit when the in-record ``Channel`` element is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from collectors.windows.hive import _sha256_of_file, _utc_now_iso  # type: ignore[attr-defined]


@dataclass
class CollectedEvtx:
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str
    channel_hint: str


def _channel_from_filename(name: str) -> str:
    """Recover the channel name from a wevtutil-exported filename.

    ``Microsoft-Windows-PowerShell%4Operational.evtx`` →
    ``Microsoft-Windows-PowerShell/Operational``.
    Plain ``Security.evtx`` → ``Security``.
    """
    stem = name
    if stem.lower().endswith(".evtx"):
        stem = stem[:-5]
    return stem.replace("%4", "/")


def collect_evtx(
    path: str | Path,
    *,
    host_id: str | None = None,
) -> CollectedEvtx:
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"evtx not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")
    sha, size = _sha256_of_file(src)
    return CollectedEvtx(
        source_path=str(src),
        sha256=sha,
        size_bytes=size,
        collected_at=_utc_now_iso(),
        channel_hint=_channel_from_filename(src.name),
    )

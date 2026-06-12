"""Collect a single registry hive file from a user-supplied path.

M2 scope: the user dumps a hive to a regular file (e.g. via a separate USB boot or
shadow copy) and points us at it. No live raw-disk access — that lands in M9+
when we bring in ``dissect.target`` against ``\\\\.\\PhysicalDriveN``.

We do not modify the source file. The artifact is identified by SHA-256 over its
full bytes, recorded in the bundle manifest so any examiner can prove the parser
saw exactly these bytes.
"""

from __future__ import annotations

import hashlib
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

HiveKind = Literal["system", "software", "sam", "security", "ntuser", "usrclass", "amcache"]

_READ_CHUNK = 1024 * 1024


@dataclass
class CollectedArtifact:
    kind: HiveKind
    source_path: str
    sha256: str
    size_bytes: int
    collected_at: str


@dataclass
class CollectionBundle:
    collection_id: str
    host_os: Literal["windows"]
    host_id: str
    created_at: str
    artifacts: list[CollectedArtifact] = field(default_factory=list)


def _sha256_of_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_READ_CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_hive(
    path: str | Path,
    kind: HiveKind,
    *,
    host_id: str | None = None,
) -> CollectionBundle:
    """Hash a hive file and return a one-artifact bundle.

    Raises ``FileNotFoundError`` if the path doesn't exist and ``ValueError``
    if it's a directory.
    """
    src = Path(path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"hive not found: {src}")
    if not src.is_file():
        raise ValueError(f"not a file: {src}")

    sha, size = _sha256_of_file(src)
    now = _utc_now_iso()
    return CollectionBundle(
        collection_id=f"col-{uuid.uuid4()}",
        host_os="windows",
        host_id=host_id or socket.gethostname(),
        created_at=now,
        artifacts=[
            CollectedArtifact(
                kind=kind,
                source_path=str(src),
                sha256=sha,
                size_bytes=size,
                collected_at=now,
            ),
        ],
    )

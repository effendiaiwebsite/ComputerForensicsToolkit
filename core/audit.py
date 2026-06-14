"""Append-only audit log for live disk collection.

One ``audit.jsonl`` per collection, written alongside the collected
artifacts. The log records every read attempt — successes carry the
SHA-256 + byte count, failures carry the error string — so an examiner
can later prove which evidence the tool saw and which it could not.

Append-only by design: the log is opened in ``a`` mode for each write,
fsync'd, and closed, so even a hard kill of the sidecar leaves a partial
but valid JSONL behind. Records are never edited or removed.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

AuditStatus = Literal["ok", "skipped", "error"]


@dataclass(frozen=True)
class AuditRecord:
    timestamp: str
    action: str
    source_path: str
    status: AuditStatus
    dest_path: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    """Thread-safe append-only JSONL writer for one collection."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def write(self, record: AuditRecord | Mapping[str, Any]) -> None:
        line = json.dumps(
            asdict(record) if isinstance(record, AuditRecord) else dict(record),
            separators=(",", ":"),
            default=str,
        )
        with self._lock, self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def ok(
        self,
        action: str,
        source_path: str,
        dest_path: str,
        sha256: str,
        size_bytes: int,
        **extra: Any,
    ) -> None:
        self.write(AuditRecord(
            timestamp=_utc_now(),
            action=action,
            source_path=source_path,
            dest_path=dest_path,
            sha256=sha256,
            size_bytes=size_bytes,
            status="ok",
            extra=extra,
        ))

    def error(self, action: str, source_path: str, exc: BaseException, **extra: Any) -> None:
        self.write(AuditRecord(
            timestamp=_utc_now(),
            action=action,
            source_path=source_path,
            status="error",
            error=f"{type(exc).__name__}: {exc}",
            extra=extra,
        ))

    def skipped(self, action: str, source_path: str, reason: str, **extra: Any) -> None:
        self.write(AuditRecord(
            timestamp=_utc_now(),
            action=action,
            source_path=source_path,
            status="skipped",
            error=reason,
            extra=extra,
        ))

    def read_all(self) -> list[dict[str, Any]]:
        """Read back every record. Tests use this; runtime never re-reads."""
        if not self._path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                out.append(json.loads(line))
        return out


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

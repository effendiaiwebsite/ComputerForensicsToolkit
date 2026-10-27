"""In-memory progress tracker for long-running sidecar operations.

The sidecar IPC is request/response (no streaming), so the UI polls a
``get_progress(collection_id)`` op every few hundred ms while a live
collection runs. This module is the source of truth those polls read.

Thread-safe: the collector runs in a worker thread inside the sidecar
while the main thread keeps serving JSON-lines from stdin.
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Literal

Phase = Literal["pending", "running", "done", "error"]


@dataclass
class ProgressSnapshot:
    collection_id: str
    phase: Phase
    label: str  # short description of the overall job
    current_item: str  # the file / artifact being worked on right now
    completed: int
    total: int
    started_at: str
    updated_at: str
    finished_at: str | None
    error: str | None
    by_category: dict[str, int] = field(default_factory=dict)
    errors: int = 0  # items that failed but did not abort the job

    def to_dict(self) -> dict:
        return asdict(self)


class ProgressTracker:
    """A keyed registry of ``ProgressSnapshot``s. Sidecar-process scope."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._snaps: dict[str, ProgressSnapshot] = {}

    def start(self, collection_id: str, *, label: str, total: int = 0) -> ProgressSnapshot:
        now = _utc_now()
        snap = ProgressSnapshot(
            collection_id=collection_id,
            phase="running",
            label=label,
            current_item="",
            completed=0,
            total=total,
            started_at=now,
            updated_at=now,
            finished_at=None,
            error=None,
        )
        with self._lock:
            self._snaps[collection_id] = snap
        return snap

    def update(
        self,
        collection_id: str,
        *,
        current_item: str | None = None,
        completed_delta: int = 0,
        total: int | None = None,
        category: str | None = None,
        errors_delta: int = 0,
    ) -> None:
        with self._lock:
            snap = self._snaps.get(collection_id)
            if snap is None:
                return
            if current_item is not None:
                snap.current_item = current_item
            if completed_delta:
                snap.completed += completed_delta
            if errors_delta:
                snap.errors += errors_delta
            if total is not None:
                snap.total = total
            if category is not None:
                snap.by_category[category] = snap.by_category.get(category, 0) + 1
            snap.updated_at = _utc_now()

    def finish(self, collection_id: str, *, error: str | None = None) -> None:
        with self._lock:
            snap = self._snaps.get(collection_id)
            if snap is None:
                return
            snap.phase = "error" if error else "done"
            snap.error = error
            snap.finished_at = _utc_now()
            snap.updated_at = snap.finished_at

    def get(self, collection_id: str) -> ProgressSnapshot | None:
        with self._lock:
            return self._snaps.get(collection_id)

    def all(self) -> list[ProgressSnapshot]:
        with self._lock:
            return list(self._snaps.values())


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

"""Read-only SQLite access that honours write-ahead logs without touching the source.

Browser databases copied off a live system usually arrive with a ``-wal``
(and sometimes ``-journal``) sidecar holding the newest rows. Opening the main
file with ``immutable=1`` ignores those sidecars, silently dropping recent
history; opening it normally lets SQLite create a ``-shm`` next to the
artifact, which violates the no-writes-to-source rule.

So: when a sidecar is present, the database and its sidecars are copied to a
private temp directory and opened there (``mode=ro``); otherwise the source is
opened in place with ``immutable=1``. Paths go through ``Path.as_uri()`` so
``%``, ``#`` and UNC prefixes survive the SQLite URI syntax.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SIDECAR_SUFFIXES: tuple[str, ...] = ("-wal", "-journal")


def sidecar_paths(db_path: str | Path) -> list[Path]:
    src = Path(db_path)
    return [
        p for suffix in SIDECAR_SUFFIXES
        if (p := src.with_name(src.name + suffix)).is_file()
    ]


@contextmanager
def open_sqlite_readonly(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    src = Path(db_path).resolve()
    sidecars = sidecar_paths(src)
    if not sidecars:
        conn = sqlite3.connect(src.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            yield conn
        finally:
            conn.close()
        return

    with tempfile.TemporaryDirectory(prefix="df-sqlite-", ignore_cleanup_errors=True) as tmp:
        tmp_db = Path(tmp) / src.name
        shutil.copyfile(src, tmp_db)
        for sidecar in sidecars:
            shutil.copyfile(sidecar, tmp_db.with_name(sidecar.name))
        conn = sqlite3.connect(tmp_db.as_uri() + "?mode=ro", uri=True)
        try:
            yield conn
        finally:
            conn.close()

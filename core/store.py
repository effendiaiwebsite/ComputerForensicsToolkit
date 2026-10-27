"""SQLite-backed event store.

In-memory by default for live triage; pass a path to persist a case file. Designed
to be queried by the UI through the IPC layer — filters, sort, pagination all live
here so the wire payload stays small.

Schema is intentionally flat with a JSON-typed ``evidence``/``raw`` blob so we can
evolve fields without migrations during Phase 1. We keep ``timestamp`` and
``event_type`` as their own indexed columns because every query hits them.
"""

from __future__ import annotations

import functools
import json
import sqlite3
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from core import SCHEMA_VERSION
from core.events import Event

_SCHEMA = r"""
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
    collection_id TEXT PRIMARY KEY,
    host_id       TEXT NOT NULL,
    host_os       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    note          TEXT,
    source_path   TEXT  -- live: '\\.\PhysicalDriveN' or '<file>.E01'; directory triage: dir
);

CREATE TABLE IF NOT EXISTS events (
    event_id         TEXT PRIMARY KEY,
    collection_id    TEXT NOT NULL,
    timestamp        TEXT,
    timestamp_source TEXT NOT NULL,
    host_os          TEXT NOT NULL,
    host_id          TEXT NOT NULL,
    user             TEXT,
    source_artifact  TEXT NOT NULL,
    source_path      TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    summary          TEXT NOT NULL,
    evidence_json    TEXT NOT NULL,
    raw_json         TEXT NOT NULL,
    parser_version   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source_artifact ON events(source_artifact);
CREATE INDEX IF NOT EXISTS idx_events_collection ON events(collection_id);

CREATE TABLE IF NOT EXISTS findings (
    finding_id              TEXT PRIMARY KEY,
    rule_id                 TEXT NOT NULL,
    rule_title              TEXT NOT NULL,
    severity                TEXT NOT NULL,
    mitre_techniques_json   TEXT NOT NULL,
    mitre_tactics_json      TEXT NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    collection_id           TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    summary                 TEXT NOT NULL,
    examiner_status         TEXT NOT NULL DEFAULT 'new'
);

CREATE INDEX IF NOT EXISTS idx_findings_collection ON findings(collection_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule       ON findings(rule_id);

-- Rebuilt wholesale by core.deletions.build_deletions; never hand-edited.
-- event_id is a logical FK to events(event_id): not declared, because
-- INSERT OR REPLACE on events would otherwise trip the FK check on re-ingest.
CREATE TABLE IF NOT EXISTS deletions (
    deletion_id      TEXT PRIMARY KEY,
    collection_id    TEXT NOT NULL,
    event_id         TEXT NOT NULL,
    deleted_at       TEXT,
    time_basis       TEXT NOT NULL,   -- 'exact' | 'upper_bound'
    path             TEXT,
    name             TEXT,
    size             INTEGER,
    is_directory     INTEGER NOT NULL DEFAULT 0,
    method           TEXT NOT NULL,   -- 'recycle_bin' | 'usn_journal' | 'mft_unallocated'
    owner_sid        TEXT,
    owner_user       TEXT,
    actor_user       TEXT,
    actor_sid        TEXT,
    actor_confidence TEXT NOT NULL,   -- 'direct' | 'likely' | 'ambiguous' | 'unknown'
    actor_reason     TEXT,
    recoverable_hint TEXT,
    source_path      TEXT
);

CREATE INDEX IF NOT EXISTS idx_deletions_collection_time   ON deletions(collection_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_deletions_collection_actor  ON deletions(collection_id, actor_user);
CREATE INDEX IF NOT EXISTS idx_deletions_collection_method ON deletions(collection_id, method);
"""

_DELETION_COLUMNS = (
    "deletion_id", "collection_id", "event_id", "deleted_at", "time_basis",
    "path", "name", "size", "is_directory", "method", "owner_sid", "owner_user",
    "actor_user", "actor_sid", "actor_confidence", "actor_reason",
    "recoverable_hint", "source_path",
)

_DELETION_SORT_COLUMNS = {"deleted_at", "path", "actor_user"}

_SORT_COLUMNS = {
    "timestamp",
    "event_type",
    "source_artifact",
    "host_id",
    "user",
    "summary",
}

_P = ParamSpec("_P")
_R = TypeVar("_R")


def _locked(fn: Callable[_P, _R]) -> Callable[_P, _R]:
    """Serialize connection use: the live-collection worker thread writes while
    the stdio thread serves reads on the same ``check_same_thread=False`` handle."""

    @functools.wraps(fn)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        self = args[0]
        with self._lock:  # type: ignore[attr-defined]
            return fn(*args, **kwargs)

    return wrapper


def _like_pattern(needle: str) -> str:
    """Wrap ``needle`` in ``%`` for LIKE, escaping its own ``%``/``_``/``\\``."""
    escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


_LIKE_ESCAPE = "ESCAPE '\\'"


class EventStore:
    """Thin wrapper over sqlite3 with the queries the UI needs."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    @_locked
    def close(self) -> None:
        self._conn.close()

    @_locked
    def register_collection(
        self,
        collection_id: str,
        host_id: str,
        host_os: str,
        created_at: str,
        note: str | None = None,
        source_path: str | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO collections"
            "(collection_id, host_id, host_os, created_at, note, source_path) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (collection_id, host_id, host_os, created_at, note, source_path),
        )

    @_locked
    def set_collection_source(self, collection_id: str, source_path: str) -> None:
        """Update the source_path of an existing collection (e.g. after directory
        triage discovers it under a parent we want the Files tab to root from)."""
        self._conn.execute(
            "UPDATE collections SET source_path = ? WHERE collection_id = ?",
            (source_path, collection_id),
        )

    @_locked
    def set_collection_host(self, collection_id: str, host_id: str) -> None:
        """Replace the placeholder host_id once triage discovers the real one."""
        self._conn.execute(
            "UPDATE collections SET host_id = ? WHERE collection_id = ?",
            (host_id, collection_id),
        )

    @_locked
    def get_collection(self, collection_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT collection_id, host_id, host_os, created_at, note, source_path "
            "FROM collections WHERE collection_id = ?",
            (collection_id,),
        ).fetchone()
        return dict(row) if row else None

    @_locked
    def timestamp_range(
        self,
        *,
        collection_id: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Return ``(min, max)`` ISO timestamps for dated events, ``(None, None)`` if empty."""
        where = "WHERE timestamp IS NOT NULL"
        params: list[Any] = []
        if collection_id is not None:
            where += " AND collection_id = ?"
            params.append(collection_id)
        row = self._conn.execute(
            f"SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM events {where}",
            params,
        ).fetchone()
        if row is None:
            return None, None
        return row["lo"], row["hi"]

    @_locked
    def insert_events(self, events: Iterable[Event]) -> int:
        rows = [
            (
                e.event_id,
                e.collection_id,
                e.timestamp,
                e.timestamp_source,
                e.host_os,
                e.host_id,
                e.user,
                e.source_artifact,
                e.source_path,
                e.event_type,
                e.summary,
                json.dumps(e.evidence, default=str),
                json.dumps(e.raw, default=str),
                e.parser_version,
            )
            for e in events
        ]
        if not rows:
            return 0
        self._conn.executemany(
            "INSERT OR REPLACE INTO events("
            "event_id, collection_id, timestamp, timestamp_source, host_os, host_id, "
            "user, source_artifact, source_path, event_type, summary, evidence_json, "
            "raw_json, parser_version"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return len(rows)

    @_locked
    def query_events(
        self,
        *,
        collection_id: str | None = None,
        event_type: str | None = None,
        event_types: list[str] | None = None,
        source_artifact: str | None = None,
        source_artifacts: list[str] | None = None,
        summary_contains: str | None = None,
        sort_by: str = "timestamp",
        sort_dir: str = "asc",
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if sort_by not in _SORT_COLUMNS:
            raise ValueError(f"sort_by must be one of {sorted(_SORT_COLUMNS)}")
        if sort_dir.lower() not in {"asc", "desc"}:
            raise ValueError("sort_dir must be 'asc' or 'desc'")

        where: list[str] = []
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        if event_type is not None:
            where.append("event_type = ?")
            params.append(event_type)
        if event_types:
            placeholders = ",".join("?" * len(event_types))
            where.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        if source_artifact is not None:
            where.append("source_artifact = ?")
            params.append(source_artifact)
        if source_artifacts:
            placeholders = ",".join("?" * len(source_artifacts))
            where.append(f"source_artifact IN ({placeholders})")
            params.extend(source_artifacts)
        if summary_contains:
            where.append(f"summary LIKE ? {_LIKE_ESCAPE}")
            params.append(_like_pattern(summary_contains))

        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        # Undated rows sort to the bottom in both directions so "newest first"
        # still leads with dated events.
        sql = (
            "SELECT event_id, collection_id, timestamp, timestamp_source, host_os, "
            "host_id, user, source_artifact, source_path, event_type, summary, "
            "evidence_json, raw_json, parser_version FROM events"
            f"{where_sql} ORDER BY {sort_by} {sort_dir.upper()} NULLS LAST LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(row) for row in rows]

    @_locked
    def insert_findings(self, findings: Iterable[Any]) -> int:
        rows = [
            (
                f.finding_id,
                f.rule_id,
                f.rule_title,
                f.severity,
                json.dumps(list(f.mitre_techniques)),
                json.dumps(list(f.mitre_tactics)),
                json.dumps(list(f.evidence_event_ids)),
                f.collection_id,
                f.created_at,
                f.summary,
                f.examiner_status,
            )
            for f in findings
        ]
        if not rows:
            return 0
        self._conn.executemany(
            "INSERT OR REPLACE INTO findings("
            "finding_id, rule_id, rule_title, severity, mitre_techniques_json, "
            "mitre_tactics_json, evidence_event_ids_json, collection_id, "
            "created_at, summary, examiner_status"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return len(rows)

    @_locked
    def clear_findings(self, *, collection_id: str | None = None) -> int:
        if collection_id is None:
            cur = self._conn.execute("DELETE FROM findings")
        else:
            cur = self._conn.execute(
                "DELETE FROM findings WHERE collection_id = ?", (collection_id,)
            )
        return cur.rowcount or 0

    @_locked
    def query_findings(
        self,
        *,
        collection_id: str | None = None,
        severities: list[str] | None = None,
        tactic: str | None = None,
        examiner_status: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        if severities:
            placeholders = ",".join("?" * len(severities))
            where.append(f"severity IN ({placeholders})")
            params.extend(severities)
        if examiner_status is not None:
            where.append("examiner_status = ?")
            params.append(examiner_status)
        if tactic is not None:
            where.append("mitre_tactics_json LIKE ?")
            params.append(f'%"{tactic}"%')

        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        sql = (
            "SELECT finding_id, rule_id, rule_title, severity, "
            "mitre_techniques_json, mitre_tactics_json, "
            "evidence_event_ids_json, collection_id, created_at, "
            "summary, examiner_status FROM findings"
            f"{where_sql} ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
            "rule_id LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [_finding_row_to_dict(r) for r in rows]

    @_locked
    def count_findings(self, *, collection_id: str | None = None) -> int:
        if collection_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE collection_id = ?",
                (collection_id,),
            ).fetchone()
        return int(row["c"])

    @_locked
    def counts_by_severity(self, *, collection_id: str | None = None) -> dict[str, int]:
        if collection_id is None:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings GROUP BY severity"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings "
                "WHERE collection_id = ? GROUP BY severity",
                (collection_id,),
            ).fetchall()
        return {row["severity"]: int(row["c"]) for row in rows}

    @_locked
    def query_usb_devices(
        self,
        *,
        collection_id: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Group ``usb_connection`` events by serial → one row per device.

        Events without a serial fall back to their registry instance key, then
        to the event itself, so unserialized devices never collapse into one row.
        """
        where = ["event_type = 'usb_connection'"]
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        where_sql = " WHERE " + " AND ".join(where)
        sql = (
            "SELECT json_extract(evidence_json, '$.serial') AS serial, "
            "COALESCE(json_extract(evidence_json, '$.serial'), "
            "json_extract(evidence_json, '$.key_path'), event_id) AS device_key, "
            "json_extract(evidence_json, '$.vendor') AS vendor, "
            "json_extract(evidence_json, '$.product') AS product, "
            "json_extract(evidence_json, '$.device_name') AS device_name, "
            "MIN(json_extract(evidence_json, '$.first_installed')) AS first_installed, "
            "MAX(json_extract(evidence_json, '$.last_connected')) AS last_connected, "
            "MAX(json_extract(evidence_json, '$.last_removed')) AS last_removed, "
            "COUNT(*) AS event_count, "
            "MIN(event_id) AS first_event_id "
            "FROM events"
            f"{where_sql} "
            "GROUP BY device_key "
            "ORDER BY last_connected DESC NULLS LAST LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d.pop("device_key", None)
            out.append(d)
        return out

    @_locked
    def query_browser_domains(
        self,
        *,
        collection_id: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Roll up Chromium-family browser events one row per host/domain.

        Visits use evidence ``host``; downloads use evidence ``source_host``;
        searches use evidence ``host``. Rows with no host (e.g. ``file://``
        URLs, malformed entries) are bucketed under ``"(no host)"`` rather
        than dropped, so the examiner doesn't lose evidence silently.
        """
        where = ["event_type IN ('browser_visit', 'browser_download', 'browser_search')"]
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        where_sql = " WHERE " + " AND ".join(where)
        sql = f"""
            WITH rolled AS (
                SELECT
                    COALESCE(
                        NULLIF(json_extract(evidence_json, '$.host'), ''),
                        NULLIF(json_extract(evidence_json, '$.source_host'), ''),
                        '(no host)'
                    ) AS host,
                    event_type,
                    timestamp,
                    source_artifact
                FROM events
                {where_sql}
            )
            SELECT
                host,
                SUM(CASE WHEN event_type = 'browser_visit'    THEN 1 ELSE 0 END) AS visit_count,
                SUM(CASE WHEN event_type = 'browser_download' THEN 1 ELSE 0 END) AS download_count,
                SUM(CASE WHEN event_type = 'browser_search'   THEN 1 ELSE 0 END) AS search_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                GROUP_CONCAT(DISTINCT source_artifact) AS browsers,
                COUNT(*) AS event_count
            FROM rolled
            GROUP BY host
            ORDER BY last_seen DESC NULLS LAST, event_count DESC
            LIMIT ?
        """
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            browsers = sorted({b for b in (r["browsers"] or "").split(",") if b})
            out.append({
                "host": r["host"],
                "visit_count": int(r["visit_count"] or 0),
                "download_count": int(r["download_count"] or 0),
                "search_count": int(r["search_count"] or 0),
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "browsers": browsers,
                "event_count": int(r["event_count"]),
            })
        return out

    @_locked
    def delete_events_by_source(self, collection_id: str, source_artifact: str) -> int:
        """Remove every event of ``source_artifact`` in a collection (used to make
        derived events idempotent on rebuild)."""
        cur = self._conn.execute(
            "DELETE FROM events WHERE collection_id = ? AND source_artifact = ?",
            (collection_id, source_artifact),
        )
        return cur.rowcount or 0

    @_locked
    def update_event_evidence(self, event_id: str, patch: dict[str, Any]) -> bool:
        """Merge ``patch`` into the stored evidence of one event (RFC 7396 merge:
        a ``None`` value removes the key). Returns False when the event is unknown."""
        if not patch:
            return False
        cur = self._conn.execute(
            "UPDATE events SET evidence_json = json_patch(evidence_json, ?) WHERE event_id = ?",
            (json.dumps(patch, default=str), event_id),
        )
        return bool(cur.rowcount)

    # ----- deletions ---------------------------------------------------------

    @_locked
    def replace_deletions(self, collection_id: str, rows: Iterable[dict[str, Any]]) -> int:
        """Drop the collection's deletion rows and insert ``rows`` (dicts keyed by
        the ``deletions`` column names; missing keys become NULL)."""
        self._conn.execute("DELETE FROM deletions WHERE collection_id = ?", (collection_id,))
        values = [
            tuple(
                collection_id if col == "collection_id"
                else int(bool(r.get(col))) if col == "is_directory"
                else r.get(col)
                for col in _DELETION_COLUMNS
            )
            for r in rows
        ]
        if not values:
            return 0
        placeholders = ",".join("?" * len(_DELETION_COLUMNS))
        self._conn.executemany(
            f"INSERT INTO deletions({','.join(_DELETION_COLUMNS)}) VALUES ({placeholders})",
            values,
        )
        return len(values)

    @staticmethod
    def _deletion_filters(
        collection_id: str,
        method: str | None,
        actor_user: str | None,
        actor_confidence: str | None,
        path_contains: str | None,
        time_basis: str | None = None,
    ) -> tuple[str, list[Any]]:
        where = ["collection_id = ?"]
        params: list[Any] = [collection_id]
        if method:
            where.append("method = ?")
            params.append(method)
        if time_basis:
            where.append("time_basis = ?")
            params.append(time_basis)
        if actor_user:
            where.append("actor_user = ?")
            params.append(actor_user)
        if actor_confidence:
            where.append("actor_confidence = ?")
            params.append(actor_confidence)
        if path_contains:
            where.append(f"path LIKE ? {_LIKE_ESCAPE}")
            params.append(_like_pattern(path_contains))
        return " WHERE " + " AND ".join(where), params

    @_locked
    def query_deletions(
        self,
        *,
        collection_id: str,
        limit: int = 500,
        offset: int = 0,
        method: str | None = None,
        actor_user: str | None = None,
        actor_confidence: str | None = None,
        path_contains: str | None = None,
        time_basis: str | None = None,
        sort_by: str = "deleted_at",
        sort_dir: str = "desc",
    ) -> list[dict[str, Any]]:
        if sort_by not in _DELETION_SORT_COLUMNS:
            raise ValueError(f"sort_by must be one of {sorted(_DELETION_SORT_COLUMNS)}")
        if sort_dir.lower() not in {"asc", "desc"}:
            raise ValueError("sort_dir must be 'asc' or 'desc'")
        where_sql, params = self._deletion_filters(
            collection_id, method, actor_user, actor_confidence, path_contains, time_basis,
        )
        sql = (
            f"SELECT {','.join(_DELETION_COLUMNS)} FROM deletions{where_sql} "
            f"ORDER BY {sort_by} {sort_dir.upper()} NULLS LAST, path ASC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [_deletion_row_to_dict(r) for r in rows]

    @_locked
    def count_deletions(
        self,
        *,
        collection_id: str,
        method: str | None = None,
        actor_user: str | None = None,
        actor_confidence: str | None = None,
        path_contains: str | None = None,
        time_basis: str | None = None,
    ) -> int:
        where_sql, params = self._deletion_filters(
            collection_id, method, actor_user, actor_confidence, path_contains, time_basis,
        )
        row = self._conn.execute(
            f"SELECT COUNT(*) AS c FROM deletions{where_sql}", params,
        ).fetchone()
        return int(row["c"])

    @_locked
    def deletions_by_method(self, *, collection_id: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT method, COUNT(*) AS c FROM deletions WHERE collection_id = ? "
            "GROUP BY method ORDER BY c DESC",
            (collection_id,),
        ).fetchall()
        return {r["method"]: int(r["c"]) for r in rows}

    @_locked
    def deletions_by_confidence(self, *, collection_id: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT actor_confidence, COUNT(*) AS c FROM deletions WHERE collection_id = ? "
            "GROUP BY actor_confidence",
            (collection_id,),
        ).fetchall()
        return {r["actor_confidence"]: int(r["c"]) for r in rows}

    @_locked
    def deletions_by_actor(self, *, collection_id: str) -> list[dict[str, Any]]:
        """``[{actor_user, actor_confidence, count}]`` most frequent first; rows
        with no attributed actor are reported under ``actor_user = None``."""
        rows = self._conn.execute(
            "SELECT actor_user, actor_confidence, COUNT(*) AS c FROM deletions "
            "WHERE collection_id = ? GROUP BY actor_user, actor_confidence "
            "ORDER BY c DESC, (actor_user IS NULL) ASC, actor_user ASC, actor_confidence ASC",
            (collection_id,),
        ).fetchall()
        return [
            {
                "actor_user": r["actor_user"],
                "actor_confidence": r["actor_confidence"],
                "count": int(r["c"]),
            }
            for r in rows
        ]

    @_locked
    def count_deletion_bursts(self, *, collection_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM events "
            "WHERE collection_id = ? AND event_type = 'file_delete_burst'",
            (collection_id,),
        ).fetchone()
        return int(row["c"])

    @_locked
    def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT event_id, collection_id, timestamp, timestamp_source, host_os, "
            "host_id, user, source_artifact, source_path, event_type, summary, "
            "evidence_json, raw_json, parser_version FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return _row_to_dict(row) if row else None

    @_locked
    def count_events(self, *, collection_id: str | None = None) -> int:
        if collection_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE collection_id = ?",
                (collection_id,),
            ).fetchone()
        return int(row["c"])

    @_locked
    def counts_by_event_type(self, *, collection_id: str | None = None) -> dict[str, int]:
        if collection_id is None:
            rows = self._conn.execute(
                "SELECT event_type, COUNT(*) AS c FROM events GROUP BY event_type"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT event_type, COUNT(*) AS c FROM events "
                "WHERE collection_id = ? GROUP BY event_type",
                (collection_id,),
            ).fetchall()
        return {row["event_type"]: int(row["c"]) for row in rows}

    @_locked
    def program_execution_composite(
        self,
        *,
        collection_id: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Union all ``program_execution`` events, deduplicated by program path.

        Pulls the program path out of the evidence JSON, falling back to
        ``executable_filename`` (Prefetch) then ``program_name`` (UserAssist)
        when ``program_path`` isn't set. Aggregates per program: earliest +
        latest sighting, the distinct sources that saw it, total event count
        across sources, and the summed ``run_count`` where the source records
        one (Prefetch always; AmCache when present).
        """
        coalesce_path = (
            "COALESCE("
            "json_extract(evidence_json, '$.program_path'), "
            "json_extract(evidence_json, '$.executable_filename'), "
            "json_extract(evidence_json, '$.program_name')"
            ")"
        )
        where_extra = ""
        params: list[Any] = []
        if collection_id is not None:
            where_extra = " AND collection_id = ?"
            params.append(collection_id)

        sql = f"""
            WITH execs AS (
                SELECT
                    timestamp,
                    source_artifact,
                    LOWER({coalesce_path}) AS program_key,
                    {coalesce_path} AS program_path,
                    CAST(json_extract(evidence_json, '$.run_count') AS INTEGER) AS run_count
                FROM events
                WHERE event_type = 'program_execution'{where_extra}
            )
            SELECT
                program_path,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                GROUP_CONCAT(DISTINCT source_artifact) AS sources,
                COUNT(*) AS event_count,
                COALESCE(SUM(run_count), 0) AS total_runs
            FROM execs
            WHERE program_key IS NOT NULL
            GROUP BY program_key
            ORDER BY last_seen DESC, program_path ASC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            sources = [s for s in (r["sources"] or "").split(",") if s]
            out.append({
                "program_path": r["program_path"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "sources": sorted(sources),
                "event_count": int(r["event_count"]),
                "total_runs": int(r["total_runs"]) if r["total_runs"] is not None else 0,
            })
        return out

    @_locked
    def program_execution_composite_count(self, *, collection_id: str | None = None) -> int:
        """Number of distinct programs in the composite view."""
        coalesce_path = (
            "COALESCE("
            "json_extract(evidence_json, '$.program_path'), "
            "json_extract(evidence_json, '$.executable_filename'), "
            "json_extract(evidence_json, '$.program_name')"
            ")"
        )
        where_extra = ""
        params: list[Any] = []
        if collection_id is not None:
            where_extra = " AND collection_id = ?"
            params.append(collection_id)
        sql = f"""
            SELECT COUNT(*) AS c FROM (
                SELECT LOWER({coalesce_path}) AS k
                FROM events
                WHERE event_type = 'program_execution'{where_extra}
                  AND {coalesce_path} IS NOT NULL
                GROUP BY k
            )
        """
        row = self._conn.execute(sql, params).fetchone()
        return int(row["c"])

    @_locked
    def query_timeline_points(
        self,
        *,
        collection_id: str | None = None,
        event_types: list[str] | None = None,
        source_artifacts: list[str] | None = None,
        summary_contains: str | None = None,
        limit: int = 100_000,
    ) -> list[dict[str, Any]]:
        """Lightweight projection for the timeline: skips JSON blobs and undated events."""
        where: list[str] = ["timestamp IS NOT NULL"]
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        if event_types:
            placeholders = ",".join("?" * len(event_types))
            where.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        if source_artifacts:
            placeholders = ",".join("?" * len(source_artifacts))
            where.append(f"source_artifact IN ({placeholders})")
            params.extend(source_artifacts)
        if summary_contains:
            where.append(f"summary LIKE ? {_LIKE_ESCAPE}")
            params.append(_like_pattern(summary_contains))

        sql = (
            "SELECT event_id, timestamp, source_artifact, event_type, summary "
            "FROM events WHERE " + " AND ".join(where) +
            " ORDER BY timestamp ASC LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    @_locked
    def activity_by_day(self, *, collection_id: str | None = None) -> list[dict[str, Any]]:
        """Per-calendar-day event counts with a per-event-type breakdown.

        Days are the ``YYYY-MM-DD`` prefix of the normalized ISO-8601 (UTC)
        timestamp; undated events are excluded. Returned in ascending date
        order, each row ``{date, count, by_event_type}``.
        """
        where = ["timestamp IS NOT NULL"]
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        sql = (
            "SELECT substr(timestamp, 1, 10) AS day, event_type, COUNT(*) AS c "
            "FROM events WHERE " + " AND ".join(where) +
            " GROUP BY day, event_type ORDER BY day ASC"
        )
        per_day: dict[str, dict[str, Any]] = {}
        for r in self._conn.execute(sql, params).fetchall():
            day = r["day"]
            d = per_day.setdefault(day, {"date": day, "count": 0, "by_event_type": {}})
            d["count"] += r["c"]
            d["by_event_type"][r["event_type"]] = r["c"]
        return list(per_day.values())

    @_locked
    def events_on_day(
        self,
        day: str,
        *,
        collection_id: str | None = None,
        event_types: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Events whose timestamp falls on ``day`` (``YYYY-MM-DD``), ascending."""
        where = ["substr(timestamp, 1, 10) = ?"]
        params: list[Any] = [day]
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        if event_types:
            placeholders = ",".join("?" * len(event_types))
            where.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        sql = (
            "SELECT event_id, timestamp, event_type, source_artifact, summary "
            "FROM events WHERE " + " AND ".join(where) +
            " ORDER BY timestamp ASC LIMIT ?"
        )
        params.append(limit)
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    @_locked
    def count_undated_events(
        self,
        *,
        collection_id: str | None = None,
        event_types: list[str] | None = None,
        source_artifacts: list[str] | None = None,
        summary_contains: str | None = None,
    ) -> int:
        where: list[str] = ["timestamp IS NULL"]
        params: list[Any] = []
        if collection_id is not None:
            where.append("collection_id = ?")
            params.append(collection_id)
        if event_types:
            placeholders = ",".join("?" * len(event_types))
            where.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        if source_artifacts:
            placeholders = ",".join("?" * len(source_artifacts))
            where.append(f"source_artifact IN ({placeholders})")
            params.extend(source_artifacts)
        if summary_contains:
            where.append(f"summary LIKE ? {_LIKE_ESCAPE}")
            params.append(_like_pattern(summary_contains))
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE " + " AND ".join(where),
            params,
        ).fetchone()
        return int(row["c"])

    @_locked
    def counts_by_source_artifact(self, *, collection_id: str | None = None) -> dict[str, int]:
        if collection_id is None:
            rows = self._conn.execute(
                "SELECT source_artifact, COUNT(*) AS c FROM events GROUP BY source_artifact"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT source_artifact, COUNT(*) AS c FROM events "
                "WHERE collection_id = ? GROUP BY source_artifact",
                (collection_id,),
            ).fetchall()
        return {row["source_artifact"]: int(row["c"]) for row in rows}


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
    d["raw"] = json.loads(d.pop("raw_json") or "{}")
    return d


def _deletion_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["is_directory"] = bool(d.get("is_directory"))
    return d


def _finding_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["mitre_techniques"] = json.loads(d.pop("mitre_techniques_json") or "[]")
    d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json") or "[]")
    d["evidence_event_ids"] = json.loads(d.pop("evidence_event_ids_json") or "[]")
    return d

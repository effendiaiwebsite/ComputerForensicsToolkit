"""SQLite-backed event store.

In-memory by default for live triage; pass a path to persist a case file. Designed
to be queried by the UI through the IPC layer — filters, sort, pagination all live
here so the wire payload stays small.

Schema is intentionally flat with a JSON-typed ``evidence``/``raw`` blob so we can
evolve fields without migrations during Phase 1. We keep ``timestamp`` and
``event_type`` as their own indexed columns because every query hits them.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core import SCHEMA_VERSION
from core.events import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
    collection_id TEXT PRIMARY KEY,
    host_id       TEXT NOT NULL,
    host_os       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    note          TEXT
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
"""

_SORT_COLUMNS = {
    "timestamp",
    "event_type",
    "source_artifact",
    "host_id",
    "user",
    "summary",
}


class EventStore:
    """Thin wrapper over sqlite3 with the queries the UI needs."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    def close(self) -> None:
        self._conn.close()

    def register_collection(
        self,
        collection_id: str,
        host_id: str,
        host_os: str,
        created_at: str,
        note: str | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO collections(collection_id, host_id, host_os, created_at, note) "
            "VALUES (?, ?, ?, ?, ?)",
            (collection_id, host_id, host_os, created_at, note),
        )

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
            where.append("summary LIKE ?")
            params.append(f"%{summary_contains}%")

        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        # NULLS LAST for timestamp asc so undated events fall to the bottom.
        nulls = "NULLS LAST" if sort_dir.lower() == "asc" else "NULLS FIRST"
        sql = (
            "SELECT event_id, collection_id, timestamp, timestamp_source, host_os, "
            "host_id, user, source_artifact, source_path, event_type, summary, "
            "evidence_json, raw_json, parser_version FROM events"
            f"{where_sql} ORDER BY {sort_by} {sort_dir.upper()} {nulls} LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(row) for row in rows]

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

    def clear_findings(self, *, collection_id: str | None = None) -> int:
        if collection_id is None:
            cur = self._conn.execute("DELETE FROM findings")
        else:
            cur = self._conn.execute(
                "DELETE FROM findings WHERE collection_id = ?", (collection_id,)
            )
        return cur.rowcount or 0

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

    def count_findings(self, *, collection_id: str | None = None) -> int:
        if collection_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE collection_id = ?",
                (collection_id,),
            ).fetchone()
        return int(row["c"])

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

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT event_id, collection_id, timestamp, timestamp_source, host_os, "
            "host_id, user, source_artifact, source_path, event_type, summary, "
            "evidence_json, raw_json, parser_version FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return _row_to_dict(row) if row else None

    def count_events(self, *, collection_id: str | None = None) -> int:
        if collection_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE collection_id = ?",
                (collection_id,),
            ).fetchone()
        return int(row["c"])

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
            where.append("summary LIKE ?")
            params.append(f"%{summary_contains}%")

        sql = (
            "SELECT event_id, timestamp, source_artifact, event_type, summary "
            "FROM events WHERE " + " AND ".join(where) +
            " ORDER BY timestamp ASC LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

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
            where.append("summary LIKE ?")
            params.append(f"%{summary_contains}%")
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE " + " AND ".join(where),
            params,
        ).fetchone()
        return int(row["c"])

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


def _finding_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["mitre_techniques"] = json.loads(d.pop("mitre_techniques_json") or "[]")
    d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json") or "[]")
    d["evidence_event_ids"] = json.loads(d.pop("evidence_event_ids_json") or "[]")
    return d

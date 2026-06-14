"""Chromium-family browser History DB parser (Chrome, Edge, Brave).

Emits three event types:

* ``browser_visit``     — one per row in ``visits``  (joined with ``urls``)
* ``browser_download``  — one per row in ``downloads`` (joined with
  ``downloads_url_chains`` for the source URL chain)
* ``browser_search``    — one per row in ``keyword_search_terms``
  (joined with ``urls``)

The History DB is opened **read-only, immutable** via a SQLite URI so we never
mutate the artifact the examiner handed us. Missing tables/columns are tolerated
silently — Chromium has churned its schema across versions, and a missing table
just means "no events of this kind to emit."

Timestamps in Chromium are microseconds since ``1601-01-01 UTC`` (Windows
FILETIME / WebKit epoch). 0 / null is left as ``None`` rather than emitted as
the 1601 sentinel.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from collectors.windows.browser import BrowserKind, detect_browser_kind
from core.events import Event, make_event

PARSER_VERSION = "browser_history/0.1.0"
HOST_OS = "windows"

logger = logging.getLogger(__name__)

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Chromium PageTransition core types (low 8 bits).
_TRANSITION_CORE = {
    0: "link",
    1: "typed",
    2: "auto_bookmark",
    3: "auto_subframe",
    4: "manual_subframe",
    5: "generated",
    6: "auto_toplevel",
    7: "form_submit",
    8: "reload",
    9: "keyword",
    10: "keyword_generated",
}

_TRANSITION_QUALIFIERS = (
    (0x01000000, "forward_back"),
    (0x02000000, "from_address_bar"),
    (0x04000000, "home_page"),
    (0x08000000, "from_api"),
    (0x10000000, "chain_start"),
    (0x20000000, "chain_end"),
    (0x40000000, "client_redirect"),
    (0x80000000, "server_redirect"),
)


def parse_browser_history(
    db_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
    browser_kind: BrowserKind | None = None,
) -> list[Event]:
    path_str = str(Path(db_path).resolve())
    kind = browser_kind or detect_browser_kind(path_str)
    source_artifact = f"{kind}.history"

    try:
        conn = sqlite3.connect(
            f"file:{Path(path_str).as_posix()}?mode=ro&immutable=1",
            uri=True,
        )
    except sqlite3.Error:
        logger.exception("could not open browser history %s", path_str)
        return []
    conn.row_factory = sqlite3.Row
    try:
        events: list[Event] = []
        events.extend(_emit_visits(conn, path_str, source_artifact, collection_id, host_id_hint, user_hint))
        events.extend(_emit_downloads(conn, path_str, source_artifact, collection_id, host_id_hint, user_hint))
        events.extend(_emit_searches(conn, path_str, source_artifact, collection_id, host_id_hint, user_hint))
        return events
    finally:
        conn.close()


# ----- visits ------------------------------------------------------------------


def _emit_visits(
    conn: sqlite3.Connection,
    source_path: str,
    source_artifact: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    if not _table_exists(conn, "visits") or not _table_exists(conn, "urls"):
        return []
    rows = _safe_fetch(
        conn,
        """
        SELECT v.id            AS visit_id,
               v.visit_time    AS visit_time,
               v.from_visit    AS from_visit,
               v.transition    AS transition,
               v.visit_duration AS visit_duration,
               u.url           AS url,
               u.title         AS title,
               u.visit_count   AS visit_count,
               u.typed_count   AS typed_count
        FROM visits v
        JOIN urls u ON u.id = v.url
        ORDER BY v.visit_time ASC
        """,
    )
    out: list[Event] = []
    for r in rows:
        url = r["url"] or ""
        title = r["title"] or ""
        ts = _webkit_us_to_iso(r["visit_time"])
        core, qualifiers = _decode_transition(r["transition"])
        host = _safe_host(url)
        duration_us = r["visit_duration"]
        summary_parts: list[str] = []
        if title:
            summary_parts.append(_clip(title, 80))
            summary_parts.append(f"({host})" if host else "")
        else:
            summary_parts.append(_clip(url, 100))
        summary = "Visit: " + " ".join(p for p in summary_parts if p)

        out.append(make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=source_artifact,
            source_path=source_path,
            event_type="browser_visit",
            summary=summary,
            evidence={
                "url": url,
                "host": host,
                "title": title,
                "transition": core,
                "transition_qualifiers": qualifiers,
                "from_visit": r["from_visit"] if r["from_visit"] else None,
                "visit_count": r["visit_count"],
                "typed_count": r["typed_count"],
                "visit_duration_ms": _us_to_ms(duration_us),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={
                "visit_id": r["visit_id"],
                "visit_time": r["visit_time"],
                "transition": r["transition"],
            },
        ))
    return out


# ----- downloads ---------------------------------------------------------------


def _emit_downloads(
    conn: sqlite3.Connection,
    source_path: str,
    source_artifact: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    if not _table_exists(conn, "downloads"):
        return []
    cols = _columns(conn, "downloads")
    select_cols = [c for c in (
        "id", "target_path", "current_path", "start_time", "end_time",
        "received_bytes", "total_bytes", "state", "danger_type",
        "interrupt_reason", "mime_type", "original_mime_type",
        "referrer", "site_url", "tab_url", "tab_referrer_url",
        "opened", "last_modified", "hash",
    ) if c in cols]
    if "id" not in select_cols or "start_time" not in select_cols:
        return []

    select_sql = ", ".join(f"d.{c}" for c in select_cols)
    rows = _safe_fetch(
        conn,
        f"SELECT {select_sql} FROM downloads d ORDER BY d.start_time ASC",
    )

    chains: dict[int, list[str]] = {}
    if _table_exists(conn, "downloads_url_chains"):
        chain_rows = _safe_fetch(
            conn,
            "SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index",
        )
        for cr in chain_rows:
            chains.setdefault(cr["id"], []).append(cr["url"] or "")

    out: list[Event] = []
    for r in rows:
        rd = dict(r)
        did = rd.get("id")
        target = rd.get("target_path") or rd.get("current_path") or ""
        url_chain = chains.get(did, [])
        source_url = url_chain[-1] if url_chain else (rd.get("referrer") or "")
        source_host = _safe_host(source_url)
        ts = _webkit_us_to_iso(rd.get("start_time"))
        end_ts = _webkit_us_to_iso(rd.get("end_time"))
        filename = Path(target).name if target else ""
        size = rd.get("total_bytes") or rd.get("received_bytes")
        size_str = f" ({_human_bytes(size)})" if size else ""
        host_str = f" from {source_host}" if source_host else ""
        summary = f"Download: {filename or _clip(target, 80)}{size_str}{host_str}"

        out.append(make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=source_artifact,
            source_path=source_path,
            event_type="browser_download",
            summary=summary,
            evidence={
                "target_path": target,
                "filename": filename,
                "source_url": source_url,
                "source_host": source_host,
                "url_chain": url_chain,
                "received_bytes": rd.get("received_bytes"),
                "total_bytes": rd.get("total_bytes"),
                "mime_type": rd.get("mime_type") or rd.get("original_mime_type"),
                "danger_type": rd.get("danger_type"),
                "interrupt_reason": rd.get("interrupt_reason"),
                "state": rd.get("state"),
                "referrer": rd.get("referrer"),
                "tab_url": rd.get("tab_url"),
                "end_time": end_ts,
                "opened": rd.get("opened"),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={"download_id": did, "start_time": rd.get("start_time")},
        ))
    return out


# ----- searches ----------------------------------------------------------------


def _emit_searches(
    conn: sqlite3.Connection,
    source_path: str,
    source_artifact: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    if not _table_exists(conn, "keyword_search_terms") or not _table_exists(conn, "urls"):
        return []
    rows = _safe_fetch(
        conn,
        """
        SELECT k.term            AS term,
               u.url             AS url,
               u.last_visit_time AS last_visit_time,
               u.visit_count     AS visit_count
        FROM keyword_search_terms k
        JOIN urls u ON u.id = k.url_id
        ORDER BY u.last_visit_time ASC
        """,
    )
    out: list[Event] = []
    for r in rows:
        term = r["term"] or ""
        url = r["url"] or ""
        host = _safe_host(url)
        ts = _webkit_us_to_iso(r["last_visit_time"])
        summary = f"Search: {_clip(term, 100)}" + (f"  ({host})" if host else "")
        out.append(make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=source_artifact,
            source_path=source_path,
            event_type="browser_search",
            summary=summary,
            evidence={
                "term": term,
                "url": url,
                "host": host,
                "visit_count": r["visit_count"],
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={"last_visit_time": r["last_visit_time"]},
        ))
    return out


# ----- helpers -----------------------------------------------------------------


def _webkit_us_to_iso(microseconds: int | None) -> str | None:
    if not microseconds:
        return None
    try:
        dt = _WEBKIT_EPOCH + timedelta(microseconds=int(microseconds))
    except (OverflowError, ValueError):
        return None
    if dt.year < 1970:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _us_to_ms(us: int | None) -> int | None:
    if us is None:
        return None
    try:
        return int(us) // 1000
    except (TypeError, ValueError):
        return None


def _decode_transition(raw: int | None) -> tuple[str, list[str]]:
    if raw is None:
        return "unknown", []
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return "unknown", []
    core = _TRANSITION_CORE.get(val & 0xFF, f"core_{val & 0xFF}")
    qualifiers = [name for mask, name in _TRANSITION_QUALIFIERS if val & mask]
    return core, qualifiers


def _safe_host(url: str) -> str:
    if not url:
        return ""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    )
    return cur.fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _safe_fetch(conn: sqlite3.Connection, sql: str) -> list[sqlite3.Row]:
    try:
        return list(conn.execute(sql))
    except sqlite3.Error:
        logger.exception("query failed: %s", sql.split("\n", 1)[0].strip())
        return []


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _human_bytes(n: int | None) -> str:
    if not n:
        return ""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{int(n)} B"

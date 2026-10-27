"""Firefox ``places.sqlite`` history/downloads/bookmarks parser.

Emits three event types:

* ``browser_visit``    — one per row in ``moz_historyvisits`` (joined with
  ``moz_places``)
* ``browser_download`` — reconstructed from the ``moz_annos`` annotation pairs
  ``downloads/destinationFileURI`` + ``downloads/metaData`` (Firefox keeps no
  downloads *table*; it annotates the originating place row instead)
* ``browser_bookmark`` — one per URL row in ``moz_bookmarks`` (type 1) joined
  with ``moz_places``

The DB is opened read-only through :mod:`parsers._sqlite` (a temp-dir snapshot
when a ``-wal``/``-journal`` sidecar is present, ``immutable=1`` in place
otherwise) so we never mutate the artifact. Missing tables/columns are
tolerated silently — Firefox has reworked this schema repeatedly
(``moz_origins``, the downloads-to-annotations move in FF 26, ``rev_host``
formatting), and a missing table just means "no events of this kind to emit."

Firefox timestamps are **microseconds since the Unix epoch** (PRTime) — a
different epoch from Chromium's 1601 WebKit time. Download ``endTime`` inside
the ``downloads/metaData`` JSON blob is **milliseconds** since the Unix epoch.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlsplit

from core.events import Event, make_event
from parsers._sqlite import open_sqlite_readonly
from parsers.browser import (
    _clip,
    _columns,
    _human_bytes,
    _safe_fetch,
    _safe_host,
    _table_exists,
)

PARSER_VERSION = "firefox_history/0.1.0"
HOST_OS = "windows"
SOURCE_ARTIFACT = "firefox.history"

logger = logging.getLogger(__name__)

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Firefox nsINavHistoryService transition types (moz_historyvisits.visit_type).
_VISIT_TYPE = {
    1: "link",
    2: "typed",
    3: "bookmark",
    4: "embed",
    5: "redirect_permanent",
    6: "redirect_temporary",
    7: "download",
    8: "framed_link",
    9: "reload",
}


def parse_firefox_history(
    db_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    path_str = str(Path(db_path).resolve())
    with ExitStack() as stack:
        try:
            conn = stack.enter_context(open_sqlite_readonly(path_str))
        except (sqlite3.Error, OSError):
            logger.exception("could not open firefox places db %s", path_str)
            return []
        conn.row_factory = sqlite3.Row
        args = (path_str, collection_id, host_id_hint, user_hint)
        events: list[Event] = []
        events.extend(_emit_visits(conn, *args))
        events.extend(_emit_downloads(conn, *args))
        events.extend(_emit_bookmarks(conn, *args))
        return events


# ----- visits ------------------------------------------------------------------


def _emit_visits(
    conn: sqlite3.Connection,
    source_path: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    if not _table_exists(conn, "moz_historyvisits") or not _table_exists(conn, "moz_places"):
        return []
    rows = _safe_fetch(
        conn,
        """
        SELECT h.id          AS visit_id,
               h.visit_date  AS visit_date,
               h.visit_type  AS visit_type,
               h.from_visit  AS from_visit,
               h.session     AS session,
               p.url         AS url,
               p.title       AS title,
               p.visit_count AS visit_count,
               p.typed       AS typed,
               p.hidden      AS hidden,
               p.rev_host    AS rev_host
        FROM moz_historyvisits h
        JOIN moz_places p ON p.id = h.place_id
        ORDER BY h.visit_date ASC
        """,
    )
    out: list[Event] = []
    for r in rows:
        url = r["url"] or ""
        title = r["title"] or ""
        ts = _unix_us_to_iso(r["visit_date"])
        vtype = _VISIT_TYPE.get(r["visit_type"], f"type_{r['visit_type']}")
        host = _safe_host(url) or _host_from_rev(r["rev_host"])
        if title:
            summary = "Visit: " + _clip(title, 80) + (f" ({host})" if host else "")
        else:
            summary = "Visit: " + _clip(url, 100)

        out.append(make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=SOURCE_ARTIFACT,
            source_path=source_path,
            event_type="browser_visit",
            summary=summary,
            evidence={
                "url": url,
                "host": host,
                "title": title,
                "transition": vtype,
                "from_visit": r["from_visit"] or None,
                "visit_count": r["visit_count"],
                "typed": bool(r["typed"]),
                "hidden": bool(r["hidden"]),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={
                "visit_id": r["visit_id"],
                "visit_date": r["visit_date"],
                "visit_type": r["visit_type"],
            },
        ))
    return out


# ----- downloads ---------------------------------------------------------------


def _emit_downloads(
    conn: sqlite3.Connection,
    source_path: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    if not (
        _table_exists(conn, "moz_annos")
        and _table_exists(conn, "moz_anno_attributes")
        and _table_exists(conn, "moz_places")
    ):
        return []

    attrs = {
        r["id"]: r["name"]
        for r in _safe_fetch(conn, "SELECT id, name FROM moz_anno_attributes")
    }
    if not any(name.startswith("downloads/") for name in attrs.values()):
        return []

    # Collapse the (place_id → {annotation_name: content}) pairs.
    per_place: dict[int, dict[str, object]] = {}
    cols = _columns(conn, "moz_annos")
    date_col = "dateAdded" if "dateAdded" in cols else None
    anno_sql = (
        "SELECT place_id, anno_attribute_id, content, dateAdded FROM moz_annos"
        if date_col
        else "SELECT place_id, anno_attribute_id, content FROM moz_annos"
    )
    for r in _safe_fetch(conn, anno_sql):
        name = attrs.get(r["anno_attribute_id"])
        if not name or not name.startswith("downloads/"):
            continue
        rec = per_place.setdefault(r["place_id"], {})
        rec[name] = r["content"]
        if date_col and name == "downloads/destinationFileURI":
            rec["_date_added"] = r["dateAdded"]

    if not per_place:
        return []

    places = {
        r["id"]: (r["url"], r["title"])
        for r in _safe_fetch(conn, "SELECT id, url, title FROM moz_places")
    }

    out: list[Event] = []
    for place_id, anno in per_place.items():
        dest_uri = anno.get("downloads/destinationFileURI")
        target = _file_uri_to_path(dest_uri) if isinstance(dest_uri, str) else ""
        url = places.get(place_id, ("", ""))[0] or ""
        source_host = _safe_host(url)

        size = None
        state = None
        end_ts = None
        meta_raw = anno.get("downloads/metaData")
        if isinstance(meta_raw, str):
            try:
                meta = json.loads(meta_raw)
            except (ValueError, TypeError):
                meta = {}
            size = meta.get("fileSize")
            state = meta.get("state")
            end_ts = _unix_ms_to_iso(meta.get("endTime"))

        ts = _unix_us_to_iso(anno.get("_date_added"))
        filename = Path(target).name if target else ""
        size_str = f" ({_human_bytes(size)})" if size else ""
        host_str = f" from {source_host}" if source_host else ""
        summary = f"Download: {filename or _clip(target, 80)}{size_str}{host_str}"

        out.append(make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=SOURCE_ARTIFACT,
            source_path=source_path,
            event_type="browser_download",
            summary=summary,
            evidence={
                "target_path": target,
                "filename": filename,
                "source_url": url,
                "source_host": source_host,
                "total_bytes": size,
                "state": state,
                "end_time": end_ts,
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={"place_id": place_id},
        ))
    return out


# ----- bookmarks ---------------------------------------------------------------


def _emit_bookmarks(
    conn: sqlite3.Connection,
    source_path: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    if not _table_exists(conn, "moz_bookmarks") or not _table_exists(conn, "moz_places"):
        return []
    rows = _safe_fetch(
        conn,
        """
        SELECT b.id           AS bookmark_id,
               b.title        AS title,
               b.dateAdded    AS date_added,
               b.lastModified AS last_modified,
               p.url          AS url
        FROM moz_bookmarks b
        JOIN moz_places p ON p.id = b.fk
        WHERE b.type = 1
        ORDER BY b.dateAdded ASC
        """,
    )
    out: list[Event] = []
    for r in rows:
        url = r["url"] or ""
        title = r["title"] or ""
        host = _safe_host(url)
        ts = _unix_us_to_iso(r["date_added"])
        summary = "Bookmark: " + (_clip(title, 80) if title else _clip(url, 100))
        if title and host:
            summary += f" ({host})"
        out.append(make_event(
            host_os=HOST_OS,
            host_id=host_id,
            source_artifact=SOURCE_ARTIFACT,
            source_path=source_path,
            event_type="browser_bookmark",
            summary=summary,
            evidence={
                "url": url,
                "host": host,
                "title": title,
                "last_modified": _unix_us_to_iso(r["last_modified"]),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={"bookmark_id": r["bookmark_id"], "date_added": r["date_added"]},
        ))
    return out


# ----- helpers -----------------------------------------------------------------


def _unix_us_to_iso(microseconds: object) -> str | None:
    if not microseconds:
        return None
    try:
        dt = _UNIX_EPOCH + timedelta(microseconds=int(microseconds))  # type: ignore[arg-type]
    except (OverflowError, ValueError, TypeError):
        return None
    if dt.year < 1970 or dt.year > 9000:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_ms_to_iso(milliseconds: object) -> str | None:
    if not milliseconds:
        return None
    try:
        dt = _UNIX_EPOCH + timedelta(milliseconds=int(milliseconds))  # type: ignore[arg-type]
    except (OverflowError, ValueError, TypeError):
        return None
    if dt.year < 1970 or dt.year > 9000:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_from_rev(rev_host: object) -> str:
    """``moz_places.rev_host`` stores the host reversed with a trailing dot,
    e.g. ``moc.elgoog.www.`` for ``www.google.com``. Recover the readable host."""
    if not isinstance(rev_host, str) or not rev_host:
        return ""
    return rev_host[::-1].lstrip(".")


def _file_uri_to_path(uri: str) -> str:
    """Convert a ``file:///C:/Users/...`` destination URI to a plain path."""
    if not uri:
        return ""
    if uri.lower().startswith("file:"):
        parsed = urlsplit(uri)
        path = unquote(parsed.path)
        # file:///C:/... → strip the leading slash before the drive letter.
        if len(path) >= 3 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return path.replace("/", "\\") if (len(path) >= 2 and path[1] == ":") else path
    return uri

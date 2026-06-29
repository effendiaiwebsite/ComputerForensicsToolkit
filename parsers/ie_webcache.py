"""Internet Explorer / legacy-Edge ``WebCacheV01.dat`` parser.

``WebCacheV01.dat`` is an ESE (Extensible Storage Engine) database under
``%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache``. It holds the post-IE10
browsing history, cookies, and download metadata that NirSoft's *Browsing
HistoryView* would otherwise surface. We read it via ``dissect.database.ese``
(a transitive dependency of ``dissect.target`` — the standalone
``dissect.esedb`` package is *not* required).

Layout: a ``Containers`` table maps a container *name* (``History``,
``iedownload``, ``Cookies``, …) to one or more numeric ``ContainerId`` values;
the actual entries live in per-container tables named ``Container_<id>``.

Emits:

* ``browser_visit``    — from ``History`` containers
* ``browser_download`` — from ``iedownload`` containers

``source_artifact='ie.webcache'``. ESE timestamps are Windows FILETIME
(100 ns since 1601), decoded with :func:`dissect.util.ts.wintimestamp`.

A ``WebCacheV01.dat`` copied off a live system is frequently in a *dirty*
state (the ESE log wasn't replayed). dissect reads the committed pages
best-effort; any open/parse failure is logged and yields no events rather
than aborting the triage run.
"""

from __future__ import annotations

import logging
from pathlib import Path

from core.events import Event, make_event
from parsers.browser import _clip, _safe_host

PARSER_VERSION = "ie_webcache/0.1.0"
HOST_OS = "windows"
SOURCE_ARTIFACT = "ie.webcache"

logger = logging.getLogger(__name__)

_HISTORY_NAMES = ("history",)
_DOWNLOAD_NAMES = ("iedownload",)


def parse_ie_webcache(
    dat_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    path_str = str(Path(dat_path).resolve())
    try:
        from dissect.database.ese import ESE
    except ImportError:
        logger.error("dissect.database.ese unavailable; cannot parse %s", path_str)
        return []

    try:
        fh = open(path_str, "rb")  # noqa: SIM115 — handle is closed in finally
    except OSError:
        logger.exception("could not open webcache %s", path_str)
        return []

    try:
        db = ESE(fh)
    except Exception:
        logger.exception("could not parse ESE database %s (dirty shutdown?)", path_str)
        fh.close()
        return []

    try:
        table_names = {t.name for t in db.tables()}
        containers = _index_containers(db)
        args = (table_names, containers, path_str, collection_id, host_id_hint, user_hint)
        events: list[Event] = []
        events.extend(_emit_visits(db, *args))
        events.extend(_emit_downloads(db, *args))
        return events
    except Exception:
        logger.exception("webcache parse failed for %s", path_str)
        return []
    finally:
        fh.close()


def _index_containers(db) -> dict[str, list[int]]:
    """Map lowercased container name → list of ``ContainerId`` values."""
    out: dict[str, list[int]] = {}
    try:
        table = db.table("Containers")
    except Exception:
        logger.warning("WebCache has no Containers table")
        return out
    for rec in table.records():
        name = rec.get("Name")
        cid = rec.get("ContainerId")
        if name is None or cid is None:
            continue
        if isinstance(name, bytes):
            name = name.decode("utf-16-le", errors="ignore")
        name = name.rstrip("\x00").strip().lower()
        if name:
            out.setdefault(name, []).append(int(cid))
    return out


def _iter_container_records(db, table_names: set[str], container_ids: list[int]):
    for cid in container_ids:
        tname = f"Container_{cid}"
        if tname not in table_names:
            continue
        try:
            table = db.table(tname)
        except Exception:
            logger.warning("could not open %s", tname)
            continue
        try:
            yield from table.records()
        except Exception:
            logger.warning("error iterating %s", tname)
            continue


# ----- visits ------------------------------------------------------------------


def _emit_visits(
    db,
    table_names: set[str],
    containers: dict[str, list[int]],
    source_path: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    from dissect.util.ts import wintimestamp

    ids: list[int] = []
    for name in _HISTORY_NAMES:
        ids.extend(containers.get(name, []))
    if not ids:
        return []

    out: list[Event] = []
    for rec in _iter_container_records(db, table_names, ids):
        raw_url = rec.get("Url")
        if not raw_url:
            continue
        if isinstance(raw_url, bytes):
            raw_url = raw_url.decode("utf-8", errors="ignore")
        # History entries are prefixed "Visited: <user>@<url>"; keep the URL.
        cleaned = raw_url.rstrip("\x00")
        _, sep, tail = cleaned.partition("@")
        url = tail if sep else cleaned
        if not url:
            continue
        host = _safe_host(url)

        ts = None
        accessed = rec.get("AccessedTime")
        if accessed:
            try:
                ts = wintimestamp(accessed)
            except (ValueError, OverflowError, OSError):
                ts = None

        summary = "Visit: " + _clip(url, 100) + (f" ({host})" if host else "")
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
                "title": None,
                "visit_count": rec.get("AccessCount"),
                "entry_id": rec.get("EntryId"),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts,
            user=user,
            raw={"accessed_time": accessed, "raw_url": cleaned},
        ))
    return out


# ----- downloads ---------------------------------------------------------------


def _emit_downloads(
    db,
    table_names: set[str],
    containers: dict[str, list[int]],
    source_path: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> list[Event]:
    from dissect.util.ts import wintimestamp

    ids: list[int] = []
    for name in _DOWNLOAD_NAMES:
        ids.extend(containers.get(name, []))
    if not ids:
        return []

    out: list[Event] = []
    for rec in _iter_container_records(db, table_names, ids):
        source_url = ""
        target = ""
        headers = rec.get("ResponseHeaders")
        if isinstance(headers, bytes):
            try:
                decoded = headers.decode("utf-16-le", errors="ignore")
                parts = decoded.split("\x00")
                if len(parts) >= 3:
                    source_url, target = parts[-3], parts[-2]
            except (ValueError, IndexError):
                pass

        ts_end = None
        accessed = rec.get("AccessedTime")
        if accessed:
            try:
                ts_end = wintimestamp(accessed)
            except (ValueError, OverflowError, OSError):
                ts_end = None

        source_host = _safe_host(source_url)
        filename = Path(target.replace("\\", "/")).name if target else ""
        host_str = f" from {source_host}" if source_host else ""
        summary = f"Download: {filename or _clip(target, 80) or '(unknown)'}{host_str}"

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
                "source_url": source_url,
                "source_host": source_host,
                "entry_id": rec.get("EntryId"),
                "end_time": _iso_or_none(ts_end),
            },
            collection_id=collection_id,
            parser_version=PARSER_VERSION,
            timestamp=ts_end,
            user=user,
            raw={"accessed_time": accessed},
        ))
    return out


def _iso_or_none(dt) -> str | None:
    if dt is None:
        return None
    try:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (AttributeError, ValueError):
        return None

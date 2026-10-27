"""Legacy Internet Explorer ``index.dat`` (MSIE Cache File) parser.

Pre-IE10 / Vista-era IE stores history, cache, and cookie metadata in binary
``index.dat`` files (the *MSIE Cache File* format), e.g.

* History:  ``AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\index.dat``
* Cache:    ``...\\Temporary Internet Files\\Content.IE5\\index.dat``
* Cookies:  ``...\\Cookies\\index.dat``

This is a *different* format from the modern ESE ``WebCacheV01.dat`` (see
:mod:`parsers.ie_webcache`) and is what the Vista-era forensic corpora (e.g.
the SANS "Wes Mantooth" image) actually contain.

We read it via ``pymsiecf`` (libmsiecf — same author/family as the
``libscca``/``libfwsi`` already in deps). Each URL item carries a ``location``
(often prefixed ``Visited: <user>@<url>``), a ``primary_time`` (last-accessed,
UTC), a hit count, and cache metadata. Emits one ``browser_visit`` per URL
item; the original record class (history/cache/cookie) is preserved in
``evidence.record_kind``.

The daily ``MSHistNN...`` sub-index files sometimes lack a standard signature
and fail to open — that (and any per-item read error) is logged and skipped
rather than aborting the run.
"""

from __future__ import annotations

import logging
from datetime import UTC
from pathlib import Path

from core.events import Event, make_event
from parsers.browser import _clip, _safe_host

PARSER_VERSION = "ie_index_dat/0.1.0"
HOST_OS = "windows"
SOURCE_ARTIFACT = "ie.index_dat"

logger = logging.getLogger(__name__)


def parse_ie_index_dat(
    dat_path: str | Path,
    *,
    collection_id: str,
    host_id_hint: str,
    user_hint: str | None = None,
) -> list[Event]:
    try:
        import pymsiecf
    except ImportError:
        logger.error("pymsiecf unavailable; cannot parse %s", dat_path)
        return []

    path_str = str(Path(dat_path).resolve())
    f = pymsiecf.file()
    try:
        f.open(path_str)
    except OSError:
        logger.warning("could not open MSIE index.dat %s (invalid signature?)", path_str)
        return []

    try:
        events: list[Event] = []
        for i in range(f.number_of_items):
            try:
                item = f.get_item(i)
            except OSError:
                continue
            ev = _item_to_event(item, path_str, collection_id, host_id_hint, user_hint)
            if ev is not None:
                events.append(ev)
        return events
    finally:
        f.close()


def _item_to_event(
    item,
    source_path: str,
    collection_id: str,
    host_id: str,
    user: str | None,
) -> Event | None:
    # Only URL items carry a location; leak/redirect items are skipped.
    if type(item).__name__ != "url":
        return None
    location = getattr(item, "location", None)
    if not location:
        return None

    record_kind = getattr(item, "type", None)  # 'history' | 'cache' | 'cookie' | ...
    # History/cookie locations are prefixed "Visited: user@url" / "Cookie:user@url".
    _, sep, tail = location.partition("@")
    url = tail if sep else location
    if not url:
        return None
    host = _safe_host(url)

    ts = _dt_to_iso(getattr(item, "primary_time", None))
    secondary = _dt_to_iso(getattr(item, "secondary_time", None))
    last_checked = _dt_to_iso(getattr(item, "last_checked_time", None))

    label = record_kind or "url"
    summary = f"IE {label}: " + _clip(url, 100) + (f" ({host})" if host else "")

    return make_event(
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
            "record_kind": record_kind,
            "visit_count": getattr(item, "number_of_hits", None),
            "cached_filename": getattr(item, "filename", None),
            "cached_file_size": getattr(item, "cached_file_size", None),
            "secondary_time": secondary,
            "last_checked_time": last_checked,
        },
        collection_id=collection_id,
        parser_version=PARSER_VERSION,
        timestamp=ts,
        user=user,
        raw={"location": location, "offset": getattr(item, "offset", None)},
    )


def _dt_to_iso(dt) -> str | None:
    """``pymsiecf`` returns naive ``datetime`` (UTC) or ``None``."""
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (AttributeError, ValueError, OverflowError):
        return None

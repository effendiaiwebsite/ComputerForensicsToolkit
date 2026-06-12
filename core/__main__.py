"""Sidecar entry point: starts the IPC dispatcher and serves over stdio.

Run with: ``python -m core``
"""

from __future__ import annotations

import logging
import socket
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from core import SCHEMA_VERSION, __version__
from core.events import Event
from core.ipc import Dispatcher, serve_stdio
from core.store import EventStore

log = logging.getLogger(__name__)


def _ping(_request: dict[str, Any]) -> dict[str, Any]:
    return {
        "sidecar_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
    }


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_collection_id() -> str:
    return f"col-{uuid.uuid4()}"


def _host_from_events(events: list[Event], fallback: str) -> str:
    for e in events:
        if e.source_artifact == "registry.system" and e.event_type == "system_config_change":
            cn = e.evidence.get("computer_name") if isinstance(e.evidence, dict) else None
            if cn:
                return str(cn)
    return fallback


def _make_run_triage_system_hive(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        hive_path = request.get("hive_path")
        if not isinstance(hive_path, str) or not hive_path:
            return {"ok": False, "error": "missing 'hive_path' string"}
        from collectors.windows.hive import collect_hive
        from parsers.registry_system import parse_system_hive

        bundle = collect_hive(hive_path, kind="system")
        artifact = bundle.artifacts[0]
        events = parse_system_hive(
            artifact.source_path,
            collection_id=bundle.collection_id,
            host_id_hint=bundle.host_id,
        )
        host_id = _host_from_events(events, bundle.host_id)
        store.register_collection(
            collection_id=bundle.collection_id,
            host_id=host_id,
            host_os=bundle.host_os,
            created_at=bundle.created_at,
            note=f"SYSTEM hive: {artifact.source_path}",
        )
        inserted = store.insert_events(events)
        by_type: dict[str, int] = {}
        for e in events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        return {
            "collection_id": bundle.collection_id,
            "host_id": host_id,
            "source_path": artifact.source_path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "event_count": inserted,
            "by_event_type": by_type,
        }

    return handler


def _make_run_triage_hive(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        hive_path = request.get("hive_path")
        if not isinstance(hive_path, str) or not hive_path:
            return {"ok": False, "error": "missing 'hive_path' string"}
        kind_hint = request.get("kind")
        user_hint = request.get("user_hint")
        collection_id = request.get("collection_id")
        host_id_hint = request.get("host_id_hint") or socket.gethostname()

        new_collection = collection_id is None
        collection_id = collection_id or _new_collection_id()

        # Same op handles registry hives, .evtx, and Prefetch — UI doesn't need to know.
        lower = hive_path.lower()
        if lower.endswith(".evtx"):
            from collectors.windows.evtx import collect_evtx
            from parsers.evtx import parse_evtx

            artifact = collect_evtx(hive_path, host_id=host_id_hint)
            events = parse_evtx(
                artifact.source_path,
                collection_id=collection_id,
                host_id_hint=host_id_hint,
                channel_hint=artifact.channel_hint,
            )
            host_id = _host_from_events(events, host_id_hint)
            note = f"evtx ({artifact.channel_hint}): {artifact.source_path}"
            kind_out = "evtx"
        elif lower.endswith(".pf"):
            from collectors.windows.prefetch import collect_prefetch
            from parsers.prefetch import parse_prefetch

            artifact = collect_prefetch(hive_path, host_id=host_id_hint)
            events = parse_prefetch(
                artifact.source_path,
                collection_id=collection_id,
                host_id_hint=host_id_hint,
            )
            host_id = host_id_hint
            note = f"prefetch: {artifact.source_path}"
            kind_out = "prefetch"
        else:
            from collectors.windows.hive import collect_hive
            from parsers.registry import parse_hive

            bundle = collect_hive(hive_path, kind=kind_hint or "system", host_id=host_id_hint)
            artifact = bundle.artifacts[0]
            try:
                detected_kind, events = parse_hive(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id_hint,
                    kind=kind_hint,
                    user_hint=user_hint,
                )
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            host_id = _host_from_events(events, host_id_hint)
            note = f"{detected_kind} hive: {artifact.source_path}"
            kind_out = detected_kind

        if new_collection:
            store.register_collection(
                collection_id=collection_id,
                host_id=host_id,
                host_os="windows",
                created_at=_utc_now_iso(),
                note=note,
            )
        inserted = store.insert_events(events)
        by_type: dict[str, int] = {}
        for e in events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        return {
            "collection_id": collection_id,
            "host_id": host_id,
            "kind": kind_out,
            "source_path": artifact.source_path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "event_count": inserted,
            "by_event_type": by_type,
        }

    return handler


def _make_run_triage_directory(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        dir_path = request.get("dir_path")
        if not isinstance(dir_path, str) or not dir_path:
            return {"ok": False, "error": "missing 'dir_path' string"}
        host_id_hint = request.get("host_id_hint") or socket.gethostname()

        from collectors.windows.evtx import collect_evtx
        from collectors.windows.hive import collect_hive
        from collectors.windows.prefetch import collect_prefetch
        from collectors.windows.user_hives import (
            discover_evtx_files,
            discover_hives,
            discover_prefetch_files,
        )
        from parsers.evtx import parse_evtx
        from parsers.prefetch import parse_prefetch
        from parsers.registry import parse_hive

        hives = discover_hives(dir_path)
        evtx_files = discover_evtx_files(dir_path)
        prefetch_files = discover_prefetch_files(dir_path)
        if not hives and not evtx_files and not prefetch_files:
            return {
                "ok": False,
                "error": f"no registry hives, .evtx, or .pf files found under {dir_path!r}",
            }

        collection_id = _new_collection_id()
        store.register_collection(
            collection_id=collection_id,
            host_id=host_id_hint,
            host_os="windows",
            created_at=_utc_now_iso(),
            note=f"directory triage: {dir_path}",
        )

        per_hive: list[dict[str, Any]] = []
        total = 0
        host_id = host_id_hint

        for hive in hives:
            try:
                bundle = collect_hive(hive.path, kind=hive.kind, host_id=host_id)
                artifact = bundle.artifacts[0]
                detected_kind, events = parse_hive(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id,
                    kind=hive.kind,
                    user_hint=hive.user_hint,
                )
                if detected_kind == "system":
                    host_id = _host_from_events(events, host_id)
                inserted = store.insert_events(events)
                total += inserted
                per_hive.append({
                    "kind": detected_kind,
                    "path": str(hive.path),
                    "user_hint": hive.user_hint,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "event_count": inserted,
                })
            except Exception as exc:
                log.exception("parse failed for %s", hive.path)
                per_hive.append({
                    "kind": hive.kind,
                    "path": str(hive.path),
                    "user_hint": hive.user_hint,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        for ev_file in evtx_files:
            try:
                artifact = collect_evtx(ev_file.path, host_id=host_id)
                events = parse_evtx(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id,
                    channel_hint=ev_file.channel_hint,
                )
                inserted = store.insert_events(events)
                total += inserted
                per_hive.append({
                    "kind": "evtx",
                    "channel": ev_file.channel_hint,
                    "path": str(ev_file.path),
                    "user_hint": None,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "event_count": inserted,
                })
            except Exception as exc:
                log.exception("parse failed for %s", ev_file.path)
                per_hive.append({
                    "kind": "evtx",
                    "channel": ev_file.channel_hint,
                    "path": str(ev_file.path),
                    "user_hint": None,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        for pf in prefetch_files:
            try:
                artifact = collect_prefetch(pf.path, host_id=host_id)
                events = parse_prefetch(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id,
                )
                inserted = store.insert_events(events)
                total += inserted
                per_hive.append({
                    "kind": "prefetch",
                    "path": str(pf.path),
                    "user_hint": None,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "event_count": inserted,
                })
            except Exception as exc:
                log.exception("parse failed for %s", pf.path)
                per_hive.append({
                    "kind": "prefetch",
                    "path": str(pf.path),
                    "user_hint": None,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        return {
            "collection_id": collection_id,
            "host_id": host_id,
            "dir_path": dir_path,
            "event_count": total,
            "by_event_type": store.counts_by_event_type(collection_id=collection_id),
            "by_source_artifact": store.counts_by_source_artifact(collection_id=collection_id),
            "artifacts": per_hive,
        }

    return handler


def _make_query_program_execution_composite(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        rows = store.program_execution_composite(
            collection_id=request.get("collection_id"),
            limit=int(request.get("limit", 1000)),
            offset=int(request.get("offset", 0)),
        )
        return {
            "rows": rows,
            "total": store.program_execution_composite_count(
                collection_id=request.get("collection_id"),
            ),
        }

    return handler


def _make_query_timeline(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        collection_id = request.get("collection_id")
        event_types = request.get("event_types")
        source_artifacts = request.get("source_artifacts")
        summary_contains = request.get("summary_contains")
        limit = int(request.get("limit", 100_000))

        rows = store.query_timeline_points(
            collection_id=collection_id,
            event_types=event_types,
            source_artifacts=source_artifacts,
            summary_contains=summary_contains,
            limit=limit,
        )

        category_index: dict[str, int] = {}
        for row in rows:
            artifact = row["source_artifact"]
            if artifact not in category_index:
                category_index[artifact] = len(category_index)

        points: list[dict[str, Any]] = []
        for row in rows:
            ts_ms = _iso_to_ms(row["timestamp"])
            if ts_ms is None:
                continue
            points.append({
                "event_id": row["event_id"],
                "ts_ms": ts_ms,
                "category_idx": category_index[row["source_artifact"]],
                "event_type": row["event_type"],
                "summary": row["summary"],
            })

        return {
            "categories": sorted(category_index, key=category_index.get),
            "points": points,
            "total": len(points),
            "skipped_unparsable_ts": len(rows) - len(points),
            "skipped_null_ts": store.count_undated_events(
                collection_id=collection_id,
                event_types=event_types,
                source_artifacts=source_artifacts,
                summary_contains=summary_contains,
            ),
        }

    return handler


def _iso_to_ms(s: str | None) -> int | None:
    """Best-effort ISO 8601 → epoch milliseconds."""
    if not s:
        return None
    txt = s.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    # SQLite-ish microsecond truncation: drop nanoseconds past 6 digits.
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        # Try shaving off everything after the decimal seconds.
        if "." in txt:
            head, sep, tail = txt.partition(".")
            # Find tz suffix in tail
            tz_idx = -1
            for i, ch in enumerate(tail):
                if ch in "+-Z":
                    tz_idx = i
                    break
            tz = tail[tz_idx:] if tz_idx >= 0 else ""
            frac = tail[:tz_idx] if tz_idx >= 0 else tail
            frac = frac[:6]
            try:
                dt = datetime.fromisoformat(f"{head}.{frac}{tz}")
            except ValueError:
                return None
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _make_query_events(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        events = store.query_events(
            collection_id=request.get("collection_id"),
            event_type=request.get("event_type"),
            event_types=request.get("event_types"),
            source_artifact=request.get("source_artifact"),
            source_artifacts=request.get("source_artifacts"),
            summary_contains=request.get("summary_contains"),
            sort_by=request.get("sort_by", "timestamp"),
            sort_dir=request.get("sort_dir", "asc"),
            limit=int(request.get("limit", 500)),
            offset=int(request.get("offset", 0)),
        )
        return {
            "events": events,
            "total": store.count_events(collection_id=request.get("collection_id")),
            "by_event_type": store.counts_by_event_type(collection_id=request.get("collection_id")),
            "by_source_artifact": store.counts_by_source_artifact(collection_id=request.get("collection_id")),
        }

    return handler


def build_dispatcher(store: EventStore | None = None) -> Dispatcher:
    store = store or EventStore()
    dispatcher = Dispatcher()
    dispatcher.register("ping", _ping)
    dispatcher.register("run_triage_system_hive", _make_run_triage_system_hive(store))
    dispatcher.register("run_triage_hive", _make_run_triage_hive(store))
    dispatcher.register("run_triage_directory", _make_run_triage_directory(store))
    dispatcher.register("query_events", _make_query_events(store))
    dispatcher.register("query_timeline", _make_query_timeline(store))

    def _get_event_handler(request: dict[str, Any]) -> dict[str, Any]:
        event_id = request.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            return {"ok": False, "error": "missing 'event_id' string"}
        row = store.get_event(event_id)
        if row is None:
            return {"ok": False, "error": "event not found"}
        return {"event": row}

    dispatcher.register("get_event", _get_event_handler)
    dispatcher.register(
        "query_program_execution_composite",
        _make_query_program_execution_composite(store),
    )
    return dispatcher


def main() -> None:
    serve_stdio(build_dispatcher())


if __name__ == "__main__":
    main()

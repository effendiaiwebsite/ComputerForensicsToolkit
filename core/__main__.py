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

        from collectors.windows.hive import collect_hive
        from parsers.registry import parse_hive

        new_collection = collection_id is None
        collection_id = collection_id or _new_collection_id()

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
        if new_collection:
            store.register_collection(
                collection_id=collection_id,
                host_id=host_id,
                host_os="windows",
                created_at=_utc_now_iso(),
                note=f"{detected_kind} hive: {artifact.source_path}",
            )
        inserted = store.insert_events(events)
        by_type: dict[str, int] = {}
        for e in events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        return {
            "collection_id": collection_id,
            "host_id": host_id,
            "kind": detected_kind,
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

        from collectors.windows.hive import collect_hive
        from collectors.windows.user_hives import discover_hives
        from parsers.registry import parse_hive

        hives = discover_hives(dir_path)
        if not hives:
            return {"ok": False, "error": f"no registry hives found under {dir_path!r}"}

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

        return {
            "collection_id": collection_id,
            "host_id": host_id,
            "dir_path": dir_path,
            "event_count": total,
            "by_event_type": store.counts_by_event_type(collection_id=collection_id),
            "by_source_artifact": store.counts_by_source_artifact(collection_id=collection_id),
            "hives": per_hive,
        }

    return handler


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
    return dispatcher


def main() -> None:
    serve_stdio(build_dispatcher())


if __name__ == "__main__":
    main()

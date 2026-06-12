"""Sidecar entry point: starts the IPC dispatcher and serves over stdio.

Run with: ``python -m core``
"""

from __future__ import annotations

import sys
from typing import Any

from core import SCHEMA_VERSION, __version__
from core.ipc import Dispatcher, serve_stdio
from core.store import EventStore


def _ping(_request: dict[str, Any]) -> dict[str, Any]:
    return {
        "sidecar_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
    }


def _make_run_triage_system_hive(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        hive_path = request.get("hive_path")
        if not isinstance(hive_path, str) or not hive_path:
            return {"ok": False, "error": "missing 'hive_path' string"}

        # Imports are deferred so a malformed regipy install doesn't kill the
        # sidecar at startup; the error surfaces here, on the actual op.
        from collectors.windows.hive import collect_hive
        from parsers.registry_system import parse_system_hive

        bundle = collect_hive(hive_path, kind="system")
        artifact = bundle.artifacts[0]
        events = parse_system_hive(
            artifact.source_path,
            collection_id=bundle.collection_id,
            host_id_hint=bundle.host_id,
        )

        host_id_from_events = next(
            (e.host_id for e in events if e.source_artifact == "registry.system" and e.event_type == "system_config_change" and e.host_id != bundle.host_id),
            bundle.host_id,
        )
        store.register_collection(
            collection_id=bundle.collection_id,
            host_id=host_id_from_events,
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
            "host_id": host_id_from_events,
            "source_path": artifact.source_path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "event_count": inserted,
            "by_event_type": by_type,
        }

    return handler


def _make_query_events(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        events = store.query_events(
            collection_id=request.get("collection_id"),
            event_type=request.get("event_type"),
            source_artifact=request.get("source_artifact"),
            summary_contains=request.get("summary_contains"),
            sort_by=request.get("sort_by", "timestamp"),
            sort_dir=request.get("sort_dir", "asc"),
            limit=int(request.get("limit", 500)),
            offset=int(request.get("offset", 0)),
        )
        return {
            "events": events,
            "total": store.count_events(collection_id=request.get("collection_id")),
        }

    return handler


def build_dispatcher(store: EventStore | None = None) -> Dispatcher:
    store = store or EventStore()
    dispatcher = Dispatcher()
    dispatcher.register("ping", _ping)
    dispatcher.register("run_triage_system_hive", _make_run_triage_system_hive(store))
    dispatcher.register("query_events", _make_query_events(store))
    return dispatcher


def main() -> None:
    serve_stdio(build_dispatcher())


if __name__ == "__main__":
    main()

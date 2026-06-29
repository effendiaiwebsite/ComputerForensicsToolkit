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

from pathlib import Path

from core import SCHEMA_VERSION, __version__
from core.events import Event
from core.ipc import Dispatcher, serve_stdio
from core.rules import Rule, evaluate_rules as _eval_rules, load_rules_from_dir
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
        browser_kind_hint = request.get("browser_kind")
        collection_id = request.get("collection_id")
        host_id_hint = request.get("host_id_hint") or socket.gethostname()

        new_collection = collection_id is None
        collection_id = collection_id or _new_collection_id()

        # Same op handles registry hives, .evtx, .pf, .lnk, JumpLists, browser History.
        lower = hive_path.lower()
        basename_lower = Path(hive_path).name.lower()
        from collectors.windows.browser import detect_browser_kind as _detect_browser

        is_browser_history = (
            browser_kind_hint is not None
            or (basename_lower == "history" and _detect_browser(hive_path) != "unknown")
        )

        if is_browser_history:
            from collectors.windows.browser import collect_browser_history
            from parsers.browser import parse_browser_history

            artifact = collect_browser_history(
                hive_path,
                host_id=host_id_hint,
                browser_kind=browser_kind_hint,
            )
            events = parse_browser_history(
                artifact.source_path,
                collection_id=collection_id,
                host_id_hint=host_id_hint,
                user_hint=user_hint,
                browser_kind=artifact.browser_kind,
            )
            host_id = host_id_hint
            note = f"browser_history ({artifact.browser_kind}): {artifact.source_path}"
            kind_out = f"{artifact.browser_kind}.history"
        elif lower.endswith(".evtx"):
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
        elif lower.endswith(".lnk"):
            from collectors.windows.lnk import collect_lnk
            from parsers.lnk import parse_lnk

            artifact = collect_lnk(hive_path, host_id=host_id_hint)
            events = parse_lnk(
                artifact.source_path,
                collection_id=collection_id,
                host_id_hint=host_id_hint,
                user_hint=user_hint,
            )
            host_id = host_id_hint
            note = f"lnk: {artifact.source_path}"
            kind_out = "lnk"
        elif lower.endswith(".automaticdestinations-ms"):
            from collectors.windows.jumplist import collect_jumplist
            from parsers.jumplist import parse_jumplist

            artifact = collect_jumplist(hive_path, host_id=host_id_hint)
            events = parse_jumplist(
                artifact.source_path,
                collection_id=collection_id,
                host_id_hint=host_id_hint,
                user_hint=user_hint,
            )
            host_id = host_id_hint
            note = f"jumplist: {artifact.source_path}"
            kind_out = "jumplist"
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

        from collectors.windows.browser import collect_browser_history
        from collectors.windows.evtx import collect_evtx
        from collectors.windows.hive import collect_hive
        from collectors.windows.jumplist import collect_jumplist
        from collectors.windows.lnk import collect_lnk
        from collectors.windows.prefetch import collect_prefetch
        from collectors.windows.user_hives import (
            discover_browser_histories,
            discover_evtx_files,
            discover_hives,
            discover_jumplist_files,
            discover_lnk_files,
            discover_prefetch_files,
        )
        from parsers.browser import parse_browser_history
        from parsers.evtx import parse_evtx
        from parsers.jumplist import parse_jumplist
        from parsers.lnk import parse_lnk
        from parsers.prefetch import parse_prefetch
        from parsers.registry import parse_hive

        hives = discover_hives(dir_path)
        evtx_files = discover_evtx_files(dir_path)
        prefetch_files = discover_prefetch_files(dir_path)
        lnk_files = discover_lnk_files(dir_path)
        jumplist_files = discover_jumplist_files(dir_path)
        browser_files = discover_browser_histories(dir_path)
        if not (
            hives or evtx_files or prefetch_files
            or lnk_files or jumplist_files or browser_files
        ):
            return {
                "ok": False,
                "error": (
                    f"no registry hives, .evtx, .pf, .lnk, JumpList, or browser "
                    f"History files found under {dir_path!r}"
                ),
            }

        # Allow callers (live collection worker) to pass an existing
        # collection_id so all events land under one ID instead of a fresh
        # one — keeps the UI's progress poller pointing at the right record.
        provided_cid = request.get("collection_id")
        collection_id = provided_cid if isinstance(provided_cid, str) and provided_cid else _new_collection_id()
        if not provided_cid:
            store.register_collection(
                collection_id=collection_id,
                host_id=host_id_hint,
                host_os="windows",
                created_at=_utc_now_iso(),
                note=f"directory triage: {dir_path}",
                source_path=dir_path,
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

        for lk in lnk_files:
            try:
                artifact = collect_lnk(lk.path, host_id=host_id)
                events = parse_lnk(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id,
                    user_hint=lk.user_hint,
                )
                inserted = store.insert_events(events)
                total += inserted
                per_hive.append({
                    "kind": "lnk",
                    "path": str(lk.path),
                    "user_hint": lk.user_hint,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "event_count": inserted,
                })
            except Exception as exc:
                log.exception("parse failed for %s", lk.path)
                per_hive.append({
                    "kind": "lnk",
                    "path": str(lk.path),
                    "user_hint": lk.user_hint,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        for jl in jumplist_files:
            try:
                artifact = collect_jumplist(jl.path, host_id=host_id)
                events = parse_jumplist(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id,
                    user_hint=jl.user_hint,
                )
                inserted = store.insert_events(events)
                total += inserted
                per_hive.append({
                    "kind": "jumplist",
                    "path": str(jl.path),
                    "user_hint": jl.user_hint,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "event_count": inserted,
                })
            except Exception as exc:
                log.exception("parse failed for %s", jl.path)
                per_hive.append({
                    "kind": "jumplist",
                    "path": str(jl.path),
                    "user_hint": jl.user_hint,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        for bh in browser_files:
            try:
                artifact = collect_browser_history(
                    bh.path,
                    host_id=host_id,
                    browser_kind=bh.browser_kind,
                )
                events = parse_browser_history(
                    artifact.source_path,
                    collection_id=collection_id,
                    host_id_hint=host_id,
                    user_hint=bh.user_hint,
                    browser_kind=artifact.browser_kind,
                )
                inserted = store.insert_events(events)
                total += inserted
                per_hive.append({
                    "kind": f"{artifact.browser_kind}.history",
                    "path": str(bh.path),
                    "user_hint": bh.user_hint,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "event_count": inserted,
                })
            except Exception as exc:
                log.exception("parse failed for %s", bh.path)
                per_hive.append({
                    "kind": f"{bh.browser_kind}.history",
                    "path": str(bh.path),
                    "user_hint": bh.user_hint,
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


def _make_query_usb_devices(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        rows = store.query_usb_devices(
            collection_id=request.get("collection_id"),
            limit=int(request.get("limit", 1000)),
        )
        return {"devices": rows, "total": len(rows)}

    return handler


def _make_query_browser_domains(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        rows = store.query_browser_domains(
            collection_id=request.get("collection_id"),
            limit=int(request.get("limit", 1000)),
        )
        return {"domains": rows, "total": len(rows)}

    return handler


def _make_generate_report(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        from hashlib import sha256

        from core.report import generate_report

        collection_id = request.get("collection_id")
        output_path = request.get("output_path")
        case_name = request.get("case_name") or "Untitled case"
        examiner = request.get("examiner") or "—"
        if not isinstance(collection_id, str) or not collection_id:
            return {"ok": False, "error": "missing 'collection_id' string"}
        if not isinstance(output_path, str) or not output_path:
            return {"ok": False, "error": "missing 'output_path' string"}

        try:
            html_text = generate_report(
                store,
                collection_id,
                case_name=case_name,
                examiner=examiner,
            )
        except Exception as exc:
            log.exception("report generation failed for %s", collection_id)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        data = html_text.encode("utf-8")
        out.write_bytes(data)
        return {
            "collection_id": collection_id,
            "output_path": str(out),
            "size_bytes": len(data),
            "sha256": sha256(data).hexdigest(),
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


def _default_rules_dir() -> Path:
    """Find the rules dir for both source-tree and PyInstaller-bundled runs.

    Resolution order:
      1. ``DFT_RULES_DIR`` env var (deployment override)
      2. PyInstaller one-folder: ``<bundle>/rules`` next to the EXE
      3. PyInstaller one-file: ``sys._MEIPASS/rules``
      4. Source tree: ``<repo>/rules`` (parent of this file's package)
    """
    import os

    env = os.environ.get("DFT_RULES_DIR")
    if env:
        return Path(env)
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            bundled = Path(meipass) / "rules"
            if bundled.exists():
                return bundled
        sibling = Path(sys.executable).resolve().parent / "rules"
        if sibling.exists():
            return sibling
    return Path(__file__).resolve().parent.parent / "rules"


def _make_evaluate_rules(store: EventStore, rules_dir: Path):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        collection_id = request.get("collection_id")
        if not isinstance(collection_id, str) or not collection_id:
            return {"ok": False, "error": "missing 'collection_id' string"}

        try:
            rules: list[Rule] = load_rules_from_dir(rules_dir)
        except Exception as exc:
            return {"ok": False, "error": f"rule load failed: {exc}"}

        events_iter = store.query_events(collection_id=collection_id, limit=10_000_000)
        store.clear_findings(collection_id=collection_id)
        findings = _eval_rules(rules, events_iter, collection_id=collection_id)
        inserted = store.insert_findings(findings)

        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        return {
            "collection_id": collection_id,
            "rules_loaded": len(rules),
            "findings_count": inserted,
            "by_severity": by_severity,
            "by_rule": by_rule,
        }

    return handler


def _make_query_findings(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        rows = store.query_findings(
            collection_id=request.get("collection_id"),
            severities=request.get("severities"),
            tactic=request.get("tactic"),
            examiner_status=request.get("examiner_status"),
            limit=int(request.get("limit", 1000)),
            offset=int(request.get("offset", 0)),
        )
        return {
            "findings": rows,
            "total": store.count_findings(collection_id=request.get("collection_id")),
            "by_severity": store.counts_by_severity(collection_id=request.get("collection_id")),
        }

    return handler


def _make_enumerate_drives():
    def handler(_request: dict[str, Any]) -> dict[str, Any]:
        from collectors.windows.live_disk import enumerate_physical_drives

        drives = enumerate_physical_drives()
        return {
            "drives": [
                {
                    "device": d.device,
                    "model": d.model,
                    "size_bytes": d.size_bytes,
                    "serial": d.serial,
                }
                for d in drives
            ],
        }

    return handler


def _make_export_events(store: EventStore):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        import csv
        import json as _json

        output_path = request.get("output_path")
        fmt = (request.get("format") or "csv").lower()
        if not isinstance(output_path, str) or not output_path:
            return {"ok": False, "error": "missing 'output_path' string"}
        if fmt not in ("csv", "ndjson"):
            return {"ok": False, "error": "format must be 'csv' or 'ndjson'"}

        rows = store.query_events(
            collection_id=request.get("collection_id"),
            event_type=request.get("event_type"),
            event_types=request.get("event_types"),
            source_artifact=request.get("source_artifact"),
            source_artifacts=request.get("source_artifacts"),
            summary_contains=request.get("summary_contains"),
            sort_by=request.get("sort_by", "timestamp"),
            sort_dir=request.get("sort_dir", "asc"),
            limit=int(request.get("limit", 1_000_000)),
            offset=int(request.get("offset", 0)),
        )
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "csv":
            cols = [
                "event_id", "timestamp", "timestamp_source", "host_id", "user",
                "source_artifact", "source_path", "event_type", "summary",
                "evidence_json", "parser_version",
            ]
            with out.open("w", encoding="utf-8", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(cols)
                for r in rows:
                    w.writerow([
                        r.get("event_id"),
                        r.get("timestamp"),
                        r.get("timestamp_source"),
                        r.get("host_id"),
                        r.get("user"),
                        r.get("source_artifact"),
                        r.get("source_path"),
                        r.get("event_type"),
                        r.get("summary"),
                        _json.dumps(r.get("evidence", {}), separators=(",", ":"), default=str),
                        r.get("parser_version"),
                    ])
        else:  # ndjson
            with out.open("w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(_json.dumps(r, separators=(",", ":"), default=str))
                    fh.write("\n")
        return {
            "output_path": str(out),
            "format": fmt,
            "rows": len(rows),
            "size_bytes": out.stat().st_size,
        }

    return handler


def _make_export_hash_report():
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        from core.audit import generate_hash_report

        audit_path = request.get("audit_path")
        output_path = request.get("output_path")
        fmt = (request.get("format") or "txt").lower()
        if not isinstance(audit_path, str) or not audit_path:
            return {"ok": False, "error": "missing 'audit_path' string"}
        if not isinstance(output_path, str) or not output_path:
            return {"ok": False, "error": "missing 'output_path' string"}
        if fmt not in ("txt", "csv"):
            return {"ok": False, "error": "format must be 'txt' or 'csv'"}
        try:
            rows, total_bytes = generate_hash_report(audit_path, output_path, format=fmt)
        except FileNotFoundError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            log.exception("hash report failed")
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return {
            "audit_path": audit_path,
            "output_path": output_path,
            "format": fmt,
            "rows": rows,
            "size_bytes": total_bytes,
        }

    return handler


def _make_export_folder(store: EventStore, browser, progress):
    import threading
    from pathlib import Path as _Path

    def handler(request: dict[str, Any]) -> dict[str, Any]:
        cid = request.get("collection_id")
        src_path = request.get("src_path") or "/"
        dest_dir = request.get("dest_dir")
        if not isinstance(cid, str) or not cid:
            return {"ok": False, "error": "missing 'collection_id' string"}
        if not isinstance(dest_dir, str) or not dest_dir:
            return {"ok": False, "error": "missing 'dest_dir' string"}
        coll = store.get_collection(cid)
        if coll is None:
            return {"ok": False, "error": "unknown collection_id"}
        source_path = coll.get("source_path") or ""
        if not source_path:
            return {
                "ok": False,
                "error": "collection has no source_path; re-ingest to populate it",
            }

        # Separate progress key per export so it doesn't collide with the
        # parent collection's own progress snapshot.
        progress_key = f"export-{uuid.uuid4()}"
        progress.start(
            progress_key,
            label=f"exporting {src_path} → {dest_dir}",
            total=0,
        )

        def _worker() -> None:
            from core.audit import AuditLog
            from core.image_browser import export_folder

            dest_root = _Path(dest_dir).resolve()
            audit = AuditLog(dest_root / "audit.jsonl")
            try:
                export_folder(
                    browser,
                    collection_id=cid,
                    src_path=src_path,
                    dest_dir=dest_root,
                    source_path=source_path,
                    audit=audit,
                    progress=progress,
                    progress_key=progress_key,
                )
                progress.finish(progress_key)
            except Exception as exc:
                logger = logging.getLogger(__name__)
                logger.exception("folder export failed")
                audit.error("export_folder", src_path, exc)
                progress.finish(progress_key, error=f"{type(exc).__name__}: {exc}")

        threading.Thread(target=_worker, name=f"export-{progress_key}", daemon=True).start()
        return {
            "progress_key": progress_key,
            "collection_id": cid,
            "src_path": src_path,
            "dest_dir": dest_dir,
            "phase": "running",
        }

    return handler


def _make_list_dir(store: EventStore, browser):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        cid = request.get("collection_id")
        path = request.get("path") or "/"
        if not isinstance(cid, str) or not cid:
            return {"ok": False, "error": "missing 'collection_id' string"}
        coll = store.get_collection(cid)
        if coll is None:
            return {"ok": False, "error": "unknown collection_id"}
        src = coll.get("source_path") or ""
        if not src:
            return {
                "ok": False,
                "error": (
                    "collection has no source_path on record. Re-ingest with the "
                    "current build to populate it."
                ),
            }
        try:
            result = browser.list_dir(collection_id=cid, path=path, source_path=src)
        except FileNotFoundError as exc:
            return {"ok": False, "error": str(exc)}
        except PermissionError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            log.exception("list_dir failed for %s @ %s", cid, path)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return {
            "path": result.path,
            "parent": result.parent,
            "source_kind": result.source_kind,
            "source_path": result.source_path,
            "entries": [e.to_dict() for e in result.entries],
        }

    return handler


def _make_get_progress(progress):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        cid = request.get("collection_id")
        if not isinstance(cid, str) or not cid:
            return {"ok": False, "error": "missing 'collection_id' string"}
        snap = progress.get(cid)
        if snap is None:
            return {"ok": False, "error": "unknown collection_id"}
        return {"progress": snap.to_dict()}

    return handler


def _make_run_live_collection(store: EventStore, progress, rules_dir: Path):
    import threading
    from pathlib import Path as _Path

    def handler(request: dict[str, Any]) -> dict[str, Any]:
        drive = request.get("source")
        dest_dir = request.get("dest_dir")
        if not isinstance(drive, str) or not drive:
            return {"ok": False, "error": "missing 'source' (drive or image path)"}
        if not isinstance(dest_dir, str) or not dest_dir:
            return {"ok": False, "error": "missing 'dest_dir'"}

        collection_id = _new_collection_id()
        progress.start(
            collection_id,
            label=f"live collection from {drive}",
            total=0,
        )

        def _worker() -> None:
            from collectors.windows.live_disk import (
                NoWindowsVolumeError,
                collect_live,
                open_target,
            )
            from core.audit import AuditLog

            dest_root = _Path(dest_dir).resolve()
            audit = AuditLog(dest_root / "audit.jsonl")
            try:
                target = open_target(drive)
                collect_live(
                    target,
                    collection_id=collection_id,
                    dest_dir=dest_root,
                    audit=audit,
                    progress=progress,
                    source_label=drive,
                )
                # Auto-chain ingestion + rule eval so the UI lands on a live collection.
                progress.update(collection_id, current_item="ingesting collected artifacts…")
                store.register_collection(
                    collection_id=collection_id,
                    host_id=socket.gethostname(),
                    host_os="windows",
                    created_at=_utc_now_iso(),
                    note=f"live: {drive} → {dest_root}",
                    source_path=drive,
                )
                # Reuse the existing directory-triage dispatcher so we don't duplicate logic.
                # Pass our collection_id so all events land under the same ID the UI is polling.
                tri = _make_run_triage_directory(store)({
                    "dir_path": str(dest_root),
                    "host_id_hint": socket.gethostname(),
                    "collection_id": collection_id,
                })
                if tri.get("ok") is not False:
                    eval_handler = _make_evaluate_rules(store, rules_dir)
                    eval_handler({"collection_id": collection_id})
                    progress.update(
                        collection_id,
                        current_item=f"done — ingested {tri.get('event_count', 0)} events",
                    )
                progress.finish(collection_id)
            except NoWindowsVolumeError as exc:
                audit.error("collect_live", drive, exc)
                progress.finish(collection_id, error=str(exc))
            except Exception as exc:
                logger = logging.getLogger(__name__)
                logger.exception("live collection failed")
                audit.error("collect_live", drive, exc)
                progress.finish(collection_id, error=f"{type(exc).__name__}: {exc}")

        threading.Thread(target=_worker, name=f"live-{collection_id}", daemon=True).start()
        return {
            "collection_id": collection_id,
            "source": drive,
            "dest_dir": dest_dir,
            "phase": "running",
        }

    return handler


def build_dispatcher(
    store: EventStore | None = None,
    *,
    rules_dir: Path | None = None,
    progress=None,
    browser=None,
) -> Dispatcher:
    from core.image_browser import ImageBrowser
    from core.progress import ProgressTracker

    store = store or EventStore()
    rules_dir = rules_dir or _default_rules_dir()
    progress = progress or ProgressTracker()
    browser = browser or ImageBrowser()
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
    dispatcher.register("evaluate_rules", _make_evaluate_rules(store, rules_dir))
    dispatcher.register("query_findings", _make_query_findings(store))
    dispatcher.register("query_usb_devices", _make_query_usb_devices(store))
    dispatcher.register(
        "query_program_execution_composite",
        _make_query_program_execution_composite(store),
    )
    dispatcher.register("query_browser_domains", _make_query_browser_domains(store))
    dispatcher.register("generate_report", _make_generate_report(store))
    dispatcher.register("enumerate_drives", _make_enumerate_drives())
    dispatcher.register("get_progress", _make_get_progress(progress))
    dispatcher.register(
        "run_live_collection",
        _make_run_live_collection(store, progress, rules_dir),
    )
    dispatcher.register("list_dir", _make_list_dir(store, browser))
    dispatcher.register("export_folder", _make_export_folder(store, browser, progress))
    dispatcher.register("export_hash_report", _make_export_hash_report())
    dispatcher.register("export_events", _make_export_events(store))
    return dispatcher


def main() -> None:
    # Force UTF-8 on the IPC channel so non-ASCII (em-dashes, Unicode names,
    # paths with accented chars) survives the round trip from the Tauri shell
    # — Windows defaults sys.stdin/out to cp1252, which silently mojibakes
    # JSON payloads from the Rust side that are already UTF-8 bytes.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass
    serve_stdio(build_dispatcher())


if __name__ == "__main__":
    main()

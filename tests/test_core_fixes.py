"""Regression tests for the review-findings fixes in ``core/``.

One test (or a small group) per finding, in the order of the review list, so a
future regression points straight at the behaviour it broke.
"""

from __future__ import annotations

import csv
import io
import threading
import time
import warnings
from pathlib import Path
from typing import Any

import pytest

import core.store
from core.__main__ import build_dispatcher
from core.audit import AuditLog
from core.events import make_event
from core.image_browser import (
    ImageBrowser,
    _hash_copy_local,
    export_dest_error,
    export_folder,
)
from core.progress import ProgressTracker
from core.rules import _apply_op, load_rule_file, load_rules_from_dir_with_errors
from core.store import EventStore

_RULE_YML = (
    "id: test-rule-001\ntitle: Test rule\nseverity: low\n"
    "mitre:\n  techniques: [T1]\nmatch:\n  event_type: program_execution\n"
)


def _ev(**overrides: Any):
    base: dict[str, Any] = dict(
        host_os="windows", host_id="H", source_artifact="prefetch", source_path="p",
        event_type="program_execution", summary="run", evidence={}, collection_id="c",
        parser_version="v",
    )
    base.update(overrides)
    return make_event(**base)


def _wait_finished(progress: ProgressTracker, key: str, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snap = progress.get(key)
        if snap is not None and snap.phase != "running":
            return snap
        time.sleep(0.02)
    raise AssertionError(f"progress {key} never finished")


# --- A: export destination must never be the source ----------------------------


def test_export_folder_refuses_dest_equal_to_or_inside_source(tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    src_root.mkdir()
    (src_root / "a.txt").write_bytes(b"keep me")

    assert export_dest_error(src_root, str(src_root))
    assert export_dest_error(src_root / "sub", str(src_root))
    assert export_dest_error(tmp_path / "elsewhere", str(src_root)) is None

    for dest in (src_root, src_root / "nested"):
        with pytest.raises(ValueError, match="collection source"):
            export_folder(
                ImageBrowser(), collection_id="c", src_path="/", dest_dir=dest,
                source_path=str(src_root), audit=AuditLog(tmp_path / "audit.jsonl"),
                progress=ProgressTracker(), progress_key="k",
            )
    assert (src_root / "a.txt").read_bytes() == b"keep me"


def test_export_folder_op_rejects_dest_inside_source_synchronously(tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    src_root.mkdir()
    (src_root / "a.txt").write_bytes(b"keep me")
    store = EventStore()
    store.register_collection(
        collection_id="c", host_id="H", host_os="windows",
        created_at="2026-01-01T00:00:00Z", source_path=str(src_root),
    )
    d = build_dispatcher(store)
    r = d.dispatch({"op": "export_folder", "collection_id": "c", "dest_dir": str(src_root)})
    assert r["ok"] is False
    assert "collection source" in r["error"]
    assert (src_root / "a.txt").read_bytes() == b"keep me"


def test_hash_copy_local_refuses_same_file(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_bytes(b"keep me")
    with pytest.raises(ValueError, match="onto itself"):
        _hash_copy_local(f, f)
    assert f.read_bytes() == b"keep me"


# --- B: schema string compiles without SyntaxWarning ---------------------------


def test_store_module_has_no_invalid_escape_warning() -> None:
    source = Path(core.store.__file__).read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(source, core.store.__file__, "exec")
    assert "PhysicalDriveN" in core.store._SCHEMA


# --- 1: live collection surfaces ingestion failure -------------------------------


def test_live_collection_reports_failed_ingestion(tmp_path: Path, monkeypatch) -> None:
    import collectors.windows.live_disk as live_disk

    monkeypatch.setattr(live_disk, "open_target", lambda drive: object())
    monkeypatch.setattr(live_disk, "collect_live", lambda *a, **kw: None)

    progress = ProgressTracker()
    d = build_dispatcher(EventStore(), progress=progress)
    r = d.dispatch({
        "op": "run_live_collection", "source": "fake-drive", "dest_dir": str(tmp_path / "out"),
    })
    assert r["ok"] is True
    snap = _wait_finished(progress, r["collection_id"])
    assert snap.phase == "error"
    assert "ingestion failed" in (snap.error or "")
    records = AuditLog(tmp_path / "out" / "audit.jsonl").read_all()
    assert any(rec["action"] == "ingest" and rec["status"] == "error" for rec in records)


# --- 2: discovered host name is written back to the collection row -------------


def test_directory_triage_writes_discovered_host_back(tmp_path: Path, monkeypatch) -> None:
    import parsers.registry as registry

    (tmp_path / "SYSTEM").write_bytes(b"\x00")

    def fake_parse_hive(path, *, collection_id, host_id_hint, kind=None, user_hint=None):
        return "system", [
            make_event(
                host_os="windows", host_id=host_id_hint, source_artifact="registry.system",
                source_path=str(path), event_type="system_config_change",
                summary="ComputerName", evidence={"computer_name": "SUSPECT-PC"},
                collection_id=collection_id, parser_version="v",
            )
        ]

    monkeypatch.setattr(registry, "parse_hive", fake_parse_hive)
    store = EventStore()
    d = build_dispatcher(store)
    r = d.dispatch({
        "op": "run_triage_directory", "dir_path": str(tmp_path), "host_id_hint": "EXAMINER-BOX",
    })
    assert r["ok"] is True
    assert r["host_id"] == "SUSPECT-PC"
    assert store.get_collection(r["collection_id"])["host_id"] == "SUSPECT-PC"

    store.register_collection(
        collection_id="pre", host_id="EXAMINER-BOX", host_os="windows",
        created_at="2026-01-01T00:00:00Z",
    )
    r2 = d.dispatch({
        "op": "run_triage_directory", "dir_path": str(tmp_path),
        "host_id_hint": "EXAMINER-BOX", "collection_id": "pre",
    })
    assert r2["ok"] is True
    assert store.get_collection("pre")["host_id"] == "SUSPECT-PC"


# --- 3: rule loading failures are visible ----------------------------------------


def test_evaluate_rules_fails_when_rules_dir_missing(tmp_path: Path) -> None:
    store = EventStore()
    store.insert_events([_ev()])
    d = build_dispatcher(store, rules_dir=tmp_path / "nope")
    r = d.dispatch({"op": "evaluate_rules", "collection_id": "c"})
    assert r["ok"] is False
    assert "rules directory not found" in r["error"]


def test_evaluate_rules_reports_unparseable_rule_files(tmp_path: Path) -> None:
    (tmp_path / "good.yml").write_text(_RULE_YML, encoding="utf-8")
    (tmp_path / "bad.yml").write_text("id: broken\ntitle: x\n", encoding="utf-8")
    rules, failed = load_rules_from_dir_with_errors(tmp_path)
    assert [r.id for r in rules] == ["test-rule-001"]
    assert list(failed) == [str(tmp_path / "bad.yml")]

    store = EventStore()
    store.insert_events([_ev()])
    d = build_dispatcher(store, rules_dir=tmp_path)
    r = d.dispatch({"op": "evaluate_rules", "collection_id": "c"})
    assert r["ok"] is True
    assert r["rules_loaded"] == 1
    assert r["rules_failed"]["count"] == 1
    assert r["rules_failed"]["names"] == ["bad.yml"]
    assert r["findings_count"] == 1


# --- 4: hash report needs an existing audit log ----------------------------------


def test_export_hash_report_missing_audit_is_an_error(tmp_path: Path) -> None:
    d = build_dispatcher(EventStore())
    r = d.dispatch({
        "op": "export_hash_report", "audit_path": str(tmp_path / "missing.jsonl"),
        "output_path": str(tmp_path / "out.txt"),
    })
    assert r["ok"] is False
    assert "audit log not found" in r["error"]
    assert not (tmp_path / "out.txt").exists()


# --- 5: an aborted image walk is a partial export, and says so ----------------


class _FakeFile:
    def __init__(self, name: str, data: bytes) -> None:
        self.name = name
        self._data = data

    def is_file(self) -> bool:
        return True

    def open(self, mode: str = "rb") -> io.BytesIO:
        return io.BytesIO(self._data)

    def relative_to(self, root: Any) -> str:
        return self.name

    def __str__(self) -> str:
        return f"/export/{self.name}"


class _FakeNode:
    def __init__(self, files: list[_FakeFile], fail_after: int | None = None) -> None:
        self._files = files
        self._fail_after = fail_after

    def exists(self) -> bool:
        return True

    def is_dir(self) -> bool:
        return True

    def rglob(self, pattern: str):
        for i, f in enumerate(self._files):
            if self._fail_after is not None and i == self._fail_after:
                raise OSError("bad sector")
            yield f


class _FakeRoot:
    def __init__(self, node: _FakeNode) -> None:
        self._node = node

    def path(self, p: str) -> _FakeNode:
        return self._node


def _image_browser(node: _FakeNode) -> ImageBrowser:
    browser = ImageBrowser()
    browser._roots["c"] = _FakeRoot(node)
    return browser


def test_image_export_records_walk_abort(tmp_path: Path) -> None:
    image = tmp_path / "disk.E01"
    image.write_bytes(b"\x00")
    node = _FakeNode([_FakeFile("a.txt", b"aaa"), _FakeFile("b.txt", b"bbb")], fail_after=1)
    dest = tmp_path / "dest"
    audit = AuditLog(dest / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("k", label="t")

    result = export_folder(
        _image_browser(node), collection_id="c", src_path="/export", dest_dir=dest,
        source_path=str(image), audit=audit, progress=progress, progress_key="k",
    )
    assert result.files_copied == 1
    assert result.errors == 1
    assert result.walk_error and "bad sector" in result.walk_error
    walk_records = [r for r in audit.read_all() if r["action"] == "export_walk"]
    assert len(walk_records) == 1 and walk_records[0]["status"] == "error"
    assert progress.get("k").errors == 1


def test_export_folder_op_finishes_with_error_on_walk_abort(tmp_path: Path) -> None:
    image = tmp_path / "disk.E01"
    image.write_bytes(b"\x00")
    node = _FakeNode([_FakeFile("a.txt", b"aaa")], fail_after=0)
    store = EventStore()
    store.register_collection(
        collection_id="c", host_id="H", host_os="windows",
        created_at="2026-01-01T00:00:00Z", source_path=str(image),
    )
    progress = ProgressTracker()
    d = build_dispatcher(store, progress=progress, browser=_image_browser(node))
    r = d.dispatch({
        "op": "export_folder", "collection_id": "c", "src_path": "/export",
        "dest_dir": str(tmp_path / "dest"),
    })
    assert r["ok"] is True
    snap = _wait_finished(progress, r["progress_key"])
    assert snap.phase == "error"
    assert "source walk aborted" in snap.error
    assert snap.errors == 1


# --- 6: close_all closes cached targets ------------------------------------------


def test_close_all_closes_targets_even_when_one_raises() -> None:
    closed: list[str] = []

    class _Target:
        def __init__(self, name: str, fail: bool = False) -> None:
            self.name, self.fail = name, fail

        def close(self) -> None:
            if self.fail:
                raise RuntimeError("already closed")
            closed.append(self.name)

    browser = ImageBrowser()
    browser._targets = {"a": _Target("a", fail=True), "b": _Target("b")}
    browser._roots = {"a": object(), "b": object()}
    browser.close_all()
    assert closed == ["b"]
    assert browser._targets == {} and browser._roots == {}


# --- 7: descending sort keeps undated events at the bottom ------------------------


def test_query_sort_desc_puts_nulls_last() -> None:
    store = EventStore()
    store.insert_events([
        _ev(timestamp=None, summary="null"),
        _ev(timestamp="2026-06-10T00:00:00Z", summary="a"),
        _ev(timestamp="2026-06-11T00:00:00Z", summary="b"),
    ])
    rows = store.query_events(sort_by="timestamp", sort_dir="desc", limit=2)
    assert [r["summary"] for r in rows] == ["b", "a"]


# --- 8 + 9: report totals and the per-day caption --------------------------------


def test_report_findings_total_uses_store_count() -> None:
    from core.report import generate_report
    from core.rules import Finding

    store = EventStore()
    store.register_collection(
        collection_id="c", host_id="H", host_os="windows", created_at="2026-01-01T00:00:00Z",
    )
    store.insert_findings([
        Finding(
            finding_id=f"f{i}", rule_id="r", rule_title="R", severity="low",
            mitre_techniques=("T1",), mitre_tactics=("execution",),
            evidence_event_ids=(f"e{i}",), collection_id="c",
            created_at="2026-01-01T00:00:00Z", summary="s",
        )
        for i in range(10_001)
    ])
    html = generate_report(store, "c", case_name="x", examiner="y")
    assert '<div class="big">10,001</div>' in html


def test_report_per_day_caption_matches_sample_cap() -> None:
    from core.report import _DAY_SAMPLE_MAX, _render_per_day

    store = EventStore()
    store.insert_events(
        [_ev(timestamp="2026-06-10T00:00:00Z") for _ in range(50)]
        + [_ev(timestamp=f"2026-06-{d:02d}T00:00:00Z") for d in range(11, 20)]
    )
    html = _render_per_day(store, "c")
    assert "busy" in html
    assert f"Up to {_DAY_SAMPLE_MAX} notable events" in html
    assert "Up to 15 notable" not in html


# --- 10: LIKE wildcards in summary_contains are literal --------------------------


def test_summary_contains_treats_like_wildcards_literally() -> None:
    store = EventStore()
    store.insert_events([
        _ev(summary="100% done", timestamp="2026-06-10T00:00:00Z"),
        _ev(summary="100x done", timestamp="2026-06-10T00:00:00Z"),
        _ev(summary="a_b", timestamp=None),
        _ev(summary="axb", timestamp=None),
        _ev(summary=r"c:\temp", timestamp=None),
    ])
    assert [r["summary"] for r in store.query_events(summary_contains="100%")] == ["100% done"]
    assert [r["summary"] for r in store.query_events(summary_contains="a_b")] == ["a_b"]
    assert [r["summary"] for r in store.query_events(summary_contains="c:\\t")] == [r"c:\temp"]
    assert len(store.query_timeline_points(summary_contains="100%")) == 1
    assert store.count_undated_events(summary_contains="a_b") == 1


# --- 11: unserialized USB devices do not merge --------------------------------------


def test_usb_devices_without_serial_stay_separate() -> None:
    def usb(key_path: str, product: str):
        return _ev(
            source_artifact="registry.system", event_type="usb_connection",
            summary=product, timestamp="2026-06-10T00:00:00Z",
            evidence={"vendor": "V", "product": product, "serial": None, "key_path": key_path},
        )

    store = EventStore()
    store.insert_events([usb("USBSTOR\\A\\1", "Disk A"), usb("USBSTOR\\B\\1", "Disk B")])
    rows = store.query_usb_devices()
    assert sorted(r["product"] for r in rows) == ["Disk A", "Disk B"]
    assert all(r["serial"] is None and r["event_count"] == 1 for r in rows)


# --- 12 + 13: rule validation ----------------------------------------------------


def test_scalar_technique_is_wrapped_not_split(tmp_path: Path) -> None:
    yml = tmp_path / "r.yml"
    yml.write_text(
        "id: x\ntitle: x\nseverity: low\nmitre:\n  techniques: T1547.001\n"
        "  tactics: persistence\nmatch:\n  event_type: x\n",
        encoding="utf-8",
    )
    rule = load_rule_file(yml)
    assert rule.techniques == ("T1547.001",)
    assert rule.tactics == ("persistence",)

    yml.write_text(
        "id: x\ntitle: x\nseverity: low\nmitre:\n  techniques: [1547]\nmatch:\n  event_type: x\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="techniques entries must be non-empty strings"):
        load_rule_file(yml)


def test_numeric_operators_require_numeric_argument(tmp_path: Path) -> None:
    yml = tmp_path / "r.yml"
    yml.write_text(
        "id: x\ntitle: x\nseverity: low\nmitre:\n  techniques: [T1]\n"
        "match:\n  any_of:\n    - evidence.size: {gt: big}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="needs a numeric argument"):
        load_rule_file(yml)
    assert _apply_op(5, "gt", "big") is False
    assert _apply_op(5, "gte", 5) is True
    assert _apply_op("5", "lt", 10) is False


# --- 14: run_triage_hive validates a caller-supplied collection_id -----------------


def test_run_triage_hive_rejects_unknown_collection_id(tmp_path: Path) -> None:
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"\x00")
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "run_triage_hive", "hive_path": str(hive), "collection_id": "ghost"})
    assert r["ok"] is False
    assert "unknown collection_id" in r["error"]


# --- 15: examiner_status survives re-evaluation ----------------------------------


def test_evaluate_rules_preserves_examiner_status(tmp_path: Path) -> None:
    (tmp_path / "r.yml").write_text(_RULE_YML, encoding="utf-8")
    store = EventStore()
    store.insert_events([_ev(summary="first"), _ev(summary="second")])
    d = build_dispatcher(store, rules_dir=tmp_path)
    assert d.dispatch({"op": "evaluate_rules", "collection_id": "c"})["findings_count"] == 2

    first = next(
        f for f in store.query_findings(collection_id="c") if f["summary"].endswith("first")
    )
    store._conn.execute(
        "UPDATE findings SET examiner_status = 'confirmed_benign' WHERE finding_id = ?",
        (first["finding_id"],),
    )
    assert d.dispatch({"op": "evaluate_rules", "collection_id": "c"})["findings_count"] == 2
    status = {f["summary"]: f["examiner_status"] for f in store.query_findings(collection_id="c")}
    assert status == {first["summary"]: "confirmed_benign", "Test rule — second": "new"}


# --- 16: CSV export neutralizes formula cells --------------------------------------


def test_csv_export_prefixes_formula_cells(tmp_path: Path) -> None:
    store = EventStore()
    store.insert_events([
        _ev(summary="=HYPERLINK(\"http://evil\")", user="@admin", timestamp="2026-06-10T00:00:00Z"),
    ])
    out = tmp_path / "e.csv"
    d = build_dispatcher(store)
    assert d.dispatch({"op": "export_events", "output_path": str(out), "format": "csv"})["ok"]
    header, row = list(csv.reader(out.open(encoding="utf-8", newline="")))
    cells = dict(zip(header, row, strict=True))
    assert cells["summary"] == "'=HYPERLINK(\"http://evil\")"
    assert cells["user"] == "'@admin"
    assert cells["event_type"] == "program_execution"


# --- 18: concurrent store access is serialized -----------------------------------


def test_store_survives_concurrent_writer_and_reader() -> None:
    store = EventStore()
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            for i in range(200):
                store.insert_events([_ev(summary=f"w{i}", timestamp="2026-06-10T00:00:00Z")])
        except BaseException as exc:
            errors.append(exc)

    def reader() -> None:
        try:
            for _ in range(200):
                store.query_events(limit=50)
                store.counts_by_event_type()
                store.query_usb_devices()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert store.count_events() == 200

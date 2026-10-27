"""Tests for the HTML report generator.

We build a small store + findings fixture, generate the report, and assert
the high-value invariants (case name appears, every rule_id appears, MITRE
techniques surface in the heat-map, timeline SVG contains the lane labels).
The HTML isn't asserted byte-for-byte — that'd be brittle — but the
structural checks catch the regressions that would actually matter to an
examiner reading the file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.__main__ import build_dispatcher
from core.events import make_event
from core.report import generate_report
from core.rules import Finding
from core.store import EventStore

_CID = "col-report-test"


@pytest.fixture
def populated_store() -> EventStore:
    store = EventStore()
    store.register_collection(
        collection_id=_CID,
        host_id="HOSTX",
        host_os="windows",
        created_at="2026-06-13T12:00:00Z",
        note="test collection — synthetic",
    )
    store.insert_events([
        make_event(
            host_os="windows", host_id="HOSTX", source_artifact="prefetch",
            source_path="/p", event_type="program_execution",
            summary="Prefetch: powershell.exe", evidence={"program_path": "powershell.exe"},
            collection_id=_CID, parser_version="v", timestamp="2026-06-10T09:00:00Z",
        ),
        make_event(
            host_os="windows", host_id="HOSTX", source_artifact="chrome.history",
            source_path="/p", event_type="browser_download",
            summary="Download: installer.exe",
            evidence={"filename": "installer.exe", "source_host": "evil.example.com"},
            collection_id=_CID, parser_version="v", timestamp="2026-06-11T10:00:00Z",
        ),
        make_event(
            host_os="windows", host_id="HOSTX", source_artifact="registry.system",
            source_path="/p", event_type="usb_connection",
            summary="USB: SanDisk Cruzer",
            evidence={"vendor": "SanDisk", "product": "Cruzer", "serial": "ABC123"},
            collection_id=_CID, parser_version="v", timestamp="2026-06-12T08:30:00Z",
        ),
    ])
    store.insert_findings([
        Finding(
            finding_id="f1", rule_id="rule-exec-001", rule_title="Suspicious execution",
            severity="high", mitre_techniques=("T1059.001",), mitre_tactics=("execution",),
            evidence_event_ids=("e1",), collection_id=_CID,
            created_at="2026-06-13T12:00:00Z", summary="powershell launched",
        ),
        Finding(
            finding_id="f2", rule_id="rule-dl-001", rule_title="Executable download",
            severity="medium", mitre_techniques=("T1204.002",),
            mitre_tactics=("initial-access", "execution"),
            evidence_event_ids=("e2",), collection_id=_CID,
            created_at="2026-06-13T12:00:00Z", summary="installer.exe from evil.example.com",
        ),
    ])
    return store


def test_generate_report_contains_case_name(populated_store: EventStore) -> None:
    html = generate_report(populated_store, _CID, case_name="Op Indigo", examiner="Sam")
    assert "Op Indigo" in html
    assert "Sam" in html
    assert "HOSTX" in html


def test_generate_report_surfaces_every_rule(populated_store: EventStore) -> None:
    html = generate_report(populated_store, _CID, case_name="C", examiner="E")
    assert "rule-exec-001" in html
    assert "rule-dl-001" in html
    assert "Suspicious execution" in html
    assert "Executable download" in html


def test_mitre_heatmap_lists_techniques(populated_store: EventStore) -> None:
    html = generate_report(populated_store, _CID, case_name="C", examiner="E")
    # Both techniques and at least one tactic column header appear.
    assert "T1059.001" in html
    assert "T1204.002" in html
    assert "execution" in html
    assert "initial-access" in html


def test_timeline_lanes_labelled(populated_store: EventStore) -> None:
    html = generate_report(populated_store, _CID, case_name="C", examiner="E")
    # All three source_artifacts that emitted events should appear as lane labels.
    for artifact in ("prefetch", "chrome.history", "registry.system"):
        assert artifact in html
    # And the timeline SVG actually renders dots.
    assert "<circle" in html


def test_per_day_section_flags_busy_day() -> None:
    store = EventStore()
    store.register_collection(
        collection_id="busy", host_id="H", host_os="windows",
        created_at="2026-06-13T12:00:00Z", note="busy-day fixture",
    )
    evs = []
    # quiet baseline: 2 events/day across several days
    for day in range(10, 14):
        for h in range(2):
            evs.append(make_event(
                host_os="windows", host_id="H", source_artifact="prefetch", source_path="/p",
                event_type="program_execution", summary=f"baseline {day}",
                evidence={}, collection_id="busy", parser_version="v",
                timestamp=f"2007-07-{day:02d}T0{h}:00:00Z",
            ))
    # spike day: lots of low-signal browsing (filler) plus one late-day deletion.
    for i in range(40):
        evs.append(make_event(
            host_os="windows", host_id="H", source_artifact="ie.index_dat", source_path="/p",
            event_type="browser_visit", summary=f"visit {i}", evidence={},
            collection_id="busy", parser_version="v", timestamp=f"2007-07-14T{i % 24:02d}:05:00Z",
        ))
    evs.append(make_event(
        host_os="windows", host_id="H", source_artifact="recycle_bin", source_path="/p",
        event_type="file_delete", summary="Deleted: CameraShy.exe", evidence={},
        collection_id="busy", parser_version="v", timestamp="2007-07-14T17:55:00Z",
    ))
    store.insert_events(evs)
    html = generate_report(store, "busy", case_name="C", examiner="E")
    # Assert specifically within the per-day section (not the per-artifact dump).
    per_day = re.search(r'<section class="per-day">.*?</section>', html, re.S)
    assert per_day is not None
    section = per_day.group(0)
    assert "2007-07-14" in section
    # the late-day deletion is prioritised over the 40 morning visits
    assert "Deleted: CameraShy.exe" in section


def test_per_day_section_notes_when_no_busy_days(populated_store: EventStore) -> None:
    html = generate_report(populated_store, _CID, case_name="C", examiner="E")
    # The flat 1-event-per-day fixture has no statistical spike.
    assert "No statistically busy days" in html


def test_empty_collection_renders_without_crashing() -> None:
    store = EventStore()
    store.register_collection(
        collection_id="empty", host_id="H", host_os="windows",
        created_at="2026-06-13T12:00:00Z", note="empty",
    )
    html = generate_report(store, "empty", case_name="Empty", examiner="X")
    # Doesn't crash, includes the report skeleton even with no data.
    assert "<title>" in html
    assert "MITRE" in html
    assert "Timeline" in html


def test_html_is_self_contained(populated_store: EventStore) -> None:
    """No external script/style/image refs — examiners email this around."""
    html = generate_report(populated_store, _CID, case_name="C", examiner="E")
    assert "<script" not in html
    assert "src=" not in html
    assert not re.search(r'<link[^>]+href="http', html)


def test_sidecar_generate_report_writes_file(tmp_path: Path, populated_store: EventStore) -> None:
    d = build_dispatcher(populated_store)
    out = tmp_path / "report.html"
    r = d.dispatch({
        "op": "generate_report",
        "collection_id": _CID,
        "output_path": str(out),
        "case_name": "From Sidecar",
        "examiner": "S",
    })
    assert r["ok"] is True
    assert r["size_bytes"] > 1000
    assert len(r["sha256"]) == 64
    text = out.read_text(encoding="utf-8")
    assert "From Sidecar" in text


def test_non_ascii_case_name_round_trips(tmp_path: Path, populated_store: EventStore) -> None:
    """Regression: em-dash / accented chars in case_name must survive to the file.

    Prior bug: Windows-default cp1252 stdin in the sidecar mojibake'd UTF-8
    bytes from the Rust IPC. The fix (sys.stdin.reconfigure utf-8) keeps
    Unicode intact end-to-end. We assert the proper character, not the
    Windows-1252 corruption it would produce.
    """
    out = tmp_path / "r.html"
    d = build_dispatcher(populated_store)
    r = d.dispatch({
        "op": "generate_report",
        "collection_id": _CID,
        "output_path": str(out),
        "case_name": "Triage — MSI · café",
        "examiner": "Sámuel",
    })
    assert r["ok"] is True
    text = out.read_text(encoding="utf-8")
    assert "Triage — MSI · café" in text
    assert "Sámuel" in text
    # The mojibake form must NOT appear.
    assert "â€" not in text


def test_sidecar_generate_report_validates_inputs() -> None:
    d = build_dispatcher(EventStore())
    r = d.dispatch({"op": "generate_report"})
    assert r["ok"] is False
    assert "collection_id" in r["error"]

    r = d.dispatch({"op": "generate_report", "collection_id": "c"})
    assert r["ok"] is False
    assert "output_path" in r["error"]


# --- Deleted files section ---------------------------------------------------


def _deletion_event(method: str, path: str, ts: str, **extra: object) -> object:
    evidence: dict[str, object] = {
        "original_path": path, "deleted_name": path.rsplit("\\", 1)[-1], "deleted_size": 5,
        "deletion_method": method, "recoverable_hint": "unknown", "is_directory": False,
    }
    evidence.update(extra)
    src = {"recycle_bin": "recycle_bin", "usn_journal": "usnjrnl", "mft_unallocated": "mft"}
    return make_event(
        host_os="windows", host_id="H", source_artifact=src[method], source_path="/p",
        event_type="file_delete", summary=f"Deleted: {path}", evidence=evidence,
        collection_id="dels", parser_version="v", timestamp=ts,
        timestamp_source="inferred" if method == "mft_unallocated" else None,
    )


def test_deleted_files_section_renders_rows_confidence_and_limits() -> None:
    from core.deletions import build_deletions

    store = EventStore()
    store.register_collection(
        collection_id="dels", host_id="H", host_os="windows",
        created_at="2026-06-13T12:00:00Z", note="deletions fixture",
    )
    sid = "S-1-5-21-9-9-9-1001"
    store.insert_events([
        make_event(
            host_os="windows", host_id="H", source_artifact="registry.sam", source_path="/p",
            event_type="account_change", summary="alice",
            evidence={"sid": sid, "username": "alice"},
            collection_id="dels", parser_version="v",
        ),
        _deletion_event("recycle_bin", r"C:\Users\alice\binned.docx", "2026-06-10T09:00:00Z",
                        actor_sid=sid, owner_sid=sid, recovered_name="$R1.docx",
                        recoverable_hint="recycle_bin_blob"),
        _deletion_event("mft_unallocated", r"C:\Users\alice\bounded.txt", "2026-06-09T09:00:00Z"),
        *[
            _deletion_event("usn_journal", rf"C:\bulk\{i}.tmp", f"2026-06-11T10:00:{i:02d}Z")
            for i in range(25)
        ],
    ])
    summary = build_deletions(store, "dels")
    assert summary.bursts == 1

    html = generate_report(store, "dels", case_name="C", examiner="E")
    section = re.search(r'<section class="deletions">.*?</section>', html, re.S)
    assert section is not None
    text = section.group(0)
    assert "Deleted files" in text
    assert "27 total" in text
    assert "Recycle Bin: <strong>1</strong>" in text
    assert "USN journal: <strong>25</strong>" in text
    assert "binned.docx" in text and "alice" in text
    assert "conf-direct" in text and "conf-unknown" in text
    assert "&le; 2026-06-09T09:00:00Z" in text  # MFT upper bound is marked
    assert "recycle_bin_blob" in text
    assert "Deletion bursts" in text and "2026-06-11T10:00:00Z" in text
    assert "How to read the user column" in text
    assert "No carving" in text and "finite retention window" in text
    assert "inferred from who was logged on" in text
    assert "Found in the Recycle Bin folder" in text  # reason surfaces as a tooltip


def test_deleted_files_section_when_empty_still_states_limits() -> None:
    store = EventStore()
    store.register_collection(
        collection_id="nodels", host_id="H", host_os="windows",
        created_at="2026-06-13T12:00:00Z", note="empty",
    )
    html = generate_report(store, "nodels", case_name="C", examiner="E")
    assert "No Recycle Bin, USN journal or $MFT deletion records" in html
    assert "No carving" in html

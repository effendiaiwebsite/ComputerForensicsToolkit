"""Tests for the append-only audit log."""

from __future__ import annotations

from pathlib import Path

from core.audit import AuditLog, AuditRecord


def test_audit_round_trip(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.ok(
        action="copy",
        source_path="/Windows/System32/config/SYSTEM",
        dest_path="Windows/System32/config/SYSTEM",
        sha256="a" * 64,
        size_bytes=1024,
        category="registry",
    )
    log.skipped("copy", "/Users/ghost/NTUSER.DAT", "not present")
    log.error("copy", "/Windows/Prefetch/X.pf", RuntimeError("locked"))

    records = log.read_all()
    assert [r["status"] for r in records] == ["ok", "skipped", "error"]
    assert records[0]["sha256"] == "a" * 64
    assert records[0]["extra"]["category"] == "registry"
    assert "locked" in records[2]["error"]


def test_audit_is_append_only_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).ok("copy", "/a", "a", "h", 1)
    AuditLog(path).ok("copy", "/b", "b", "h", 2)
    AuditLog(path).ok("copy", "/c", "c", "h", 3)

    records = AuditLog(path).read_all()
    assert [r["source_path"] for r in records] == ["/a", "/b", "/c"]


def test_audit_accepts_raw_record(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.write(AuditRecord(
        timestamp="2026-06-13T12:00:00Z",
        action="custom",
        source_path="/x",
        status="ok",
        sha256="abc",
        size_bytes=10,
    ))
    assert log.read_all()[0]["action"] == "custom"

"""Tests for ``collectors.windows.ntfs_meta.collect_ntfs_meta`` against a fake target.

The fake exposes exactly the surface the collector touches: ``target.fs.mounts``,
``target.filesystems``, ``fs.ntfs.{mft.fh, usnjrnl.fh, secure.sds}`` and
``fs.path(...)``. Stream bytes are arbitrary; what matters is the copy, the
SHA-256 in the audit record and the sparse-prefix handling for ``$J``.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from types import SimpleNamespace

from dissect.util.stream import RunlistStream

from collectors.windows.ntfs_meta import NtfsMetaArtifacts, collect_ntfs_meta
from core.audit import AuditLog

MFT_BYTES = b"FILE0" * 400
SDS_BYTES = b"SDS!" * 100
J_DATA = b"USN-RECORDS" * 20


class _FakePath:
    """Mimics ``TargetPath``: ``exists()`` / ``is_dir()`` / ``open('rb')``."""

    def __init__(self, exists: bool = False, is_dir: bool = False, fh=None) -> None:
        self._exists = exists
        self._is_dir = is_dir
        self._fh = fh

    def exists(self) -> bool:
        return self._exists

    def is_dir(self) -> bool:
        return self._is_dir

    def open(self, mode: str = "rb"):
        if self._fh is None:
            raise FileNotFoundError
        return self._fh


class _FakeNtfsFs:
    def __init__(self, ntfs, paths: dict[str, _FakePath] | None = None, windows: bool = True):
        self.ntfs = ntfs
        self._paths = dict(paths or {})
        if windows:
            self._paths.setdefault("/Windows", _FakePath(exists=True, is_dir=True))

    def path(self, p: str) -> _FakePath:
        return self._paths.get(p, _FakePath())


def _ntfs(mft: bytes | None = MFT_BYTES, j=J_DATA, sds: bytes | None = SDS_BYTES):
    """``ntfs`` object with raw streams, like ``dissect.ntfs.NTFS`` exposes them."""
    return SimpleNamespace(
        mft=SimpleNamespace(fh=io.BytesIO(mft)) if mft is not None else None,
        usnjrnl=SimpleNamespace(fh=io.BytesIO(j) if isinstance(j, bytes) else j)
        if j is not None else None,
        secure=SimpleNamespace(sds=io.BytesIO(sds)) if sds is not None else None,
    )


def _target(*filesystems, mounts: dict | None = None):
    return SimpleNamespace(
        fs=SimpleNamespace(mounts=mounts or {}),
        filesystems=list(filesystems),
    )


def _ok_records(audit: AuditLog) -> dict[str, dict]:
    return {r["extra"]["label"]: r for r in audit.read_all() if r["status"] == "ok"}


def test_copies_three_streams_via_raw_fallback_with_hashes(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    target = _target(_FakeNtfsFs(_ntfs()))

    result = collect_ntfs_meta(target, tmp_path, audit=audit)

    assert isinstance(result, NtfsMetaArtifacts)
    assert result.errors == []
    assert result.drive_letter == "C:"
    assert Path(result.mft_path) == tmp_path / "ntfs" / "$MFT"
    assert Path(result.usnjrnl_path) == tmp_path / "ntfs" / "$J"
    assert Path(result.sds_path) == tmp_path / "ntfs" / "$SDS"
    assert Path(result.mft_path).read_bytes() == MFT_BYTES
    assert Path(result.usnjrnl_path).read_bytes() == J_DATA
    assert Path(result.sds_path).read_bytes() == SDS_BYTES

    ok = _ok_records(audit)
    assert set(ok) == {"$MFT", "$UsnJrnl:$J", "$Secure:$SDS"}
    for rec in ok.values():
        copied = (tmp_path / rec["dest_path"]).read_bytes()
        assert rec["sha256"] == hashlib.sha256(copied).hexdigest()
        assert rec["size_bytes"] == len(copied)
        assert rec["extra"]["category"] == "ntfs_meta"
        assert rec["dest_path"].startswith("ntfs")
    assert ok["$UsnJrnl:$J"]["extra"]["sparse_prefix_bytes"] == 0
    assert ok["$MFT"]["source_path"] == "filesystems[0]:$MFT"


def test_prefers_fs_path_ads_and_skips_sparse_prefix(tmp_path: Path) -> None:
    # $J as NTFS stores it: a sparse (purged) prefix followed by the live data.
    volume = io.BytesIO(J_DATA + b"\x00" * 1024)
    block = 64
    data_blocks = -(-len(J_DATA) // block)
    j_stream = RunlistStream(volume, [(None, 3), (0, data_blocks)], 3 * block + len(J_DATA), block)
    paths = {
        "$MFT": _FakePath(exists=True, fh=io.BytesIO(MFT_BYTES)),
        "$Extend/$UsnJrnl:$J": _FakePath(exists=True, fh=j_stream),
        "$Secure:$SDS": _FakePath(exists=True, fh=io.BytesIO(SDS_BYTES)),
    }
    # Raw fallbacks hold different bytes so we can tell which route was taken.
    ntfs = _ntfs(mft=b"RAW-MFT", j=b"RAW-J", sds=b"RAW-SDS")
    audit = AuditLog(tmp_path / "audit.jsonl")

    result = collect_ntfs_meta(_target(_FakeNtfsFs(ntfs, paths)), tmp_path, audit=audit)

    assert result.errors == []
    assert Path(result.mft_path).read_bytes() == MFT_BYTES
    assert Path(result.sds_path).read_bytes() == SDS_BYTES
    assert Path(result.usnjrnl_path).read_bytes() == J_DATA
    ok = _ok_records(audit)
    assert ok["$UsnJrnl:$J"]["extra"]["sparse_prefix_bytes"] == 3 * block
    assert ok["$UsnJrnl:$J"]["size_bytes"] == len(J_DATA)


def test_missing_journal_is_skipped_not_error(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = collect_ntfs_meta(_target(_FakeNtfsFs(_ntfs(j=None))), tmp_path, audit=audit)
    assert result.usnjrnl_path is None
    assert result.mft_path and result.sds_path
    assert result.errors == []
    skipped = [r for r in audit.read_all() if r["status"] == "skipped"]
    assert len(skipped) == 1
    assert skipped[0]["extra"]["label"] == "$UsnJrnl:$J"
    assert skipped[0]["error"] == "not present"


def test_no_ntfs_filesystem_yields_empty_result(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    target = SimpleNamespace(fs=SimpleNamespace(), filesystems=[object()])
    result = collect_ntfs_meta(target, tmp_path, audit=audit)
    assert (result.mft_path, result.usnjrnl_path, result.sds_path) == (None, None, None)
    assert result.errors == []
    assert not (tmp_path / "ntfs").exists()
    records = audit.read_all()
    assert len(records) == 1 and records[0]["status"] == "skipped"
    assert "no NTFS filesystem" in records[0]["error"]


class _ExplodingStream(io.BytesIO):
    def read(self, n: int = -1) -> bytes:
        raise OSError("device read error")


def test_read_failure_is_audited_and_partial_file_removed(tmp_path: Path) -> None:
    ntfs = _ntfs()
    ntfs.mft = SimpleNamespace(fh=_ExplodingStream(b"x"))
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = collect_ntfs_meta(_target(_FakeNtfsFs(ntfs)), tmp_path, audit=audit)
    assert result.mft_path is None
    assert result.usnjrnl_path and result.sds_path
    assert len(result.errors) == 1 and "device read error" in result.errors[0]
    assert not (tmp_path / "ntfs" / "$MFT").exists()
    errors = [r for r in audit.read_all() if r["status"] == "error"]
    assert len(errors) == 1
    assert errors[0]["extra"]["label"] == "$MFT"
    assert "OSError" in errors[0]["error"]


def test_explicit_fs_index_and_drive_letter_from_mounts(tmp_path: Path) -> None:
    other = _FakeNtfsFs(_ntfs(mft=b"OTHER"), windows=False)
    windows = _FakeNtfsFs(_ntfs(mft=b"WIN"))
    mounts = {"sysvol": windows, "d:": other, "c:": windows}
    audit = AuditLog(tmp_path / "audit.jsonl")

    auto = collect_ntfs_meta(_target(other, windows, mounts=mounts), tmp_path / "auto", audit=audit)
    assert Path(auto.mft_path).read_bytes() == b"WIN"
    assert auto.drive_letter == "C:"

    forced = collect_ntfs_meta(
        _target(other, windows, mounts=mounts), tmp_path / "forced", audit=audit, fs_index=0,
    )
    assert Path(forced.mft_path).read_bytes() == b"OTHER"
    assert forced.drive_letter == "D:"

    bad = collect_ntfs_meta(_target(other, windows), tmp_path / "bad", audit=audit, fs_index=5)
    assert bad.mft_path is None and bad.errors == []


def test_falls_back_to_first_ntfs_when_no_windows_dir(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    fs = _FakeNtfsFs(_ntfs(mft=b"ONLY"), windows=False)
    result = collect_ntfs_meta(_target(fs), tmp_path, audit=audit)
    assert Path(result.mft_path).read_bytes() == b"ONLY"

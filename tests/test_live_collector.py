"""Tests for the live disk collector using a fake dissect target.

We don't drive real ``dissect.target`` here — that would need admin or a
sample image. Instead we build a minimal ``FakeTarget`` exposing the same
attribute surface the collector actually touches (``target.fs.path`` and
``target.user_details.all``). This keeps the collector's contract honest:
if it grows to assume new attributes, the test must grow with it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from collectors.windows.live_disk import NoWindowsVolumeError, _normalize_home, collect_live
from core.audit import AuditLog
from core.progress import ProgressTracker


def test_normalize_home_strips_drive_for_volume_relative_root():
    # user_details hands back Windows drive-lettered homes; the raw NTFS root
    # (image E01s) needs volume-relative paths or every per-user artifact drops.
    assert _normalize_home(r"C:\Users\Wes Mantooth") == "/Users/Wes Mantooth"
    assert _normalize_home("C:/Users/Dracula") == "/Users/Dracula"
    assert _normalize_home("/Users/already") == "/Users/already"
    assert _normalize_home("Users/norel") == "/Users/norel"
    assert _normalize_home(None) is None
    assert _normalize_home("") is None


@dataclass
class FakeFile:
    """One file in the fake target's tree."""
    rel_path: str
    payload: bytes


class FakePath:
    def __init__(self, root: Path, rel: str) -> None:
        self._root = root
        self._rel = rel.lstrip("/")
        self._concrete = (root / self._rel).resolve()

    @property
    def name(self) -> str:
        return self._concrete.name

    def exists(self) -> bool:
        return self._concrete.exists()

    def is_file(self) -> bool:
        return self._concrete.is_file()

    def is_dir(self) -> bool:
        return self._concrete.is_dir()

    def open(self, mode: str = "rb"):
        return self._concrete.open(mode)

    def iterdir(self) -> Iterator[FakePath]:
        for child in self._concrete.iterdir():
            yield FakePath(self._root, str(child.relative_to(self._root)).replace("\\", "/"))

    def rglob(self, pattern: str) -> Iterator[FakePath]:
        for child in self._concrete.rglob(pattern):
            yield FakePath(self._root, str(child.relative_to(self._root)).replace("\\", "/"))

    def relative_to(self, other: FakePath) -> Path:
        return self._concrete.relative_to(other._concrete)

    def __str__(self) -> str:
        return "/" + self._rel

    def __repr__(self) -> str:
        return f"FakePath({self._rel!r})"


class FakeFS:
    def __init__(self, root: Path) -> None:
        self._root = root

    def path(self, p: str) -> FakePath:
        return FakePath(self._root, p)


@dataclass
class FakeUser:
    name: str
    home: str


class FakeUserDetails:
    """Wraps a list of users so collector.user_details.all() works."""
    def __init__(self, users: list[FakeUser]):
        self._users = users

    def all(self) -> Iterator[dict]:
        for u in self._users:
            yield {"user": u, "home_path": u.home, "name": u.name}


class FakeTarget:
    def __init__(self, fs_root: Path, users: list[FakeUser]):
        self.fs = FakeFS(fs_root)
        # user_details emits objects with .user.name and .home_path — but our
        # collector falls back to dict-style access too, so a list of dicts works.
        self._users = users

    @property
    def user_details(self):
        target = self

        class _Wrap:
            @staticmethod
            def all():
                for u in target._users:
                    yield type("UD", (), {"user": u, "home_path": u.home, "name": u.name})()
        return _Wrap()


def _materialize(root: Path, files: list[FakeFile]) -> None:
    for f in files:
        p = root / f.rel_path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(f.payload)


def test_collect_copies_hashes_and_audits(tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    dest_root = tmp_path / "dest"
    src_root.mkdir()
    dest_root.mkdir()

    _materialize(src_root, [
        FakeFile("Windows/System32/config/SYSTEM",   b"SYSTEM_HIVE_BYTES" * 128),
        FakeFile("Windows/System32/config/SOFTWARE", b"SOFTWARE_HIVE"),
        FakeFile("Windows/Prefetch/CHROME.EXE-A1B2C3D4.pf", b"prefetch-bytes"),
        FakeFile("Windows/Prefetch/CMD.EXE-FFEEDDCC.pf",    b"another-pf"),
        FakeFile("Windows/System32/winevt/Logs/Security.evtx", b"evtx-bytes"),
        FakeFile("Users/alice/NTUSER.DAT", b"alice-ntuser"),
        FakeFile(
            "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
            b"chrome-history-bytes",
        ),
    ])

    audit = AuditLog(dest_root / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("c1", label="test", total=0)

    target = FakeTarget(src_root, [FakeUser(name="alice", home="/Users/alice")])
    result = collect_live(
        target,
        collection_id="c1",
        dest_dir=dest_root,
        audit=audit,
        progress=progress,
        source_label="fake://test",
    )

    # All seven seeded files should land in the dest tree under mirrored paths.
    expected = [
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SOFTWARE",
        "Windows/Prefetch/CHROME.EXE-A1B2C3D4.pf",
        "Windows/Prefetch/CMD.EXE-FFEEDDCC.pf",
        "Windows/System32/winevt/Logs/Security.evtx",
        "Users/alice/NTUSER.DAT",
        "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
    ]
    for rel in expected:
        copied = dest_root / rel
        assert copied.exists(), f"missing in dest: {rel}"

    # SHA-256 in the audit log matches the actual file bytes.
    records = audit.read_all()
    ok_records = [r for r in records if r["status"] == "ok"]
    assert len(ok_records) == len(expected)
    for rec in ok_records:
        dest_bytes = (dest_root / rec["dest_path"]).read_bytes()
        assert hashlib.sha256(dest_bytes).hexdigest() == rec["sha256"]
        assert rec["size_bytes"] == len(dest_bytes)

    assert result.files_collected == len(expected)
    assert result.errors == 0
    snap = progress.get("c1")
    # Progress.completed counts every attempted spec — copies + skips — so it
    # equals snap.total once the run finishes.
    assert snap.completed == snap.total
    assert snap.by_category["registry"] >= 3
    # The fake target exposes no NTFS internals: NTFS metadata is reported as
    # absent (one skipped audit record), never as an error.
    assert result.ntfs_meta == {
        "mft_path": None, "usnjrnl_path": None, "sds_path": None,
        "drive_letter": "C:", "errors": [],
    }
    assert any(r["extra"].get("label") == "ntfs_meta" for r in records if r["status"] == "skipped")


class _FakeNtfsTarget(FakeTarget):
    """FakeTarget plus one dissect-shaped NTFS filesystem for ntfs_meta collection."""

    def __init__(self, fs_root: Path, users: list[FakeUser], *, mft: bytes, j: bytes) -> None:
        super().__init__(fs_root, users)
        import io
        from types import SimpleNamespace

        ntfs = SimpleNamespace(
            mft=SimpleNamespace(fh=io.BytesIO(mft)),
            usnjrnl=SimpleNamespace(fh=io.BytesIO(j)),
            secure=None,
        )
        ntfs_fs = SimpleNamespace(ntfs=ntfs, path=self.fs.path)
        self.filesystems = [ntfs_fs]


def test_collect_live_includes_ntfs_metadata(tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    dest_root = tmp_path / "dest"
    src_root.mkdir()
    dest_root.mkdir()
    _materialize(src_root, [FakeFile("Windows/System32/config/SYSTEM", b"sys")])
    audit = AuditLog(dest_root / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("c", label="t", total=0)

    target = _FakeNtfsTarget(src_root, [], mft=b"FILE" * 256, j=b"J" * 100)
    result = collect_live(
        target, collection_id="c", dest_dir=dest_root, audit=audit, progress=progress,
        source_label="fake://ntfs",
    )

    assert result.files_collected == 3  # SYSTEM + $MFT + $J
    assert result.bytes_collected == 3 + 1024 + 100
    assert result.errors == 0
    assert result.ntfs_meta["mft_path"] == str(dest_root / "ntfs" / "$MFT")
    assert result.ntfs_meta["usnjrnl_path"] == str(dest_root / "ntfs" / "$J")
    assert result.ntfs_meta["sds_path"] is None
    assert (dest_root / "ntfs" / "$MFT").read_bytes() == b"FILE" * 256
    ok = [r for r in audit.read_all() if r["status"] == "ok"]
    labels = {r["extra"]["label"] for r in ok}
    assert {"$MFT", "$UsnJrnl:$J", "SYSTEM hive"} <= labels
    snap = progress.get("c")
    assert snap.completed == snap.total
    assert snap.by_category["ntfs_meta"] == 1


def test_missing_artifacts_are_skipped_not_failed(tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    dest_root = tmp_path / "dest"
    src_root.mkdir()
    dest_root.mkdir()
    # Only one system file present — the rest of the spec list should be cleanly
    # skipped, BUT at least one of the five system hives must land so we don't
    # trip the no-Windows-volume early-exit.
    _materialize(src_root, [
        FakeFile("Windows/System32/config/SYSTEM", b"only-system"),
    ])

    audit = AuditLog(dest_root / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("c", label="t", total=0)

    target = FakeTarget(src_root, [])  # no users either
    result = collect_live(
        target,
        collection_id="c",
        dest_dir=dest_root,
        audit=audit,
        progress=progress,
        source_label="fake://empty",
    )
    assert result.files_collected == 1
    assert result.errors == 0
    records = audit.read_all()
    skipped = [r for r in records if r["status"] == "skipped"]
    assert len(skipped) >= 3  # SOFTWARE, SAM, SECURITY all missing


def test_no_windows_volume_raises_early(tmp_path: Path) -> None:
    """If none of the 5 system hives land, abort instead of grinding the rest."""
    src_root = tmp_path / "src"
    dest_root = tmp_path / "dest"
    src_root.mkdir()
    dest_root.mkdir()
    # Image contains a Linux-shaped tree, no /Windows at all.
    _materialize(src_root, [
        FakeFile("etc/passwd", b"root:x:0:0:root:/root:/bin/bash"),
        FakeFile("home/alice/.bashrc", b"# noop"),
    ])

    audit = AuditLog(dest_root / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("c", label="t", total=0)

    target = FakeTarget(src_root, [])
    # _resolve_windows_root catches the missing /Windows dir up front (one audit
    # entry); the legacy post-probe path (five skipped specs) still applies
    # whenever /Windows is present but the SYSTEM/SOFTWARE/etc. hives aren't.
    with pytest.raises(
        NoWindowsVolumeError, match=r"(No Windows volume|canonical Windows system hives)"
    ):
        collect_live(
            target,
            collection_id="c",
            dest_dir=dest_root,
            audit=audit,
            progress=progress,
            source_label="fake://linux",
        )

    # One audit record for the resolve_windows_root abort — the audit trail
    # shows we looked and found no Windows volume, instead of silently doing
    # zero work and leaving the examiner wondering.
    records = audit.read_all()
    assert len(records) == 1
    assert records[0]["action"] == "resolve_windows_root"
    assert records[0]["status"] == "skipped"


def test_enumerate_drives_non_windows_returns_empty(monkeypatch) -> None:
    import collectors.windows.live_disk as ld

    monkeypatch.setattr(ld.sys, "platform", "linux")
    assert ld.enumerate_physical_drives() == []


def test_open_target_translates_device_paths_to_local(monkeypatch) -> None:
    """Regression: \\\\.\\PhysicalDriveN must go through dissect's LocalLoader.

    If routed through Target.open() with the raw device path, the VBLoader
    auto-detect calls path.joinpath('MFT_C.bin').exists() and trips
    WinError 31 on Windows. Translating to 'local' bypasses the broken
    auto-detect path entirely.
    """
    seen: list[str] = []

    class _FakeTargetModule:
        class Target:
            @staticmethod
            def open(source: str) -> str:
                seen.append(source)
                return f"target<{source}>"

    monkeypatch.setitem(__import__("sys").modules, "dissect.target", _FakeTargetModule)

    from collectors.windows.live_disk import open_target

    open_target(r"\\.\PhysicalDrive0")
    open_target(r"\\.\PhysicalDrive1")
    open_target("local")
    open_target(r"C:\images\evidence.E01")

    assert seen == ["local", "local", "local", r"C:\images\evidence.E01"]


def _run_collect(tmp_path: Path, files: list[FakeFile], users: list[FakeUser]):
    src_root = tmp_path / "src"
    dest_root = tmp_path / "dest"
    src_root.mkdir()
    dest_root.mkdir()
    _materialize(src_root, files)
    audit = AuditLog(dest_root / "audit.jsonl")
    progress = ProgressTracker()
    progress.start("c", label="t", total=0)
    result = collect_live(
        FakeTarget(src_root, users),
        collection_id="c", dest_dir=dest_root, audit=audit, progress=progress,
        source_label="fake://sidecars",
    )
    return result, dest_root, audit.read_all()


def test_sqlite_wal_sidecars_are_collected_when_present(tmp_path: Path) -> None:
    chrome = "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History"
    places = (
        "Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release/places.sqlite"
    )
    webcache_dir = "Users/alice/AppData/Local/Microsoft/Windows/WebCache"
    result, dest_root, records = _run_collect(tmp_path, [
        FakeFile("Windows/System32/config/SYSTEM", b"sys"),
        FakeFile(chrome, b"history"),
        FakeFile(chrome + "-wal", b"history-wal"),
        FakeFile(places, b"places"),
        FakeFile(places + "-wal", b"places-wal"),
        FakeFile(places + "-journal", b"places-journal"),
        FakeFile(f"{webcache_dir}/WebCacheV01.dat", b"ese"),
        FakeFile(f"{webcache_dir}/V01.log", b"log"),
        FakeFile(f"{webcache_dir}/V01.chk", b"chk"),
        FakeFile(f"{webcache_dir}/V01res00001.jrs", b"jrs"),
    ], [FakeUser(name="alice", home="/Users/alice")])

    for rel in (
        chrome, chrome + "-wal", places, places + "-wal", places + "-journal",
        f"{webcache_dir}/WebCacheV01.dat", f"{webcache_dir}/V01.log",
        f"{webcache_dir}/V01.chk", f"{webcache_dir}/V01res00001.jrs",
    ):
        assert (dest_root / rel).exists(), rel
    # A missing sidecar is simply not attempted: no "not present" noise for it.
    skipped_paths = [r["source_path"] for r in records if r["status"] == "skipped"]
    assert not any(p.endswith("History-journal") for p in skipped_paths)
    assert result.errors == 0


def test_directory_at_artifact_path_is_audited_as_not_a_regular_file(tmp_path: Path) -> None:
    result, _dest_root, records = _run_collect(tmp_path, [
        FakeFile("Windows/System32/config/SYSTEM", b"sys"),
        FakeFile("Windows/System32/config/SAM/placeholder", b"x"),  # SAM is a directory
    ], [])
    sam = [r for r in records if r["source_path"].endswith("config/SAM")]
    assert sam and sam[0]["status"] == "skipped"
    assert sam[0]["error"] == "not a regular file"
    software = [r for r in records if r["source_path"].endswith("config/SOFTWARE")]
    assert software[0]["error"] == "not present"
    assert result.errors == 0

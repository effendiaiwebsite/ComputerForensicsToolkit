"""Tests for the prefetch parser — drive a synthetic pyscca-shaped object."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from parsers.prefetch import _event_from_pf


class _FakeFileMetric:
    def __init__(self, filename: str) -> None:
        self.filename = filename


class _FakeVolume:
    def __init__(self, device_path: str, serial_number: int, creation_time: datetime) -> None:
        self.device_path = device_path
        self.serial_number = serial_number
        self.creation_time = creation_time


class _FakeSCCA:
    def __init__(
        self,
        *,
        executable_filename: str = "POWERSHELL.EXE",
        run_count: int = 5,
        format_version: int = 30,
        prefetch_hash: int = 0xDEADBEEF,
        run_times: list[datetime | None] | None = None,
        accessed_files: list[str] | None = None,
        volumes: list[_FakeVolume] | None = None,
    ) -> None:
        self.executable_filename = executable_filename
        self.run_count = run_count
        self.format_version = format_version
        self.prefetch_hash = prefetch_hash
        self._run_times = run_times or []
        self._accessed = accessed_files or []
        self._volumes = volumes or []

    def get_last_run_time(self, idx: int) -> datetime | None:
        if 0 <= idx < len(self._run_times):
            return self._run_times[idx]
        raise OSError("no more run times")

    @property
    def number_of_file_metrics_entries(self) -> int:
        return len(self._accessed)

    def get_file_metrics_entry(self, idx: int) -> _FakeFileMetric:
        return _FakeFileMetric(self._accessed[idx])

    @property
    def number_of_volumes(self) -> int:
        return len(self._volumes)

    def get_volume_information(self, idx: int) -> _FakeVolume:
        return self._volumes[idx]


def _kwargs(**overrides: Any) -> dict[str, Any]:
    base = dict(
        source_path=r"C:\Windows\Prefetch\POWERSHELL.EXE-1234ABCD.pf",
        collection_id="col-1",
        host_id_hint="HOST",
    )
    base.update(overrides)
    return base


def test_event_uses_first_run_time_as_timestamp() -> None:
    pf = _FakeSCCA(
        run_times=[
            datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC),
            datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        ],
    )
    ev = _event_from_pf(pf, **_kwargs())
    assert ev.event_type == "program_execution"
    assert ev.source_artifact == "prefetch"
    assert ev.timestamp == "2026-06-11T12:00:00Z"
    assert ev.evidence["last_run_time"] == "2026-06-11T12:00:00Z"
    assert ev.evidence["previous_run_times"] == ["2026-06-10T12:00:00Z"]


def test_summary_includes_name_and_run_count() -> None:
    pf = _FakeSCCA(
        executable_filename="NOTEPAD.EXE",
        run_count=42,
        run_times=[datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)],
    )
    ev = _event_from_pf(pf, **_kwargs())
    assert "NOTEPAD.EXE" in ev.summary
    assert "42" in ev.summary


def test_zero_filetime_run_times_are_skipped() -> None:
    pf = _FakeSCCA(
        run_times=[
            datetime(1601, 1, 1, tzinfo=UTC),  # FILETIME zero
            datetime(2026, 6, 10, tzinfo=UTC),
        ],
    )
    ev = _event_from_pf(pf, **_kwargs())
    assert ev.timestamp == "2026-06-10T00:00:00Z"
    assert ev.evidence["previous_run_times"] == []


def test_program_path_resolved_from_accessed_files() -> None:
    pf = _FakeSCCA(
        executable_filename="POWERSHELL.EXE",
        accessed_files=[
            r"\VOLUME{abc}\WINDOWS\SYSTEM32\NTDLL.DLL",
            r"\VOLUME{abc}\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE",
        ],
        run_times=[datetime(2026, 6, 11, tzinfo=UTC)],
    )
    ev = _event_from_pf(pf, **_kwargs())
    assert ev.evidence["program_path"].endswith("POWERSHELL.EXE")
    assert ev.evidence["accessed_files_count"] == 2


def test_volume_information_collected() -> None:
    pf = _FakeSCCA(
        run_times=[datetime(2026, 6, 11, tzinfo=UTC)],
        volumes=[
            _FakeVolume(
                device_path=r"\Device\HarddiskVolume3",
                serial_number=0xAABBCCDD,
                creation_time=datetime(2024, 1, 1, tzinfo=UTC),
            ),
        ],
    )
    ev = _event_from_pf(pf, **_kwargs())
    assert ev.evidence["volume_count"] == 1
    assert ev.evidence["volumes"][0]["device_path"] == r"\Device\HarddiskVolume3"
    assert ev.evidence["volumes"][0]["serial_number"] == "0xAABBCCDD"
    assert ev.evidence["volumes"][0]["creation_time"] == "2024-01-01T00:00:00Z"


def test_prefetch_hash_formatted_as_hex() -> None:
    pf = _FakeSCCA(
        prefetch_hash=0x12345678,
        run_times=[datetime(2026, 6, 11, tzinfo=UTC)],
    )
    ev = _event_from_pf(pf, **_kwargs())
    assert ev.evidence["prefetch_hash"] == "0x12345678"


def test_parse_prefetch_swallows_open_errors(tmp_path: Path) -> None:
    """Real pyscca raises on bad files; we want an empty list, not a crash."""
    bogus = tmp_path / "bogus.pf"
    bogus.write_bytes(b"not a real prefetch")
    from parsers.prefetch import parse_prefetch

    events = parse_prefetch(bogus, collection_id="c", host_id_hint="H")
    assert events == []


def test_module_uses_pyscca_file() -> None:
    """Smoke-check that the real parse_prefetch calls pyscca.file().open()."""
    from parsers import prefetch as mod

    captured: dict[str, Any] = {}

    class _Stub:
        def open(self, p):
            captured["opened"] = p
            raise RuntimeError("stop after open")

        def close(self):
            pass

    with patch.object(mod.pyscca, "file", return_value=_Stub()):
        events = mod.parse_prefetch("anything.pf", collection_id="c", host_id_hint="H")
    assert events == []
    assert captured["opened"].endswith("anything.pf")

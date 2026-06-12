"""Tests for the single-hive collector."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from collectors.windows.hive import collect_hive


def test_collect_hive_hashes_file_and_records_size(tmp_path: Path) -> None:
    payload = b"regf-fake-content" * 32
    src = tmp_path / "SYSTEM"
    src.write_bytes(payload)

    bundle = collect_hive(src, kind="system", host_id="HOST123")

    assert bundle.host_os == "windows"
    assert bundle.host_id == "HOST123"
    assert bundle.collection_id.startswith("col-")
    assert len(bundle.artifacts) == 1
    a = bundle.artifacts[0]
    assert a.kind == "system"
    assert a.size_bytes == len(payload)
    assert a.sha256 == hashlib.sha256(payload).hexdigest()


def test_collect_hive_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        collect_hive(tmp_path / "nope", kind="system")


def test_collect_hive_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        collect_hive(tmp_path, kind="system")

"""Hive dispatcher rejects unsupported kinds and unreadable paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from parsers.registry import parse_hive


def test_unknown_path_bubbles_up(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        parse_hive(
            tmp_path / "missing.hve",
            collection_id="c",
            host_id_hint="HOST",
            kind="system",
        )


def test_unsupported_kind_hint_raises(tmp_path: Path) -> None:
    fake = tmp_path / "fake.hve"
    fake.write_bytes(b"\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="unsupported hive type"):
        parse_hive(fake, collection_id="c", host_id_hint="HOST", kind="bogus")

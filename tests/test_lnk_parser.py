"""Tests for the LNK parser — mocks LnkFile so we don't need raw bytes."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

import parsers.lnk as lnk_module


class _FakeLnk:
    def __init__(self, payload):
        self._payload = payload

    def process(self):
        return None

    def get_json(self, get_all=False):
        return self._payload


@pytest.fixture
def patched_lnk(monkeypatch):
    def _patch(payload):
        def factory(fhandle=None, indata=None, cp=None, allow_terminal_blocks=True):
            return _FakeLnk(payload)

        monkeypatch.setattr(lnk_module, "LnkFile", factory)

    return _patch


def test_parse_lnk_emits_file_access_with_target_and_times(tmp_path: Path, patched_lnk):
    lnk_path = tmp_path / "recent.lnk"
    lnk_path.write_bytes(b"\x00\x00")  # actual bytes irrelevant — LnkFile is mocked

    patched_lnk({
        "header": {
            "creation_time": datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc),
            "modified_time": datetime(2026, 6, 11, 12, 34, 56, tzinfo=timezone.utc),
            "accessed_time": datetime(2026, 6, 12, 1, 0, 0, tzinfo=timezone.utc),
            "file_size": 4096,
        },
        "link_info": {
            "local_base_path": r"C:\Users\alice\Documents\quarterly.xlsx",
            "location_info": {
                "drive_type": "DRIVE_FIXED",
                "drive_serial_number": "0x1AE29510",
                "volume_label": "Windows",
            },
        },
        "data": {
            "working_directory": r"C:\Users\alice\Documents",
            "command_line_arguments": None,
            "icon_location": None,
            "description": None,
            "relative_path": r"..\Documents\quarterly.xlsx",
        },
    })

    events = lnk_module.parse_lnk(
        lnk_path, collection_id="col-1", host_id_hint="MSI", user_hint="alice",
    )

    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "file_access"
    assert ev.user == "alice"
    assert ev.source_artifact == "lnk"
    assert ev.evidence["target_path"] == r"C:\Users\alice\Documents\quarterly.xlsx"
    assert ev.evidence["drive_serial"] == "0x1AE29510"
    assert ev.evidence["volume_label"] == "Windows"
    assert ev.timestamp == "2026-06-11T12:34:56Z"  # prefers modified_time
    assert "quarterly.xlsx" in ev.summary


def test_parse_lnk_falls_back_to_relative_path_when_local_base_missing(tmp_path: Path, patched_lnk):
    lnk_path = tmp_path / "fallback.lnk"
    lnk_path.write_bytes(b"\x00")

    patched_lnk({
        "header": {"creation_time": None, "modified_time": None, "accessed_time": None},
        "link_info": {},
        "data": {"relative_path": r"..\Docs\hello.txt"},
    })

    events = lnk_module.parse_lnk(lnk_path, collection_id="c", host_id_hint="H")
    assert events[0].evidence["target_path"] == r"..\Docs\hello.txt"
    assert events[0].timestamp is None
    assert events[0].timestamp_source == "none"


def test_parse_lnk_swallows_corrupt_file(tmp_path: Path, monkeypatch):
    lnk_path = tmp_path / "bad.lnk"
    lnk_path.write_bytes(b"\x00")

    class _Boom:
        def __init__(self, *a, **kw):
            raise ValueError("corrupt")

    monkeypatch.setattr(lnk_module, "LnkFile", _Boom)

    assert lnk_module.parse_lnk(lnk_path, collection_id="c", host_id_hint="H") == []

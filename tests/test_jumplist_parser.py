"""JumpList parser tests — mocks olefile + LnkFile so no OLE container is needed."""

from __future__ import annotations

from pathlib import Path

import pytest

import parsers.jumplist as jl_module


class _FakeStream:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


class _FakeOle:
    def __init__(self, streams: dict[str, bytes], has_destlist: bool = False):
        self._streams = streams
        self._has_destlist = has_destlist

    def listdir(self):
        # olefile returns each path as a list of segments — we match that.
        return [[name] for name in self._streams]

    def openstream(self, name):
        key = name if isinstance(name, str) else "/".join(name)
        return _FakeStream(self._streams[key])

    def exists(self, name):
        return name == "DestList" and self._has_destlist


class _FakeLnk:
    def __init__(self, payload):
        self._payload = payload

    def process(self):
        return None

    def get_json(self, get_all=False):
        return self._payload


@pytest.fixture
def patch_ole_lnk(monkeypatch):
    def _patch(streams: dict[str, bytes], lnk_payloads: dict[str, dict]):
        monkeypatch.setattr(jl_module.olefile, "OleFileIO", lambda path: _FakeOle(streams))

        # Map by stream contents → payload for return.
        def factory(fhandle=None, indata=None, cp=None, allow_terminal_blocks=True):
            raw = fhandle.read() if fhandle is not None else indata
            payload = lnk_payloads[raw]
            return _FakeLnk(payload)

        monkeypatch.setattr(jl_module, "LnkFile", factory)

    return _patch


def test_parse_jumplist_emits_event_per_numbered_stream(tmp_path: Path, patch_ole_lnk):
    jl_path = tmp_path / "1ced32d74a95c7bc.automaticDestinations-ms"
    jl_path.write_bytes(b"\x00")

    stream_a = b"\x01STREAM_A"
    stream_b = b"\x02STREAM_B"
    patch_ole_lnk(
        streams={"1": stream_a, "2": stream_b, "DestList": b""},
        lnk_payloads={
            stream_a: {
                "header": {"modified_time": None, "accessed_time": None, "creation_time": None},
                "link_info": {"local_base_path": r"C:\Users\alice\report.docx"},
                "data": {},
            },
            stream_b: {
                "header": {"modified_time": None, "accessed_time": None, "creation_time": None},
                "link_info": {"local_base_path": r"C:\Users\alice\notes.txt"},
                "data": {},
            },
        },
    )

    events = jl_module.parse_jumplist(
        jl_path, collection_id="col", host_id_hint="MSI", user_hint="alice",
    )

    paths = sorted(e.evidence["target_path"] for e in events)
    assert paths == [r"C:\Users\alice\notes.txt", r"C:\Users\alice\report.docx"]
    assert all(e.source_artifact == "jumplist" for e in events)
    assert all(e.user == "alice" for e in events)
    # AppID prefix from the filename should land in evidence.
    assert all(e.evidence["app_id"] == "1ced32d74a95c7bc" for e in events)
    assert all(e.evidence["app_name"] == "WordPad" for e in events)


def test_parse_jumplist_skips_non_numbered_streams(tmp_path: Path, patch_ole_lnk):
    jl_path = tmp_path / "deadbeefdeadbeef.automaticDestinations-ms"
    jl_path.write_bytes(b"\x00")

    stream_a = b"A"
    patch_ole_lnk(
        streams={"1": stream_a, "SomeOther": b"X", "metadata": b"Y"},
        lnk_payloads={
            stream_a: {
                "header": {"modified_time": None, "accessed_time": None, "creation_time": None},
                "link_info": {"local_base_path": r"C:\f.txt"},
                "data": {},
            }
        },
    )

    events = jl_module.parse_jumplist(jl_path, collection_id="c", host_id_hint="H")
    assert len(events) == 1
    assert events[0].evidence["entry_id"] == 1


def test_parse_jumplist_returns_empty_when_not_ole(tmp_path: Path, monkeypatch):
    jl_path = tmp_path / "bad.automaticDestinations-ms"
    jl_path.write_bytes(b"not OLE")

    def boom(_):
        raise ValueError("not an OLE compound file")

    monkeypatch.setattr(jl_module.olefile, "OleFileIO", boom)

    assert jl_module.parse_jumplist(jl_path, collection_id="c", host_id_hint="H") == []


def test_filetime_to_iso_handles_zero_and_overflow():
    assert jl_module._filetime_to_iso(0) is None
    assert jl_module._filetime_to_iso(-1) is None
    # FILETIME for 2025-01-01T00:00:00Z: epoch-1735689600 + 11644473600 ticks × 10M.
    iso = jl_module._filetime_to_iso(133_801_632_000_000_000)
    assert iso == "2025-01-01T00:00:00Z"

"""Tests for SAM username + SID decoding.

regipy doesn't decode the account name from the ``V`` structure, so the parser
does it. A SAM hive has no Python writer, so we craft ``V`` byte blobs and a
tiny fake hive. Verified end-to-end against the Mantooth SAM (Administrator/
Guest/Wes Mantooth/Dracula/Laurent + machine SID 3166329-3263506726-1320359247).
"""

from __future__ import annotations

import struct

from parsers.registry_sam import _decode_account_v, _machine_sid, _v_string


def _make_v(username: str, full_name: str = "") -> bytes:
    name_b = username.encode("utf-16-le")
    full_b = full_name.encode("utf-16-le")
    data = name_b + full_b
    v = bytearray(0xCC + len(data))
    struct.pack_into("<II", v, 0x0C, 0, len(name_b))             # name {offset, length}
    struct.pack_into("<II", v, 0x18, len(name_b), len(full_b))   # full name
    v[0xCC:0xCC + len(data)] = data
    return bytes(v)


class _FakeKey:
    def __init__(self, v: bytes):
        self._v = v

    def get_value(self, name):
        return self._v if name == "V" else None


class _FakeHive:
    def __init__(self, mapping: dict[str, bytes]):
        self._m = mapping

    def get_key(self, path: str):
        if path in self._m:
            return _FakeKey(self._m[path])
        raise KeyError(path)


def test_v_string_decodes_name_and_fullname():
    v = _make_v("Wes Mantooth", "Wesley Mantooth")
    assert _v_string(v, 0x0C) == "Wes Mantooth"
    assert _v_string(v, 0x18) == "Wesley Mantooth"


def test_v_string_handles_truncated_blob():
    assert _v_string(b"\x00" * 4, 0x0C) is None


def test_machine_sid_from_account_v():
    account_v = b"\x00" * 20 + struct.pack("<III", 3166329, 3263506726, 1320359247)
    hive = _FakeHive({r"\SAM\Domains\Account": account_v})
    assert _machine_sid(hive) == "S-1-5-21-3166329-3263506726-1320359247"


def test_machine_sid_absent_returns_none():
    assert _machine_sid(_FakeHive({})) is None


def test_decode_account_v_reads_username():
    key_path = r"\SAM\Domains\Account\Users\000003E8"
    hive = _FakeHive({key_path: _make_v("Wes Mantooth")})
    name, _full = _decode_account_v(hive, key_path)
    assert name == "Wes Mantooth"


def test_decode_account_v_missing_key():
    assert _decode_account_v(_FakeHive({}), None) == (None, None)

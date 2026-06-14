"""Tests for the directory hive discoverer."""

from __future__ import annotations

from pathlib import Path

import pytest

from collectors.windows.user_hives import discover_browser_histories, discover_hives


def test_flat_dump_layout(tmp_path: Path) -> None:
    (tmp_path / "SYSTEM").write_bytes(b"\x00")
    (tmp_path / "SOFTWARE").write_bytes(b"\x00")
    (tmp_path / "SAM").write_bytes(b"\x00")
    (tmp_path / "Amcache.hve").write_bytes(b"\x00")

    found = {h.kind: h for h in discover_hives(tmp_path)}
    assert set(found) == {"system", "software", "sam", "amcache"}
    for hive in found.values():
        assert hive.user_hint is None


def test_reg_save_suffix_dumps_match(tmp_path: Path) -> None:
    (tmp_path / "SYSTEM_dump.hve").write_bytes(b"\x00")
    (tmp_path / "SOFTWARE.bak").write_bytes(b"\x00")

    kinds = {h.kind for h in discover_hives(tmp_path)}
    assert kinds == {"system", "software"}


def test_users_tree_per_user_hint(tmp_path: Path) -> None:
    alice = tmp_path / "Users" / "alice"
    bob = tmp_path / "Users" / "bob" / "AppData" / "Local" / "Microsoft" / "Windows"
    alice.mkdir(parents=True)
    bob.mkdir(parents=True)
    (alice / "NTUSER.DAT").write_bytes(b"\x00")
    (bob / "UsrClass.dat").write_bytes(b"\x00")

    by_kind = {h.kind: h for h in discover_hives(tmp_path)}
    assert by_kind["ntuser"].user_hint == "alice"
    assert by_kind["usrclass"].user_hint == "bob"


def test_system_first_in_sort_order(tmp_path: Path) -> None:
    (tmp_path / "Amcache.hve").write_bytes(b"\x00")
    (tmp_path / "NTUSER.DAT").write_bytes(b"\x00")
    (tmp_path / "SYSTEM").write_bytes(b"\x00")

    kinds = [h.kind for h in discover_hives(tmp_path)]
    assert kinds[0] == "system"


def test_empty_directory_returns_empty_list(tmp_path: Path) -> None:
    assert discover_hives(tmp_path) == []


def test_not_a_directory_raises(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_bytes(b"")
    with pytest.raises(NotADirectoryError):
        discover_hives(f)


def test_evtx_files_are_not_classified_as_hives(tmp_path: Path) -> None:
    """Regression: Security.evtx / System.evtx must not be treated as hives."""
    (tmp_path / "Security.evtx").write_bytes(b"\x00")
    (tmp_path / "System.evtx").write_bytes(b"\x00")
    (tmp_path / "SYSTEM").write_bytes(b"\x00")
    kinds = {h.kind for h in discover_hives(tmp_path)}
    assert kinds == {"system"}


def test_discover_browser_histories_matches_chrome_and_edge(tmp_path: Path) -> None:
    chrome = tmp_path / "Users" / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    edge = tmp_path / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default"
    chrome.mkdir(parents=True)
    edge.mkdir(parents=True)
    (chrome / "History").write_bytes(b"\x00")
    (edge / "History").write_bytes(b"\x00")
    # Unrelated SQLite-shaped file at a non-browser path → must not match.
    (tmp_path / "History").write_bytes(b"\x00")

    found = discover_browser_histories(tmp_path)
    kinds = {h.browser_kind for h in found}
    assert kinds == {"chrome", "edge"}
    assert all(h.user_hint == "alice" for h in found)

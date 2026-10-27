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
    local = tmp_path / "Users" / "alice" / "AppData" / "Local"
    chrome = local / "Google" / "Chrome" / "User Data" / "Default"
    edge = local / "Microsoft" / "Edge" / "User Data" / "Default"
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


def test_transaction_logs_are_not_classified_as_hives(tmp_path: Path) -> None:
    """SYSTEM.LOG1 / SAM.LOG2 / Amcache.hve.LOG1 / *.blf / *.regtrans-ms sit
    beside the hives in config/ and must not be handed to regipy."""
    for name in (
        "SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2", "SOFTWARE.LOG1", "SAM.LOG2",
        "Amcache.hve", "Amcache.hve.LOG1",
        "SYSTEM{0b2e}.TM.blf", "SYSTEM{0b2e}.TMContainer00000000000000000001.regtrans-ms",
    ):
        (tmp_path / name).write_bytes(b"\x00")

    found = discover_hives(tmp_path)
    assert sorted(h.path.name for h in found) == ["Amcache.hve", "SYSTEM"]


def test_discover_recycle_bin_files_requires_dollar_i_plus_six_chars(tmp_path: Path) -> None:
    from collectors.windows.user_hives import discover_recycle_bin_files

    bin_dir = tmp_path / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
    bin_dir.mkdir(parents=True)
    names = ("$IABC123.txt", "$Ixyz789", "$I30", "$Iwhatever.log", "$RABC123.txt", "desktop.ini")
    for name in names:
        (bin_dir / name).write_bytes(b"\x00")

    names = sorted(f.path.name for f in discover_recycle_bin_files(tmp_path))
    assert names == ["$IABC123.txt", "$Ixyz789"]

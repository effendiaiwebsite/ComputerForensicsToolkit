"""Tests for the IPC dispatcher."""

from __future__ import annotations

import pytest

from core.ipc import Dispatcher


def test_dispatcher_routes_to_registered_handler() -> None:
    d = Dispatcher()
    d.register("echo", lambda req: {"echoed": req.get("payload")})
    result = d.dispatch({"op": "echo", "payload": "hello"})
    assert result == {"ok": True, "echoed": "hello"}


def test_dispatcher_unknown_op_returns_error() -> None:
    d = Dispatcher()
    result = d.dispatch({"op": "nope"})
    assert result["ok"] is False
    assert "unknown op" in result["error"]


def test_dispatcher_missing_op_returns_error() -> None:
    d = Dispatcher()
    result = d.dispatch({})
    assert result["ok"] is False
    assert "missing" in result["error"]


def test_dispatcher_non_string_op_returns_error() -> None:
    d = Dispatcher()
    result = d.dispatch({"op": 123})
    assert result["ok"] is False


def test_dispatcher_handler_exception_becomes_error() -> None:
    d = Dispatcher()

    def boom(_req: dict) -> dict:
        raise ValueError("nope")

    d.register("boom", boom)
    result = d.dispatch({"op": "boom"})
    assert result["ok"] is False
    assert "ValueError" in result["error"]
    assert "nope" in result["error"]


def test_dispatcher_rejects_duplicate_registration() -> None:
    d = Dispatcher()
    d.register("x", lambda r: {})
    with pytest.raises(ValueError):
        d.register("x", lambda r: {})


def test_dispatcher_handler_returning_non_dict_is_error() -> None:
    d = Dispatcher()
    d.register("bad", lambda r: "not a dict")  # type: ignore[arg-type,return-value]
    result = d.dispatch({"op": "bad"})
    assert result["ok"] is False
    assert "non-dict" in result["error"]

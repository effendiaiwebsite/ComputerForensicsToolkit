"""JSON-over-stdio IPC with the desktop shell.

Protocol
--------
Requests: one JSON object per line on stdin. Required field ``op``; optional
``request_id`` is echoed back for correlation; any other fields are passed to
the handler.

Responses: one JSON object per line on stdout. Always carries ``ok`` (bool).
On success, response fields are handler-specific. On failure, an ``error``
string explains the cause. The ``request_id`` is echoed when present.

Logging (future): the sidecar uses stderr exclusively, leaving stdout for the
protocol stream.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

Handler = Callable[[dict[str, Any]], dict[str, Any]]


class Dispatcher:
    """Maps op names to handler callables."""

    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}

    def register(self, op: str, handler: Handler) -> None:
        if op in self._handlers:
            raise ValueError(f"handler for {op!r} already registered")
        self._handlers[op] = handler

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        if not isinstance(op, str):
            return {"ok": False, "error": "missing or non-string 'op' field"}
        handler = self._handlers.get(op)
        if handler is None:
            return {"ok": False, "error": f"unknown op: {op!r}"}
        try:
            result = handler(request)
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if not isinstance(result, dict):
            return {"ok": False, "error": f"handler for {op!r} returned non-dict"}
        result.setdefault("ok", True)
        return result


def serve_stdio(dispatcher: Dispatcher) -> None:
    """Read JSON-lines requests from stdin and write JSON-lines responses to stdout."""
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            request = json.loads(stripped)
        except json.JSONDecodeError as exc:
            _write({"ok": False, "error": f"invalid JSON: {exc}"})
            continue
        if not isinstance(request, dict):
            _write({"ok": False, "error": "request must be a JSON object"})
            continue
        response = dispatcher.dispatch(request)
        if (rid := request.get("request_id")) is not None:
            response.setdefault("request_id", rid)
        _write(response)


def _write(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()

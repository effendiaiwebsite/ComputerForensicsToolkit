"""Helpers shared by the regipy-driven hive parsers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def flatten_persistence_values(payload: dict[str, dict[str, Any]]) -> Iterable[tuple[str, str, dict[str, Any], list[dict[str, Any]]]]:
    """Yield ``(key_path, last_write, value_dict, raw_values)`` for the standard
    "Run-key-style" output shape used by regipy's persistence plugins.

    Input shape::

        {
          "\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run": {
            "timestamp": "2025-...",
            "values": [
              {"name": "OneDrive", "value": "...", "value_type": "REG_SZ"},
              ...
            ]
          },
          ...
        }
    """
    for key_path, info in (payload or {}).items():
        if not isinstance(info, dict):
            continue
        last_write = info.get("timestamp") or info.get("last_write") or None
        values = info.get("values") or []
        flat = {v.get("name"): v.get("value") for v in values if isinstance(v, dict)}
        yield key_path, last_write, flat, values


def short_path(key_path: str) -> str:
    """Last two segments of a registry path, for compact summaries."""
    parts = [p for p in key_path.replace("/", "\\").split("\\") if p]
    return "\\".join(parts[-2:]) if parts else key_path

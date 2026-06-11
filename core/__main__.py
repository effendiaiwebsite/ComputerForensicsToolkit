"""Sidecar entry point: starts the IPC dispatcher and serves over stdio.

Run with: ``python -m core``
"""

from __future__ import annotations

import sys
from typing import Any

from core import SCHEMA_VERSION, __version__
from core.ipc import Dispatcher, serve_stdio


def _ping(_request: dict[str, Any]) -> dict[str, Any]:
    return {
        "sidecar_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
    }


def build_dispatcher() -> Dispatcher:
    dispatcher = Dispatcher()
    dispatcher.register("ping", _ping)
    return dispatcher


def main() -> None:
    serve_stdio(build_dispatcher())


if __name__ == "__main__":
    main()

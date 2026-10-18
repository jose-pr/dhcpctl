"""`dhcpctl backends`: the schemes a URI may name."""

from __future__ import annotations

import json

from duho import Cmd

from .._registry import backend_names, get_backend

__all__ = ["Backends"]


class Backends(Cmd):
    """List the registered backends: scheme, class and the settings its URI takes."""

    _parsername_ = "backends"

    as_json: bool = False
    "Print a JSON list of {scheme, class, settings} instead of a table"
    ("--json",)

    def __call__(self) -> int:
        rows = []
        for scheme in backend_names():
            backend = get_backend(scheme)
            rows.append(
                {
                    "scheme": scheme,
                    "class": f"{backend.__module__}.{backend.__qualname__}",
                    "settings": sorted(backend.SETTINGS),
                }
            )
        if self.as_json:
            print(json.dumps(rows, indent=2))
            return 0
        for row in rows:
            print(f"{row['scheme']:10} {row['class']:45} {', '.join(row['settings'])}")
        return 0

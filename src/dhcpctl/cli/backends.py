"""`dhcpctl backends`: the schemes a URI may name."""

from __future__ import annotations

from duho import Cmd, OutputArgs

from .._registry import backend_names, get_backend

__all__ = ["Backends"]


class Backends(OutputArgs, Cmd):
    """List the registered backends: scheme, class and the settings its URI takes."""

    _parsername_ = "backends"

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
        self._output_(rows, text=_table)
        return 0


def _table(rows: list) -> str:
    return "\n".join(
        f"{row['scheme']:10} {row['class']:45} {', '.join(row['settings'])}"
        for row in rows
    )

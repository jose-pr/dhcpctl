"""Configured paths: local, or any URI pathapi-uri can open."""

from __future__ import annotations

from typing import Union

from pathapi import LocalPath, Path

__all__ = ["parse_path"]


def parse_path(path: Union[str, Path]) -> Path:
    """A bare path is local, `scheme:` is a URI.

    A single-letter scheme is a Windows drive (`C:\\srv`), not a URI: real URI
    schemes are at least two characters.
    """
    if isinstance(path, Path):
        return path
    text = str(path)
    scheme, sep, _ = text.partition(":")
    if not sep or len(scheme) < 2 or not scheme.isalnum():
        return LocalPath(text)
    from uripath import URIPath

    return URIPath(text)

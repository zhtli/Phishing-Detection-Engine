"""Shared helper for the vendored DomainRadar extractor."""
__author__ = "Ondřej Ondryáš <xondry02@vut.cz>"

from typing import Any


def get_safe(data: dict, path: str) -> Any | None:
    """Get a value from a nested dictionary, returning None if the path doesn't exist."""
    if data is None:
        return None
    try:
        for key in path.split("."):
            if data is None:
                return None
            data = data[key]
        return data
    except (KeyError, TypeError):
        return None

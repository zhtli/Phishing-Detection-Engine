# Portions of this file are derived from DomainRadar
# (https://github.com/nesfit/domainradar), Copyright (c) 2024 FIT BUT, FIT CTU,
# licensed under BSD-3-Clause. See THIRD_PARTY_NOTICES at the repository root.
"""Shared helper for the domain feature extractor.

Originally authored by Ondřej Ondryáš <xondry02@vut.cz> as part of DomainRadar."""

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

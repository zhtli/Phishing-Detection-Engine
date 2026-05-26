"""Central logging configuration for the phishing engine.

Library modules log via ``logging.getLogger(__name__)`` and never install handlers
(the package root gets a ``NullHandler`` in ``phishing_engine/__init__.py``). Entry
points — the CLIs and the API — call :func:`configure_logging` once to attach a stderr
handler so those records are actually emitted.

Level defaults to ``INFO`` and can be overridden with the ``PHISHING_ENGINE_LOG_LEVEL``
environment variable (e.g. ``DEBUG``) or the ``level`` argument.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional, Union

ROOT_LOGGER_NAME = "phishing_engine"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

_configured = False


def _resolve_level(level: Optional[Union[int, str]]) -> int:
    """Turn an explicit level / the env var / the default into a numeric level."""
    if level is None:
        level = os.getenv("PHISHING_ENGINE_LOG_LEVEL", "INFO")
    if isinstance(level, str):
        resolved = logging.getLevelName(level.upper())
        return resolved if isinstance(resolved, int) else logging.INFO
    return level


def configure_logging(level: Optional[Union[int, str]] = None, *, force: bool = False) -> None:
    """Attach a stderr stream handler to the ``phishing_engine`` logger (idempotent).

    ``level`` overrides the default; otherwise ``PHISHING_ENGINE_LOG_LEVEL`` is consulted,
    falling back to ``INFO``. Calling more than once in a process is a no-op unless
    ``force`` is set, so importing several entry points stays safe.
    """
    global _configured
    if _configured and not force:
        return

    numeric_level = _resolve_level(level)
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(numeric_level)

    # Drop the package NullHandler and any stream handler we installed previously, so
    # repeated/forced calls don't emit each record twice. Foreign handlers are left alone.
    for existing in list(logger.handlers):
        if isinstance(existing, (logging.NullHandler, logging.StreamHandler)):
            logger.removeHandler(existing)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)
    logger.propagate = False
    _configured = True

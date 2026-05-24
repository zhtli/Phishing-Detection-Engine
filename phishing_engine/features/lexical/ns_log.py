"""Minimal logger factory for the vendored lexical analyzer.

Returns a quiet, no-side-effect logger (library convention: a NullHandler that the host
application can override). The original wrote rotating log files into the package dir;
that side-effect was removed during vendoring.
"""
import logging


def NsLog(modulename):
    logger = logging.getLogger(f"phishing_engine.lexical.{modulename}")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger

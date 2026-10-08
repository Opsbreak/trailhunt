"""Filesystem path helpers."""

from __future__ import annotations

import os

__all__ = ["display_path", "long_path"]

_EXTENDED = "\\\\?\\"  # the Windows extended-length path prefix: \\?\


def long_path(path: str) -> str:
    """On Windows, use an extended-length path for deep trees such as
    ``AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD`` so they work without
    the LongPathsEnabled registry setting."""
    if os.name != "nt" or path.startswith(_EXTENDED):
        return path
    full = os.path.abspath(path)
    if full.startswith("\\\\"):  # UNC share: \\server\share -> \\?\UNC\server\share
        return _EXTENDED + "UNC\\" + full[2:]
    return _EXTENDED + full


def display_path(path: str) -> str:
    if path.startswith(_EXTENDED + "UNC\\"):
        return "\\\\" + path[len(_EXTENDED) + 4 :]
    return path[len(_EXTENDED) :] if path.startswith(_EXTENDED) else path

"""Time and duration helpers.

Event times are carried internally as float UTC epoch seconds, which keeps the
hot path (window arithmetic, heap ordering) cheap.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$")
_PART_RE = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d|w)")
_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "w": 604800.0, None: 1.0}


class DurationError(ValueError):
    pass


def parse_duration(value: object) -> float:
    """Parse ``"30s"``, ``"5m"``, ``"1h"``, ``"7d"``, ``"2w"`` or a bare number of seconds."""
    if isinstance(value, bool):
        raise DurationError(f"invalid duration {value!r}")
    if isinstance(value, (int, float)):
        if value < 0:
            raise DurationError(f"duration must be >= 0, got {value!r}")
        return float(value)
    if not isinstance(value, str):
        raise DurationError(f"invalid duration {value!r}")
    m = _DURATION_RE.match(value)
    if m:
        return float(m.group(1)) * _UNITS[m.group(2)]
    compact = value.strip().replace(" ", "")
    parts = _PART_RE.findall(compact)
    if not parts or "".join(n + u for n, u in parts) != compact:
        raise DurationError(f"invalid duration {value!r} (expected e.g. 30s, 5m, 1h30m, 7d)")
    return sum(float(n) * _UNITS[u] for n, u in parts)


def format_duration(seconds: float) -> str:
    seconds = float(seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{int(seconds // size)}{unit}"
    if seconds == int(seconds):
        return f"{int(seconds)}s"
    return f"{seconds:g}s"


_FAST_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f")


def parse_time(value: object) -> float | None:
    """Parse a CloudTrail / ISO-8601 timestamp (or epoch number) to UTC epoch seconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):  # YAML loaders turn timestamps into datetimes
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).timestamp()
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v  # tolerate epoch milliseconds
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    # Fast path for the canonical CloudTrail form 2024-01-02T03:04:05Z
    if len(s) == 20 and s[10] == "T" and s[19] == "Z":
        try:
            return datetime(
                int(s[0:4]),
                int(s[5:7]),
                int(s[8:10]),
                int(s[11:13]),
                int(s[14:16]),
                int(s[17:19]),
                tzinfo=timezone.utc,
            ).timestamp()
        except ValueError:
            return None
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        dt = None
        for fmt in _FAST_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            # fromisoformat on 3.10 rejects fractional seconds that are not 3 or 6 digits
            m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$", s)
            if not m:
                return None
            tz = m.group(2) or "+00:00"
            if tz == "Z":
                tz = "+00:00"
            elif ":" not in tz:
                tz = tz[:3] + ":" + tz[3:]
            try:
                dt = datetime.fromisoformat(m.group(1).replace(" ", "T") + tz)
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def iso(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_cli_time(value: str) -> float:
    """Parse ``--since/--until`` values: ISO timestamps or dates."""
    ts = parse_time(value)
    if ts is None and re.match(r"^\d{4}-\d{2}-\d{2}$", value.strip()):
        ts = parse_time(value.strip() + "T00:00:00Z")
    if ts is None:
        raise ValueError(f"cannot parse time {value!r} (use ISO-8601, e.g. 2026-01-31T12:00:00Z)")
    return ts

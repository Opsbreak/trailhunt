"""Dotted field paths with list traversal and value transforms.

A path such as ``requestParameters.ipPermissions.items.ipRanges.items.cidrIp``
walks dictionaries key by key. When a list is met, every element is visited
(so the path above yields every CIDR of every permission). Numeric segments
index into lists (``resources.0.ARN``).

A segment may carry ``|transform`` suffixes applied to the value(s) resolved
so far, e.g. ``requestParameters.policyDocument|json.Statement.Principal.AWS|account``.

Transforms: json, lower, upper, str, len, account, net16, net24.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

_MISSING = object()
_ACCOUNT_RE = re.compile(r"^\d{12}$")


class PathError(ValueError):
    pass


def _t_json(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    s = v.strip()
    if s.startswith(("%7B", "%7b", "%5B", "%5b")):
        s = unquote(s)
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return _MISSING


def _t_lower(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def _t_upper(v: Any) -> Any:
    return v.upper() if isinstance(v, str) else v


def _t_str(v: Any) -> Any:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, separators=(",", ":"))
    return str(v)


def _t_len(v: Any) -> Any:
    if isinstance(v, (list, dict, str)):
        return len(v)
    return _MISSING


def _t_account(v: Any) -> Any:
    """Extract the 12-digit account id from an ARN or bare account id. ``*`` passes through."""
    if not isinstance(v, str):
        if isinstance(v, int):
            v = f"{v:012d}"
        else:
            return _MISSING
    s = v.strip()
    if s == "*":
        return "*"
    if _ACCOUNT_RE.match(s):
        return s
    if s.startswith("arn:"):
        parts = s.split(":", 5)
        if len(parts) >= 5 and _ACCOUNT_RE.match(parts[4]):
            return parts[4]
    return _MISSING


@lru_cache(maxsize=65536)
def parse_ip(s: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP address (cached: CloudTrail repeats the same addresses a lot)."""
    try:
        return ipaddress.ip_address(s.strip())
    except ValueError:
        return None


@lru_cache(maxsize=65536)
def _net_cached(s: str, v4: int, v6: int) -> str | None:
    addr = parse_ip(s)
    if addr is None:
        return None
    prefix = v4 if addr.version == 4 else v6
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def _net(v: Any, v4: int, v6: int) -> Any:
    if not isinstance(v, str):
        return _MISSING
    r = _net_cached(v, v4, v6)
    return _MISSING if r is None else r


TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "json": _t_json,
    "lower": _t_lower,
    "upper": _t_upper,
    "str": _t_str,
    "len": _t_len,
    "account": _t_account,
    "net16": lambda v: _net(v, 16, 48),
    "net24": lambda v: _net(v, 24, 64),
}

# Transforms that operate on a whole (list) node rather than on each element.
_NODE_TRANSFORMS = {"len"}

Segment = tuple[str, tuple[str, ...]]


@lru_cache(maxsize=4096)
def parse_path(path: str) -> tuple[Segment, ...]:
    if not isinstance(path, str) or not path.strip():
        raise PathError("field path must be a non-empty string")
    segments: list[Segment] = []
    for raw in path.split("."):
        parts = raw.split("|")
        key = parts[0]
        transforms = tuple(p.strip() for p in parts[1:])
        if key == "" and not transforms:
            raise PathError(f"empty segment in field path {path!r}")
        for t in transforms:
            if t not in TRANSFORMS:
                raise PathError(
                    f"unknown transform {t!r} in field path {path!r} (known: {', '.join(sorted(TRANSFORMS))})"
                )
        segments.append((key, transforms))
    return tuple(segments)


def _apply(t: str, nodes: list[Any]) -> list[Any]:
    fn = TRANSFORMS[t]
    out: list[Any] = []
    if t in _NODE_TRANSFORMS:
        for n in nodes:
            r = fn(n)
            if r is not _MISSING:
                out.append(r)
        return out
    for n in nodes:
        if isinstance(n, list):
            for item in _flatten(n):
                r = fn(item)
                if r is not _MISSING:
                    out.append(r)
        else:
            r = fn(n)
            if r is not _MISSING:
                out.append(r)
    return out


def _flatten(v: Any) -> list[Any]:
    return _flatten_ordered(v) if isinstance(v, list) else [v]


def _flatten_ordered(v: list[Any]) -> list[Any]:
    out: list[Any] = []
    for item in v:
        if isinstance(item, list):
            out.extend(_flatten_ordered(item))
        else:
            out.append(item)
    return out


def resolve_segments(root: Any, segments: tuple[Segment, ...], start: int = 0) -> list[Any]:
    """Resolve parsed segments against ``root``; returns a flat list of leaf values (no ``None``)."""
    nodes: list[Any] = [root]
    for key, transforms in segments[start:]:
        if key:
            nxt: list[Any] = []
            for n in nodes:
                if isinstance(n, dict):
                    v = n.get(key, _MISSING)
                    if v is not _MISSING and v is not None:
                        nxt.append(v)
                elif isinstance(n, list):
                    if key.isdigit():
                        idx = int(key)
                        if idx < len(n):
                            v = n[idx]
                            if v is not None:
                                nxt.append(v)
                        continue
                    for item in _flatten_ordered(n):
                        if isinstance(item, dict):
                            v = item.get(key, _MISSING)
                            if v is not _MISSING and v is not None:
                                nxt.append(v)
            nodes = nxt
            if not nodes:
                return []
        for t in transforms:
            nodes = _apply(t, nodes)
            if not nodes:
                return []
    out: list[Any] = []
    for n in nodes:
        if isinstance(n, list):
            out.extend(x for x in _flatten_ordered(n) if x is not None)
        else:
            out.append(n)
    return out


def resolve(root: Any, path: str) -> list[Any]:
    return resolve_segments(root, parse_path(path))

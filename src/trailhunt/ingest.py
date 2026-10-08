"""Streaming ingestion of CloudTrail logs.

Supported inputs:

* CloudTrail delivery files ``{"Records": [...]}``, plain or gzip.
* JSON Lines / NDJSON (one event per line; CloudTrail Lake / Athena exports),
  plain or gzip - streamed line by line, never fully loaded.
* A JSON array of events, or a single event object.
* Directories (walked recursively; CloudTrail digest files are skipped).
* ``-`` for stdin (gzip auto-detected).

Files from a directory are ordered by the delivery timestamp embedded in
CloudTrail object names (``..._CloudTrail_<region>_YYYYMMDDTHHMMZ_...``) and
then by path, so a typical ``AWSLogs/`` tree is read in near-chronological
order across regions. A bounded reorder buffer (:class:`ReorderBuffer`) then
restores strict ordering for the remaining jitter.
"""

from __future__ import annotations

import gzip
import heapq
import io
import json
import os
import re
import sys
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import IO, Any

from trailhunt.event import Event
from trailhunt.pathutil import display_path, long_path

_CT_NAME_TS = re.compile(r"_(\d{8}T\d{4})Z_")
_EXTENSIONS = (".json", ".json.gz", ".jsonl", ".jsonl.gz", ".ndjson", ".ndjson.gz", ".gz")


@dataclass
class IngestStats:
    files: int = 0
    records: int = 0
    events: int = 0
    malformed: int = 0
    duplicates: int = 0
    late: int = 0
    filtered: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "records": self.records,
            "events": self.events,
            "malformed": self.malformed,
            "duplicates": self.duplicates,
            "late": self.late,
            "filtered": self.filtered,
            "errors": self.errors[:20],
        }


def _file_sort_key(path: str) -> tuple[str, str]:
    m = _CT_NAME_TS.search(os.path.basename(path))
    return (m.group(1) if m else "", path)


def discover_files(path: str) -> list[str]:
    """Return candidate log files under ``path`` in near-chronological order."""
    if os.path.isfile(long_path(path)):
        return [long_path(path)]
    found: list[str] = []
    for root, dirs, files in os.walk(long_path(path)):
        dirs[:] = sorted(d for d in dirs if d != "CloudTrail-Digest" and not d.startswith("."))
        for name in files:
            low = name.lower()
            if "_cloudtrail-digest_" in low or not low.endswith(_EXTENSIONS):
                continue
            found.append(os.path.join(root, name))
    found.sort(key=_file_sort_key)
    return found


def _open_text(path: str) -> IO[str]:
    with open(path, "rb") as fh:
        magic = fh.read(2)
    if magic == b"\x1f\x8b":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8-sig", errors="replace")


def _stdin_text() -> IO[str]:
    buf = sys.stdin.buffer
    head = buf.peek(2)[:2] if hasattr(buf, "peek") else b""
    if head == b"\x1f\x8b":
        return io.TextIOWrapper(gzip.GzipFile(fileobj=buf), encoding="utf-8", errors="replace")
    return io.TextIOWrapper(buf, encoding="utf-8-sig", errors="replace")


def _looks_like_event(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "Records" not in obj
        and ("eventTime" in obj or "eventName" in obj or "eventtime" in obj or "eventJson" in obj)
    )


def iter_records_from_stream(fh: IO[str], source: str, stats: IngestStats) -> Iterator[dict[str, Any]]:
    """Yield raw records from a text stream, auto-detecting the document layout."""
    first = ""
    for line in fh:
        if line.strip():
            first = line
            break
    if not first:
        return
    try:
        obj = json.loads(first)
    except ValueError:
        obj = None
    if _looks_like_event(obj):
        # JSON Lines: stream the rest of the file line by line.
        yield obj
        for lineno, line in enumerate(fh, start=2):
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                stats.malformed += 1
                if len(stats.errors) < 50:
                    stats.errors.append(f"{source}:{lineno}: invalid JSON line")
                continue
            if isinstance(rec, dict):
                yield rec
            else:
                stats.malformed += 1
        return
    text = first + fh.read()
    try:
        doc = json.loads(text)
    except ValueError as exc:
        stats.malformed += 1
        stats.errors.append(f"{source}: not valid JSON / JSON Lines ({exc.msg} at line {exc.lineno})")
        return
    if isinstance(doc, dict) and isinstance(doc.get("Records"), list):
        records: Iterable[Any] = doc["Records"]
    elif isinstance(doc, list):
        records = doc
    elif _looks_like_event(doc):
        records = [doc]
    else:
        stats.malformed += 1
        stats.errors.append(f"{source}: JSON document has no 'Records' array")
        return
    for rec in records:
        if isinstance(rec, dict):
            yield rec
        else:
            stats.malformed += 1


def iter_records(paths: Iterable[str], stats: IngestStats | None = None) -> Iterator[dict[str, Any]]:
    stats = stats if stats is not None else IngestStats()
    for p in paths:
        if p == "-":
            stats.files += 1
            yield from iter_records_from_stream(_stdin_text(), "<stdin>", stats)
            continue
        if not os.path.exists(long_path(p)):
            stats.errors.append(f"{p}: no such file or directory")
            continue
        for f in discover_files(p):
            stats.files += 1
            try:
                with _open_text(f) as fh:
                    yield from iter_records_from_stream(fh, display_path(f), stats)
            except (OSError, EOFError, gzip.BadGzipFile) as exc:
                stats.malformed += 1
                stats.errors.append(f"{display_path(f)}: {exc}")


class ReorderBuffer:
    """Bounded min-heap that turns a nearly sorted event stream into a sorted one.

    Events are released once more than ``capacity`` are buffered. An event
    older than the last released one is *late*: it is still released (in
    arrival order) and counted, so correlation degrades gracefully instead of
    dropping data.
    """

    def __init__(self, capacity: int = 20000) -> None:
        self.capacity = max(1, capacity)
        self._heap: list[tuple[float, int, Event]] = []
        self._seq = 0
        self.watermark = float("-inf")
        self.late = 0

    def push(self, ev: Event) -> Iterator[Event]:
        if ev.ts < self.watermark:
            self.late += 1
        heapq.heappush(self._heap, (ev.ts, self._seq, ev))
        self._seq += 1
        while len(self._heap) > self.capacity:
            yield self._pop()

    def _pop(self) -> Event:
        ts, _, ev = heapq.heappop(self._heap)
        if ts > self.watermark:
            self.watermark = ts
        return ev

    def drain(self) -> Iterator[Event]:
        while self._heap:
            yield self._pop()


class _SeenIds:
    """Bounded LRU set of eventIDs used to drop duplicate deliveries."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._d: OrderedDict[str, None] = OrderedDict()

    def seen(self, key: str) -> bool:
        d = self._d
        if key in d:
            d.move_to_end(key)
            return True
        d[key] = None
        if len(d) > self.capacity:
            d.popitem(last=False)
        return False


def iter_events(
    paths: Iterable[str],
    stats: IngestStats | None = None,
    *,
    since: float | None = None,
    until: float | None = None,
    reorder: int = 20000,
    dedup: int = 200000,
) -> Iterator[Event]:
    """Yield normalized, time-ordered, de-duplicated events from ``paths``."""
    stats = stats if stats is not None else IngestStats()
    buf = ReorderBuffer(reorder)
    seen = _SeenIds(dedup) if dedup > 0 else None
    for rec in iter_records(paths, stats):
        stats.records += 1
        ev = Event.from_record(rec)
        if ev is None:
            stats.malformed += 1
            continue
        if (since is not None and ev.ts < since) or (until is not None and ev.ts >= until):
            stats.filtered += 1
            continue
        if seen is not None and ev.event_id and seen.seen(ev.event_id):
            stats.duplicates += 1
            continue
        for out in buf.push(ev):
            stats.events += 1
            yield out
    for out in buf.drain():
        stats.events += 1
        yield out
    stats.late = buf.late


def events_from_records(records: Iterable[dict[str, Any]]) -> list[Event]:
    """Normalize and sort in-memory records (used by rule tests and the API)."""
    out = [e for e in (Event.from_record(dict(r)) for r in records) if e is not None]
    out.sort(key=lambda e: e.ts)
    return out

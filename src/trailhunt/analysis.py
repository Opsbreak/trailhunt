"""``timeline`` and ``stats`` analyses."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from trailhunt.engine import Engine, Finding, sort_findings
from trailhunt.event import Event, EventRef
from trailhunt.rules import Rule
from trailhunt.timeutil import format_duration, iso

BAR_WIDTH = 40


def _bar(n: int, peak: int, width: int = BAR_WIDTH) -> str:
    if peak <= 0:
        return ""
    filled = max(1, round(width * n / peak)) if n else 0
    return "#" * filled


# --------------------------------------------------------------------------- timeline


def actor_matches(ev: Event, needle: str) -> bool:
    if needle in (ev.actor, ev.actor_name, ev.access_key_id, ev.session_name):
        return True
    ui = ev.raw.get("userIdentity")
    return isinstance(ui, dict) and needle in (ui.get("arn"), ui.get("principalId"), ui.get("userName"))


@dataclass
class Timeline:
    needle: str
    actors: Counter[str] = field(default_factory=Counter)
    events: list[EventRef] = field(default_factory=list)
    ips: Counter[str] = field(default_factory=Counter)
    regions: Counter[str] = field(default_factory=Counter)
    agents: Counter[str] = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)
    total_events: int = 0


def build_timeline(events: Iterable[Event], rules: list[Rule], needle: str) -> Timeline:
    tl = Timeline(needle)
    engine = Engine(rules)
    ids: set[str] = set()
    findings: list[Finding] = []
    for ev in events:
        tl.total_events += 1
        if actor_matches(ev, needle):
            tl.actors[ev.actor] += 1
            tl.events.append(ev.ref())
            tl.ips[ev.src_ip] += 1
            tl.regions[ev.region] += 1
            tl.agents[ev.ua_family] += 1
            if ev.event_id:
                ids.add(ev.event_id)
        findings.extend(engine.process(ev))
    findings.extend(engine.finish())
    actor_keys = set(tl.actors)
    tl.findings = sort_findings(
        [f for f in findings if f.actor in actor_keys or any(e.event_id in ids for e in f.events)]
    )
    return tl


def render_timeline(
    tl: Timeline, *, bucket: float = 3600.0, limit: int = 400, display_since: float | None = None
) -> str:
    """Render a timeline. ``display_since`` hides older detail while keeping the full analysis."""
    out: list[str] = []
    if not tl.events:
        return f"No events found for actor {tl.needle!r} (searched {tl.total_events} events).\n"
    evs = tl.events
    out.append(f"Timeline for {tl.needle}")
    for a, n in tl.actors.most_common():
        out.append(f"  actor      : {a} ({n} events)")
    out.append(f"  events     : {len(evs)}   first: {iso(evs[0].ts)}   last: {iso(evs[-1].ts)}")
    out.append("  source IPs : " + ", ".join(f"{ip} ({n})" for ip, n in tl.ips.most_common(6)))
    out.append("  regions    : " + ", ".join(f"{r} ({n})" for r, n in tl.regions.most_common(8)))
    out.append("  clients    : " + ", ".join(f"{u} ({n})" for u, n in tl.agents.most_common(6)))
    out.append(f"  findings   : {len(tl.findings)}")
    if display_since is not None:
        evs = [e for e in evs if e.ts >= display_since]
        out.append(f"  showing    : events since {iso(display_since)} ({len(evs)})")
        if not evs:
            return "\n".join(out) + "\n"
    out.append("")

    # Activity histogram, with finding markers per bucket.
    buckets: Counter[int] = Counter(int(e.ts // bucket) for e in evs)
    marks: dict[int, list[Finding]] = {}
    for f in tl.findings:
        if display_since is None or f.last_ts >= display_since:
            marks.setdefault(int(f.last_ts // bucket), []).append(f)
    peak = max(buckets.values())
    out.append(f"Activity per {format_duration(bucket)} (only non-empty buckets; ! = finding)")
    for b in sorted(set(buckets) | set(marks)):
        n = buckets.get(b, 0)
        flag = "!" * min(len(marks.get(b, [])), 5)
        out.append(
            f"  {iso(b * bucket)[:16].replace('T', ' ')}  |{_bar(n, peak):<{BAR_WIDTH}}| {n:>5} {flag}"
        )
    out.append("")

    # Detailed lines: consecutive identical calls are collapsed; findings are
    # printed right after the event that completed them.
    by_last: dict[str, list[Finding]] = {}
    for f in tl.findings:
        if f.events:
            by_last.setdefault(f.events[-1].event_id, []).append(f)
    out.append("Events (consecutive identical calls collapsed)")
    printed = 0
    i = 0
    while i < len(evs) and printed < limit:
        e = evs[i]
        j = i + 1
        key = (e.service, e.event_name, e.error, e.region, e.src_ip)
        while (
            j < len(evs)
            and (evs[j].service, evs[j].event_name, evs[j].error, evs[j].region, evs[j].src_ip) == key
            and evs[j - 1].event_id not in by_last
        ):
            j += 1
        run = j - i
        times = iso(e.ts) if run == 1 else f"{iso(e.ts)} +{format_duration(round(evs[j - 1].ts - e.ts))}"
        count = f" x{run}" if run > 1 else ""
        out.append(f"  {times:<30} {e.summary}{count}  [{e.region} {e.src_ip}]")
        for k in range(i, j):
            for f in by_last.get(evs[k].event_id, []):
                out.append(f"  {'':<30} >> [{f.severity.upper()}] {f.rule_id}: {f.title}")
        printed += 1
        i = j
    if i < len(evs):
        out.append(f"  ... output limited to {limit} lines ({len(evs) - i} events not shown; use --limit)")
    shown = {fp for fl in by_last.values() for fp in (f.fingerprint for f in fl)}
    other = [f for f in tl.findings if f.fingerprint not in shown]
    if other:
        out.append("")
        out.append("Related findings completed by other actors' events")
        for f in other:
            out.append(f"  {iso(f.last_ts)}  [{f.severity.upper()}] {f.rule_id}: {f.title} (actor {f.actor})")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- stats


@dataclass
class Stats:
    total: int = 0
    first: float | None = None
    last: float | None = None
    actors: Counter[str] = field(default_factory=Counter)
    actor_types: Counter[str] = field(default_factory=Counter)
    events: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)
    regions: Counter[str] = field(default_factory=Counter)
    ips: Counter[str] = field(default_factory=Counter)
    agents: Counter[str] = field(default_factory=Counter)
    accounts: Counter[str] = field(default_factory=Counter)

    def add(self, ev: Event) -> None:
        self.total += 1
        if self.first is None or ev.ts < self.first:
            self.first = ev.ts
        if self.last is None or ev.ts > self.last:
            self.last = ev.ts
        self.actors[ev.actor] += 1
        self.actor_types[ev.actor_type] += 1
        self.events[f"{ev.service}:{ev.event_name}"] += 1
        if ev.error_code:
            self.errors[ev.error_code] += 1
        self.regions[ev.region or "-"] += 1
        self.ips[ev.src_ip or "-"] += 1
        self.agents[ev.ua_family] += 1
        acct = ev.raw.get("recipientAccountId")
        if acct:
            self.accounts[str(acct)] += 1

    def sections(self) -> list[tuple[str, Counter[str]]]:
        return [
            ("Top actors", self.actors),
            ("Actor types", self.actor_types),
            ("Top events", self.events),
            ("Error codes", self.errors),
            ("Regions", self.regions),
            ("Source IPs", self.ips),
            ("Client families", self.agents),
            ("Accounts", self.accounts),
        ]

    def to_dict(self, top: int) -> dict[str, Any]:
        return {
            "total_events": self.total,
            "first_event": iso(self.first),
            "last_event": iso(self.last),
            **{
                title.lower().replace(" ", "_"): [{"value": k, "count": n} for k, n in c.most_common(top)]
                for title, c in self.sections()
            },
        }


def compute_stats(events: Iterable[Event]) -> Stats:
    st = Stats()
    for ev in events:
        st.add(ev)
    return st


def render_stats(st: Stats, top: int = 10, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(st.to_dict(top), indent=2) + "\n"
    out = [f"{st.total} events  {iso(st.first)} .. {iso(st.last)}", ""]
    for title, counter in st.sections():
        if not counter:
            continue
        out.append(f"{title} ({len(counter)} distinct)")
        items = counter.most_common(top)
        peak = items[0][1]
        width = min(60, max(len(k) for k, _ in items))
        for k, n in items:
            label = k if len(k) <= width else k[: width - 3] + "..."
            out.append(f"  {label:<{width}}  {n:>8}  {_bar(n, peak, 30)}")
        out.append("")
    return "\n".join(out)

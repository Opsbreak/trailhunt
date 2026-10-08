"""Detection engine: one stateful detector per rule, driven by event time.

All detectors use *event time* (never wall-clock time), so results are
deterministic and identical between a live tail and a replay of old logs.

* :class:`MatchDetector` - stateless single-event predicate.
* :class:`ThresholdDetector` - sliding window per group; counts events or
  distinct values; re-arms after firing.
* :class:`SequenceDetector` - per-key state machine. For every join key it
  keeps at most one partial match *per step*, so memory is bounded by
  ``keys x steps`` no matter how noisy the stream is. Supports repeated steps
  (``count``), per-step ``within`` and a trailing ``absent`` step implemented
  with an event-time timer heap.
* :class:`NewValueDetector` - first-seen values per group after a learning
  period, with optional persisted baseline state.
"""

from __future__ import annotations

import hashlib
import heapq
import json
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from trailhunt.event import Event, EventRef
from trailhunt.rules import Rule, Step
from trailhunt.timeutil import format_duration, iso

MAX_FINDING_EVENTS = 50
SWEEP_EVERY = 5000
STATE_VERSION = 1


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    rule_type: str
    actor: str
    first_ts: float
    last_ts: float
    events: list[EventRef]
    event_count: int
    attack: list[str]
    description: str = ""
    group: dict[str, str] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "type": self.rule_type,
            "actor": self.actor,
            "first_seen": iso(self.first_ts),
            "last_seen": iso(self.last_ts),
            "attack": self.attack,
            "group": self.group,
            "details": self.details,
            "event_count": self.event_count,
            "events": [e.to_dict() for e in self.events],
            "description": self.description,
        }


def _fingerprint(rule_id: str, group: dict[str, str], parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    h.update(rule_id.encode())
    h.update(b"\x00")
    h.update(json.dumps(group, sort_keys=True).encode())
    for p in parts:
        h.update(b"\x00")
        h.update(p.encode())
    return h.hexdigest()[:24]


def _key(ev: Event, paths: tuple[str, ...]) -> tuple[str, ...] | None:
    out = []
    for p in paths:
        vals = ev.values(p)
        if not vals:
            return None
        v = vals[0]
        out.append(v if isinstance(v, str) else json.dumps(v, sort_keys=True))
    return tuple(out)


def _unique_refs(refs: Iterable[EventRef]) -> list[EventRef]:
    seen: set[str] = set()
    out: list[EventRef] = []
    for r in refs:
        k = r.event_id or f"{r.ts}:{r.event_name}"
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    out.sort(key=lambda r: r.ts)
    return out


def make_finding(
    rule: Rule,
    refs: list[EventRef],
    group: dict[str, str] | None = None,
    details: dict[str, Any] | None = None,
    fp_parts: Iterable[str] | None = None,
    actor: str | None = None,
) -> Finding:
    refs = _unique_refs(refs)
    group = group or {}
    actor = actor or group.get("actor") or (refs[0].actor if refs else "")
    parts = list(fp_parts) if fp_parts is not None else [r.event_id for r in refs]
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        rule_type=rule.type,
        actor=actor,
        first_ts=refs[0].ts if refs else 0.0,
        last_ts=refs[-1].ts if refs else 0.0,
        events=refs[:MAX_FINDING_EVENTS],
        event_count=len(refs),
        attack=list(rule.attack),
        description=rule.description,
        group=group,
        details=details or {},
        fingerprint=_fingerprint(rule.id, group, parts),
    )


class Detector:
    rule: Rule
    _suppressed: dict[tuple[str, ...], float]

    def names(self) -> frozenset[str] | None:
        return self.rule.names

    def _is_suppressed(self, ev: Event) -> bool:
        """Rule-level ``suppress``: after an alert, mute the same suppress key for a while."""
        if not self.rule.suppress:
            return False
        key = _key(ev, self.rule.suppress_by) or ("",)
        until = self._suppressed.get(key)
        return until is not None and ev.ts < until

    def _mute(self, ev: Event) -> None:
        if self.rule.suppress:
            key = _key(ev, self.rule.suppress_by) or ("",)
            self._suppressed[key] = ev.ts + self.rule.suppress

    def on_event(self, ev: Event) -> list[Finding] | None:  # pragma: no cover - interface
        raise NotImplementedError

    def advance(self, now: float) -> list[Finding] | None:
        return None

    def sweep(self, now: float) -> None:
        return None

    def has_timers(self) -> bool:
        return False


class MatchDetector(Detector):
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        assert rule.pred is not None
        self.pred = rule.pred
        self._suppressed = {}

    def on_event(self, ev: Event) -> list[Finding] | None:
        if self.pred(ev) and not self._is_suppressed(ev):
            self._mute(ev)
            return [make_finding(self.rule, [ev.ref()])]
        return None

    def sweep(self, now: float) -> None:
        if self._suppressed:
            self._suppressed = {k: t for k, t in self._suppressed.items() if t > now}


class _ThresholdGroup:
    __slots__ = ("distinct", "events", "last")

    def __init__(self) -> None:
        self.events: deque[EventRef] = deque()
        self.distinct: OrderedDict[str, EventRef] = OrderedDict()
        self.last = 0.0


class ThresholdDetector(Detector):
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        assert rule.pred is not None
        self.pred = rule.pred
        self.window = rule.window
        self.threshold = rule.threshold
        self.distinct = rule.distinct
        self.groups: dict[tuple[str, ...], _ThresholdGroup] = {}
        self._suppressed = {}

    def on_event(self, ev: Event) -> list[Finding] | None:
        if not self.pred(ev):
            return None
        key = _key(ev, self.rule.group_by)
        if key is None:
            return None
        g = self.groups.get(key)
        if g is None:
            g = self.groups[key] = _ThresholdGroup()
        g.last = ev.ts
        cutoff = ev.ts - self.window
        ref = ev.ref()
        if self.distinct is None:
            dq = g.events
            while dq and dq[0].ts < cutoff:
                dq.popleft()
            dq.append(ref)
            metric = len(dq)
        else:
            od = g.distinct
            while od:
                first_key = next(iter(od))
                if od[first_key].ts < cutoff:
                    del od[first_key]
                else:
                    break
            vals = ev.values(self.distinct)
            if not vals:
                return None
            for v in vals:
                sv = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
                if sv in od:
                    od.move_to_end(sv)
                od[sv] = ref
            metric = len(od)
        if metric < self.threshold:
            return None
        if self._is_suppressed(ev):
            del self.groups[key]
            return None
        self._mute(ev)
        group = dict(zip(self.rule.group_by, key, strict=True))
        if self.distinct is None:
            refs = list(g.events)
            details: dict[str, Any] = {
                "count": metric,
                "threshold": self.threshold,
                "window": format_duration(self.window),
            }
        else:
            refs = list(g.distinct.values())
            details = {
                "distinct_field": self.distinct,
                "distinct_count": metric,
                "threshold": self.threshold,
                "window": format_duration(self.window),
                "values": sorted(g.distinct.keys())[:25],
            }
        del self.groups[key]  # re-arm: the next alert needs a fresh window's worth of activity
        return [make_finding(self.rule, refs, group, details)]

    def sweep(self, now: float) -> None:
        cutoff = now - self.window
        stale = [k for k, g in self.groups.items() if g.last < cutoff]
        for k in stale:
            del self.groups[k]
        if self._suppressed:
            self._suppressed = {k: t for k, t in self._suppressed.items() if t > now}


class _SeqInstance:
    __slots__ = ("acc", "last", "refs", "start", "step")

    def __init__(self, step: int, start: float, last: float, refs: list[EventRef]) -> None:
        self.step = step  # index of the step this instance is waiting for
        self.start = start
        self.last = last  # time the previous step completed
        self.refs = refs
        self.acc: list[EventRef] = []  # partial matches of a repeated (count > 1) step


class SequenceDetector(Detector):
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.steps: list[Step] = rule.steps
        self.within = rule.within
        # key -> {step index -> instance waiting at that step}
        self.state: dict[tuple[str, ...], dict[int, _SeqInstance]] = {}
        self.timers: list[tuple[float, int, tuple[str, ...], int, _SeqInstance]] = []
        self._seq = 0
        self.has_absent = bool(self.steps) and self.steps[-1].absent
        # reverse order: an event must not satisfy two consecutive steps in one pass
        self._order = list(reversed(range(len(self.steps))))
        names: set[str] = set()
        self._names: frozenset[str] | None = None
        for s in self.steps:
            if s.names is None:
                break
            names |= s.names
        else:
            self._names = frozenset(names)

    def names(self) -> frozenset[str] | None:
        return self._names

    def has_timers(self) -> bool:
        return self.has_absent

    def _valid(self, inst: _SeqInstance, step: Step, now: float) -> bool:
        if now - inst.start > self.within:
            return False
        return not (step.within is not None and now - inst.last > step.within)

    def _complete_step(
        self, key: tuple[str, ...], slots: dict[int, _SeqInstance], inst: _SeqInstance, idx: int, now: float
    ) -> list[Finding] | None:
        if slots.get(idx) is inst:
            del slots[idx]
        inst.refs.extend(inst.acc)
        inst.acc = []
        inst.step = idx + 1
        inst.last = now
        if inst.step >= len(self.steps):
            if not slots:
                self.state.pop(key, None)
            return [self._finding(key, inst)]
        slots[inst.step] = inst  # replaces an older instance at the same progress
        nxt = self.steps[inst.step]
        if nxt.absent:
            assert nxt.within is not None
            self._seq += 1
            heapq.heappush(self.timers, (now + nxt.within, self._seq, key, inst.step, inst))
        return None

    def _finding(self, key: tuple[str, ...], inst: _SeqInstance) -> Finding:
        group = dict(zip(self.rule.steps[0].by or (), key, strict=True))
        details = {
            "steps": [s.name for s in self.steps],
            "within": format_duration(self.within),
        }
        if self.has_absent:
            last = self.steps[-1]
            details["absent"] = f"no '{last.name}' within {format_duration(last.within or 0)}"
        return make_finding(self.rule, inst.refs, group, details)

    def on_event(self, ev: Event) -> list[Finding] | None:
        out: list[Finding] | None = None
        now = ev.ts
        for idx in self._order:
            step = self.steps[idx]
            if step.names is not None and ev.event_name not in step.names:
                continue
            if not step.pred(ev):
                continue
            key = _key(ev, step.by or ())
            if key is None:
                continue
            if step.count > 1:
                # Greedy repeats: further matches of an already-satisfied repeated step are
                # attached to the instance now waiting for the next step (e.g. the 6th and 7th
                # failed logins before the successful one), so the finding shows them all.
                waiting = self.state.get(key, {}).get(idx + 1)
                if waiting is not None and len(waiting.refs) < MAX_FINDING_EVENTS:
                    waiting.refs.append(ev.ref())
            if idx == 0:
                slots = self.state.setdefault(key, {})
                if step.count == 1:
                    inst = _SeqInstance(0, now, now, [ev.ref()])
                    r = self._complete_step(key, slots, inst, 0, now)
                else:
                    inst = slots.get(0) or _SeqInstance(0, now, now, [])
                    slots[0] = inst
                    span = step.within if step.within is not None else self.within
                    inst.acc = [r_ for r_ in inst.acc if now - r_.ts <= span]
                    inst.acc.append(ev.ref())
                    inst.start = inst.acc[0].ts
                    r = None
                    if len(inst.acc) >= step.count:
                        done = _SeqInstance(0, inst.start, now, [])
                        done.acc = inst.acc
                        del slots[0]
                        r = self._complete_step(key, slots, done, 0, now)
                if r:
                    out = (out or []) + r
                continue
            slots_or_none = self.state.get(key)
            if not slots_or_none:
                continue
            slots = slots_or_none
            inst_or_none = slots.get(idx)
            if inst_or_none is None:
                continue
            inst = inst_or_none
            if not self._valid(inst, step, now):
                del slots[idx]
                if not slots:
                    del self.state[key]
                continue
            if step.absent:
                # the event we required NOT to happen did happen: discard the partial match
                del slots[idx]
                if not slots:
                    del self.state[key]
                continue
            inst.acc.append(ev.ref())
            if len(inst.acc) >= step.count:
                r = self._complete_step(key, slots, inst, idx, now)
                if r:
                    out = (out or []) + r
        return out

    def advance(self, now: float) -> list[Finding] | None:
        out: list[Finding] | None = None
        timers = self.timers
        while timers and timers[0][0] < now:
            _deadline, _, key, idx, inst = heapq.heappop(timers)
            slots = self.state.get(key)
            if not slots or slots.get(idx) is not inst:
                continue  # cancelled or superseded
            del slots[idx]
            if not slots:
                del self.state[key]
            inst.step = idx + 1
            out = (out or []) + [self._finding(key, inst)]
        return out

    def sweep(self, now: float) -> None:
        dead = []
        for key, slots in self.state.items():
            expired = [
                i for i, inst in slots.items() if now - inst.start > self.within and not self.steps[i].absent
            ]
            for idx in expired:
                del slots[idx]
            if not slots:
                dead.append(key)
        for k in dead:
            del self.state[k]


class NewValueDetector(Detector):
    MAX_VALUES_PER_GROUP = 5000

    def __init__(self, rule: Rule, state: dict[str, Any] | None = None) -> None:
        self.rule = rule
        self.pred = rule.pred
        self.start: float | None = None
        self.end: float | None = None
        self.groups: dict[tuple[str, ...], OrderedDict[str, float]] = {}
        if state and state.get("signature") == self.signature():
            self.start = state.get("start")
            self.end = state.get("end")
            for gk, values in state.get("groups", {}).items():
                try:
                    key = tuple(json.loads(gk))
                except ValueError:
                    continue
                od: OrderedDict[str, float] = OrderedDict(sorted(values.items(), key=lambda kv: kv[1]))
                self.groups[key] = od

    def signature(self) -> str:
        return json.dumps(
            {"group_by": list(self.rule.group_by), "value": list(self.rule.value), "match": self.rule.match},
            sort_keys=True,
            default=str,
        )

    def _candidates(self, ev: Event) -> list[str]:
        if len(self.rule.value) == 1:
            vals = ev.values(self.rule.value[0])
            out = []
            for v in vals:
                sv = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
                if sv not in out:
                    out.append(sv)
            return out
        k = _key(ev, self.rule.value)
        return ["|".join(k)] if k else []

    def on_event(self, ev: Event) -> list[Finding] | None:
        if self.pred is not None and not self.pred(ev):
            return None
        key = _key(ev, self.rule.group_by)
        if key is None:
            return None
        cands = self._candidates(ev)
        if not cands:
            return None
        if self.start is None:
            self.start = ev.ts
        if self.end is None or ev.ts > self.end:
            self.end = ev.ts
        learning = ev.ts < self.start + self.rule.baseline
        known = self.groups.get(key)
        new_group = known is None
        if known is None:
            known = self.groups[key] = OrderedDict()
        out: list[Finding] | None = None
        for c in cands:
            if c in known:
                known[c] = ev.ts
                known.move_to_end(c)
                continue
            previous = list(known.keys())
            known[c] = ev.ts
            if len(known) > self.MAX_VALUES_PER_GROUP:
                known.popitem(last=False)
            if learning or (new_group and self.rule.on_new_group == "learn"):
                continue
            group = dict(zip(self.rule.group_by, key, strict=True))
            details = {
                "field": self.rule.value[0] if len(self.rule.value) == 1 else list(self.rule.value),
                "new_value": c,
                "known_values": previous[-10:],
                "known_count": len(previous),
                "baseline_since": iso(self.start),
            }
            f = make_finding(self.rule, [ev.ref()], group, details, fp_parts=[c])
            out = (out or []) + [f]
        return out

    def export_state(self) -> dict[str, Any]:
        return {
            "signature": self.signature(),
            "start": self.start,
            "end": self.end,
            "groups": {json.dumps(list(k)): dict(v) for k, v in self.groups.items()},
        }


def make_detector(rule: Rule, state: dict[str, Any] | None = None) -> Detector:
    if rule.type == "match":
        return MatchDetector(rule)
    if rule.type == "threshold":
        return ThresholdDetector(rule)
    if rule.type == "sequence":
        return SequenceDetector(rule)
    if rule.type == "new_value":
        return NewValueDetector(rule, (state or {}).get(rule.id))
    raise ValueError(f"unknown rule type {rule.type}")


class Engine:
    """Runs a set of rules over a time-ordered event stream."""

    def __init__(self, rules: Iterable[Rule], *, state: dict[str, Any] | None = None) -> None:
        rule_state = (state or {}).get("rules", {}) if state and state.get("version") == STATE_VERSION else {}
        self.detectors: list[Detector] = [make_detector(r, rule_state) for r in rules if r.enabled]
        self.by_name: dict[str, list[Detector]] = {}
        self.wildcard: list[Detector] = []
        for d in self.detectors:
            names = d.names()
            if names is None:
                self.wildcard.append(d)
            else:
                for n in names:
                    self.by_name.setdefault(n, []).append(d)
        self.timed = [d for d in self.detectors if d.has_timers()]
        self.fingerprints: set[str] = set()
        self.events = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self._next_sweep = SWEEP_EVERY

    def _emit(self, out: list[Finding], found: list[Finding] | None) -> None:
        if not found:
            return
        for f in found:
            if f.fingerprint in self.fingerprints:
                continue
            self.fingerprints.add(f.fingerprint)
            out.append(f)

    def process(self, ev: Event) -> list[Finding]:
        out: list[Finding] = []
        self.events += 1
        if self.first_ts is None:
            self.first_ts = ev.ts
        if self.last_ts is None or ev.ts > self.last_ts:
            self.last_ts = ev.ts
        for d in self.timed:
            self._emit(out, d.advance(ev.ts))
        for d in self.by_name.get(ev.event_name, ()):
            self._emit(out, d.on_event(ev))
        for d in self.wildcard:
            self._emit(out, d.on_event(ev))
        if self.events >= self._next_sweep:
            self._next_sweep = self.events + SWEEP_EVERY
            for d in self.detectors:
                d.sweep(ev.ts)
        return out

    def finish(self) -> list[Finding]:
        """Flush timers that expired by the end of the data (pending ones are not reported)."""
        out: list[Finding] = []
        if self.last_ts is not None:
            for d in self.timed:
                self._emit(out, d.advance(self.last_ts))
        return out

    def run(self, events: Iterable[Event]) -> list[Finding]:
        out: list[Finding] = []
        for ev in events:
            out.extend(self.process(ev))
        out.extend(self.finish())
        return out

    def export_state(self, previous: dict[str, Any] | None = None) -> dict[str, Any]:
        rules: dict[str, Any] = {}
        if previous and previous.get("version") == STATE_VERSION:
            rules.update(previous.get("rules", {}))
        for d in self.detectors:
            if isinstance(d, NewValueDetector):
                rules[d.rule.id] = d.export_state()
        return {"version": STATE_VERSION, "rules": rules}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    from trailhunt.rules import SEV_RANK

    return sorted(findings, key=lambda f: (f.first_ts, -SEV_RANK[f.severity], f.rule_id))

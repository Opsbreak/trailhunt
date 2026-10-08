"""Rule model, YAML loading and schema validation.

Rules are validated with a strict hand-written schema so that typos
(``treshold:``), wrong types and bad operators are reported with the file,
rule id and exact key path instead of surfacing later as silent misses.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

import yaml

from trailhunt.fieldpath import PathError, parse_path
from trailhunt.pathutil import long_path
from trailhunt.predicate import Pred, PredicateError, compile_predicate, required_event_names
from trailhunt.timeutil import DurationError, parse_duration

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RULE_TYPES = ("match", "threshold", "sequence", "new_value")

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,79}$")
_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

_COMMON_KEYS = {
    "id",
    "title",
    "type",
    "severity",
    "description",
    "attack",
    "falsepositives",
    "references",
    "tags",
    "enabled",
    "author",
    "tests",
}
_TYPE_KEYS = {
    "match": {"match", "suppress", "suppress_by"},
    "threshold": {"match", "group_by", "window", "threshold", "distinct", "suppress", "suppress_by"},
    "sequence": {"by", "within", "steps"},
    "new_value": {"match", "group_by", "value", "baseline", "on_new_group"},
}
_STEP_KEYS = {"name", "match", "by", "within", "count", "absent"}
_REQUIRED = {
    "match": ("match",),
    "threshold": ("match", "window", "threshold"),
    "sequence": ("within", "steps"),
    "new_value": ("value", "baseline"),
}


class RuleError(ValueError):
    """Raised when one or more rules fail validation."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass
class Step:
    name: str
    match: Any
    pred: Pred
    names: frozenset[str] | None
    by: tuple[str, ...] | None
    within: float | None
    count: int = 1
    absent: bool = False


@dataclass
class Rule:
    id: str
    title: str
    type: str
    severity: str
    description: str = ""
    attack: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    source: str = "<memory>"
    match: Any = None
    pred: Pred | None = None
    names: frozenset[str] | None = None
    group_by: tuple[str, ...] = ("actor",)
    window: float = 0.0
    threshold: int = 0
    distinct: str | None = None
    within: float = 0.0
    steps: list[Step] = field(default_factory=list)
    value: tuple[str, ...] = ()
    baseline: float = 0.0
    on_new_group: str = "learn"
    suppress: float = 0.0
    suppress_by: tuple[str, ...] = ("actor",)
    tests: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def rank(self) -> int:
        return SEV_RANK[self.severity]


class _V:
    """Collects validation errors for a single rule."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.errors: list[str] = []

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{self.prefix}: {where}: {msg}" if where else f"{self.prefix}: {msg}")

    def duration(self, where: str, v: Any, *, positive: bool = True) -> float:
        try:
            d = parse_duration(v)
        except DurationError as exc:
            self.err(where, str(exc))
            return 0.0
        if positive and d <= 0:
            self.err(where, "duration must be > 0")
        return d

    def paths(self, where: str, v: Any, *, allow_empty: bool = False) -> tuple[str, ...]:
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list) or (not v and not allow_empty):
            self.err(where, "expected a field path or a list of field paths")
            return ()
        out = []
        for i, p in enumerate(v):
            try:
                parse_path(p)
                out.append(p)
            except PathError as exc:
                self.err(f"{where}[{i}]", str(exc))
        return tuple(out)

    def pred(self, where: str, node: Any) -> Pred | None:
        try:
            return compile_predicate(node, where)
        except PredicateError as exc:
            self.err("", str(exc))
            return None

    def str_list(self, where: str, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            self.err(where, "expected a list of strings")
            return []
        return list(v)


def build_rule(doc: Any, source: str = "<memory>", index: int = 0) -> tuple[Rule | None, list[str]]:
    """Validate and compile one rule document. Returns ``(rule, errors)``."""
    if not isinstance(doc, dict):
        return None, [f"{source}: document #{index + 1}: a rule must be a mapping, got {type(doc).__name__}"]
    rid = doc.get("id")
    v = _V(f"{source}: rule '{rid}'" if isinstance(rid, str) else f"{source}: document #{index + 1}")
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        v.err("id", "required; lowercase letters, digits, '.', '_' or '-' (2-80 chars)")
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        v.err("title", "required non-empty string")
    rtype = doc.get("type")
    if rtype not in RULE_TYPES:
        v.err("type", f"must be one of {', '.join(RULE_TYPES)} (got {rtype!r})")
        return None, v.errors
    sev = doc.get("severity")
    if sev not in SEVERITIES:
        v.err("severity", f"must be one of {', '.join(SEVERITIES)} (got {sev!r})")
    allowed = _COMMON_KEYS | _TYPE_KEYS[rtype]
    for k in doc:
        if k not in allowed:
            v.err(str(k), f"unknown key for a '{rtype}' rule (allowed: {', '.join(sorted(allowed))})")
    for k in _REQUIRED[rtype]:
        if k not in doc:
            v.err(k, f"required for '{rtype}' rules")
    desc = doc.get("description", "")
    if not isinstance(desc, str):
        v.err("description", "expected a string")
        desc = ""
    attack = v.str_list("attack", doc.get("attack"))
    for t in attack:
        if not _ATTACK_RE.match(t):
            v.err("attack", f"{t!r} is not a MITRE ATT&CK technique id (e.g. T1078 or T1078.004)")
    enabled = doc.get("enabled", True)
    if not isinstance(enabled, bool):
        v.err("enabled", "expected true or false")
        enabled = True

    rule = Rule(
        id=rid if isinstance(rid, str) else "?",
        title=title if isinstance(title, str) else "?",
        type=rtype,
        severity=sev if sev in SEVERITIES else "info",
        description=desc.strip(),
        attack=attack,
        falsepositives=v.str_list("falsepositives", doc.get("falsepositives")),
        references=v.str_list("references", doc.get("references")),
        tags=v.str_list("tags", doc.get("tags")),
        enabled=enabled,
        source=source,
        raw=doc,
    )

    if "match" in doc:
        rule.match = doc["match"]
        rule.pred = v.pred("match", doc["match"])
        rule.names = required_event_names(doc["match"])

    if "suppress" in doc:
        rule.suppress = v.duration("suppress", doc["suppress"])
    if "suppress_by" in doc:
        if "suppress" not in doc:
            v.err("suppress_by", "requires 'suppress'")
        rule.suppress_by = v.paths("suppress_by", doc["suppress_by"])

    if rtype in ("threshold", "new_value"):
        rule.group_by = v.paths("group_by", doc.get("group_by", ["actor"]), allow_empty=rtype == "new_value")

    if rtype == "threshold":
        if "window" in doc:  # missing required keys are reported once, above
            rule.window = v.duration("window", doc["window"])
        if "threshold" in doc:
            th = doc["threshold"]
            if isinstance(th, bool) or not isinstance(th, int) or th < 1:
                v.err("threshold", "expected an integer >= 1")
            else:
                rule.threshold = th
        if "distinct" in doc:
            d = v.paths("distinct", doc["distinct"])
            if len(d) != 1:
                v.err("distinct", "expected a single field path")
            else:
                rule.distinct = d[0]

    elif rtype == "new_value":
        if "value" in doc:
            rule.value = v.paths("value", doc["value"])
        if "baseline" in doc:
            rule.baseline = v.duration("baseline", doc["baseline"], positive=False)
        rule.on_new_group = doc.get("on_new_group", "learn")
        if rule.on_new_group not in ("learn", "alert"):
            v.err("on_new_group", "must be 'learn' (default) or 'alert'")

    elif rtype == "sequence":
        if "within" in doc:
            rule.within = v.duration("within", doc["within"])
        default_by = v.paths("by", doc.get("by", ["actor"]))
        steps = doc.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            v.err("steps", "a sequence needs a list of at least 2 steps")
            steps = []
        for i, s in enumerate(steps):
            where = f"steps[{i}]"
            if not isinstance(s, dict):
                v.err(where, "step must be a mapping")
                continue
            for k in s:
                if k not in _STEP_KEYS:
                    v.err(f"{where}.{k}", f"unknown step key (allowed: {', '.join(sorted(_STEP_KEYS))})")
            if "match" not in s:
                v.err(f"{where}.match", "required")
                continue
            pred = v.pred(f"{where}.match", s["match"])
            by = v.paths(f"{where}.by", s["by"]) if "by" in s else default_by
            if len(by) != len(default_by):
                v.err(
                    f"{where}.by",
                    f"must have the same number of fields as the rule-level 'by' ({len(default_by)})",
                )
            within = v.duration(f"{where}.within", s["within"]) if "within" in s else None
            count = s.get("count", 1)
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                v.err(f"{where}.count", "expected an integer >= 1")
                count = 1
            absent = s.get("absent", False)
            if not isinstance(absent, bool):
                v.err(f"{where}.absent", "expected true or false")
                absent = False
            if absent:
                if i != len(steps) - 1:
                    v.err(f"{where}.absent", "only the last step of a sequence may be 'absent'")
                if i == 0:
                    v.err(f"{where}.absent", "the first step cannot be 'absent'")
                if within is None:
                    v.err(f"{where}.within", "an 'absent' step requires 'within' (how long to wait)")
                if count != 1:
                    v.err(f"{where}.count", "'count' cannot be used on an 'absent' step")
            name = s.get("name", f"step{i + 1}")
            if pred is not None:
                rule.steps.append(
                    Step(
                        name=str(name),
                        match=s["match"],
                        pred=pred,
                        names=required_event_names(s["match"]),
                        by=by,
                        within=within,
                        count=count,
                        absent=absent,
                    )
                )
        if rule.within and rule.steps:
            total_absent = rule.steps[-1].within if rule.steps[-1].absent else 0
            if total_absent and total_absent > rule.within:
                v.err("steps[-1].within", "absent window cannot exceed the sequence 'within'")

    tests = doc.get("tests")
    if tests is not None:
        _validate_tests(v, tests)
        rule.tests = tests if isinstance(tests, dict) else {}

    return (rule if not v.errors else None), v.errors


def _validate_tests(v: _V, tests: Any) -> None:
    if not isinstance(tests, dict):
        v.err("tests", "expected a mapping with 'positive' and/or 'negative' lists")
        return
    for k in tests:
        if k not in ("positive", "negative"):
            v.err(f"tests.{k}", "unknown key (allowed: positive, negative)")
    for kind in ("positive", "negative"):
        cases = tests.get(kind, [])
        if not isinstance(cases, list):
            v.err(f"tests.{kind}", "expected a list of test cases")
            continue
        for i, case in enumerate(cases):
            where = f"tests.{kind}[{i}]"
            if not isinstance(case, dict):
                v.err(where, "test case must be a mapping")
                continue
            if "events" in case:
                evs = case["events"]
                if not isinstance(evs, list) or not evs or not all(isinstance(e, dict) for e in evs):
                    v.err(f"{where}.events", "expected a non-empty list of event mappings")
                for k in case:
                    if k not in ("events", "name", "expect"):
                        v.err(f"{where}.{k}", "unknown key (allowed: events, name, expect)")
            exp = case.get("expect")
            if exp is not None and (isinstance(exp, bool) or not isinstance(exp, int) or exp < 0):
                v.err(f"{where}.expect", "expected an integer >= 0")


def _parse_yaml(text: str, source: str) -> tuple[list[Any], list[str]]:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        return [], [f"{source}: YAML error: {exc}"]
    out: list[Any] = []
    for d in docs:
        if isinstance(d, list):
            out.extend(d)
        else:
            out.append(d)
    return out, []


def load_rules_from_text(text: str, source: str = "<memory>") -> tuple[list[Rule], list[str]]:
    docs, errors = _parse_yaml(text, source)
    rules: list[Rule] = []
    for i, d in enumerate(docs):
        r, errs = build_rule(d, source, i)
        errors.extend(errs)
        if r is not None:
            rules.append(r)
    return rules, errors


def _builtin_sources() -> list[tuple[str, str]]:
    base = resources.files("trailhunt").joinpath("rules", "builtin")
    out = []
    for entry in sorted(base.iterdir(), key=lambda p: p.name):
        if entry.name.endswith((".yaml", ".yml")):
            out.append((f"builtin/{entry.name}", entry.read_text(encoding="utf-8")))
    return out


def _dir_sources(path: str) -> list[tuple[str, str]]:
    files: list[str] = []
    lp = long_path(path)
    if os.path.isfile(lp):
        files = [lp]
    elif os.path.isdir(lp):
        for root, dirs, names in os.walk(lp):
            dirs.sort()
            files.extend(os.path.join(root, n) for n in sorted(names) if n.endswith((".yaml", ".yml")))
    else:
        raise FileNotFoundError(path)
    out = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            # report paths the way the user typed them
            shown = path if f == lp else os.path.join(path, os.path.relpath(f, lp))
            out.append((shown, fh.read()))
    return out


def collect_rules(
    rule_paths: list[str] | None = None, *, builtin: bool = True
) -> tuple[list[Rule], list[str]]:
    """Load rules, returning ``(rules, errors)`` without raising."""
    sources: list[tuple[str, str]] = []
    errors: list[str] = []
    if builtin:
        sources.extend(_builtin_sources())
    for p in rule_paths or []:
        try:
            sources.extend(_dir_sources(p))
        except FileNotFoundError:
            errors.append(f"{p}: rules path does not exist")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for src, text in sources:
        rs, errs = load_rules_from_text(text, src)
        errors.extend(errs)
        for r in rs:
            if r.id in seen:
                errors.append(f"{src}: rule '{r.id}': duplicate rule id (first defined in {seen[r.id]})")
                continue
            seen[r.id] = src
            rules.append(r)
    return rules, errors


def load_rules(rule_paths: list[str] | None = None, *, builtin: bool = True) -> list[Rule]:
    rules, errors = collect_rules(rule_paths, builtin=builtin)
    if errors:
        raise RuleError(errors)
    return rules

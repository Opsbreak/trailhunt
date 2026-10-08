"""Compilation of rule predicates into fast Python callables.

Predicate language (YAML)::

    match:
      eventSource: iam.amazonaws.com          # scalar  -> equals
      eventName: [CreateUser, DeleteUser]     # list    -> in
      errorCode: {exists: false}              # mapping -> operators (ANDed)
      sourceIPAddress: {cidr: [10.0.0.0/8]}
      any:                                    # boolean composition
        - requestParameters.userName: {glob: "svc-*"}
        - not: {userAgent: {regex: "(?i)terraform"}}

Several keys in one mapping are ANDed. ``all``/``any`` take a list of
predicates, ``not`` takes one predicate.

A field resolves to *zero or more* values (lists are traversed). Positive
operators succeed when **any** value satisfies them; ``exists: false``
succeeds when there are no values; ``not_*`` operators succeed when **no**
value matches.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from trailhunt.fieldpath import PathError, parse_ip, parse_path

if TYPE_CHECKING:
    from trailhunt.event import Event

Pred = Callable[["Event"], bool]


class PredicateError(ValueError):
    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


COMBINATORS = ("all", "any", "not")
OPERATORS = (
    "equals",
    "not_equals",
    "iequals",
    "in",
    "not_in",
    "glob",
    "not_glob",
    "regex",
    "not_regex",
    "cidr",
    "not_cidr",
    "exists",
    "startswith",
    "endswith",
    "contains",
    "gt",
    "gte",
    "lt",
    "lte",
    "eq_field",
    "ne_field",
)


def _norm(v: Any) -> Any:
    if isinstance(v, bool):
        return "true" if v else "false"
    return v


def _eq(a: Any, b: Any) -> bool:
    """Loose equality: bools compare to 'true'/'false', numbers to numeric strings."""
    if a == b and type(a) is type(b):
        return True
    a, b = _norm(a), _norm(b)
    if a == b:
        return True
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        try:
            return float(a) == float(b)
        except (TypeError, ValueError):
            return False
    return False


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def _as_list(arg: Any) -> list[Any]:
    return list(arg) if isinstance(arg, (list, tuple)) else [arg]


def _hashable_set(values: list[Any]) -> tuple[set[Any], list[Any]]:
    """Split comparison values into a fast set of strings and a slow list for loose equality."""
    fast: set[Any] = set()
    slow: list[Any] = []
    for v in values:
        if isinstance(v, str):
            fast.add(v)
        else:
            slow.append(v)
    return fast, slow


def _value_in(v: Any, fast: set[Any], slow: list[Any]) -> bool:
    if isinstance(v, str):
        if v in fast:
            return True
        return any(_eq(v, s) for s in slow)
    if isinstance(v, (dict, list)):
        return False
    return any(_eq(v, s) for s in slow) or any(_eq(v, s) for s in fast)


def _compile_op(field: str, op: str, arg: Any, where: str) -> Callable[[list[Any], Event], bool]:
    """Return ``test(values, event) -> bool`` for one operator."""
    if op in ("equals", "in", "not_equals", "not_in"):
        if op in ("equals", "not_equals") and isinstance(arg, (list, dict)):
            raise PredicateError(where, f"'{op}' expects a scalar (use 'in' for a list)")
        if op in ("in", "not_in") and not isinstance(arg, list):
            raise PredicateError(where, f"'{op}' expects a list")
        fast, slow = _hashable_set(_as_list(arg))
        if op in ("equals", "in"):
            return lambda vals, ev: any(_value_in(v, fast, slow) for v in vals)
        return lambda vals, ev: not any(_value_in(v, fast, slow) for v in vals)
    if op == "iequals":
        targets = {str(a).lower() for a in _as_list(arg)}
        return lambda vals, ev: any(isinstance(v, str) and v.lower() in targets for v in vals)
    if op in ("glob", "not_glob"):
        pats = [str(p) for p in _as_list(arg)]
        rx = re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in pats), re.DOTALL)
        if op == "glob":
            return lambda vals, ev: any(isinstance(v, str) and rx.match(v) is not None for v in vals)
        return lambda vals, ev: not any(isinstance(v, str) and rx.match(v) is not None for v in vals)
    if op in ("regex", "not_regex"):
        pats = [str(p) for p in _as_list(arg)]
        try:
            rxs = [re.compile(p) for p in pats]
        except re.error as exc:
            raise PredicateError(where, f"invalid regex: {exc}") from None
        if op == "regex":
            return lambda vals, ev: any(
                isinstance(v, (str, int, float)) and any(r.search(str(v)) for r in rxs) for v in vals
            )
        return lambda vals, ev: (
            not any(isinstance(v, (str, int, float)) and any(r.search(str(v)) for r in rxs) for v in vals)
        )
    if op in ("cidr", "not_cidr"):
        nets = []
        for c in _as_list(arg):
            try:
                nets.append(ipaddress.ip_network(str(c), strict=False))
            except ValueError:
                raise PredicateError(where, f"invalid CIDR {c!r}") from None

        def in_nets(v: Any) -> bool:
            if not isinstance(v, str):
                return False
            if "/" in v:
                try:
                    net = ipaddress.ip_network(v.strip(), strict=False)
                except ValueError:
                    return False
                return any(net.version == n.version and net.subnet_of(n) for n in nets)  # type: ignore[arg-type]
            addr = parse_ip(v)
            if addr is None:
                return False
            return any(addr.version == n.version and addr in n for n in nets)

        if op == "cidr":
            return lambda vals, ev: any(in_nets(v) for v in vals)
        return lambda vals, ev: bool(vals) and not any(in_nets(v) for v in vals)
    if op == "exists":
        if not isinstance(arg, bool):
            raise PredicateError(where, "'exists' expects true or false")
        if arg:
            return lambda vals, ev: any(v != "" for v in vals)
        return lambda vals, ev: not any(v != "" for v in vals)
    if op in ("startswith", "endswith", "contains"):
        subs = [str(s) for s in _as_list(arg)]
        if op == "startswith":
            tup = tuple(subs)
            return lambda vals, ev: any(isinstance(v, str) and v.startswith(tup) for v in vals)
        if op == "endswith":
            tup = tuple(subs)
            return lambda vals, ev: any(isinstance(v, str) and v.endswith(tup) for v in vals)
        return lambda vals, ev: any(isinstance(v, str) and any(s in v for s in subs) for v in vals)
    if op in ("gt", "gte", "lt", "lte"):
        n = _num(arg)
        if n is None:
            raise PredicateError(where, f"'{op}' expects a number, got {arg!r}")
        cmp: Callable[[float], bool] = {
            "gt": lambda x: x > n,
            "gte": lambda x: x >= n,
            "lt": lambda x: x < n,
            "lte": lambda x: x <= n,
        }[op]

        def numeric(vals: list[Any], ev: Event) -> bool:
            for v in vals:
                x = _num(v)
                if x is not None and cmp(x):
                    return True
            return False

        return numeric
    if op in ("eq_field", "ne_field"):
        if not isinstance(arg, str):
            raise PredicateError(where, f"'{op}' expects a field path")
        try:
            parse_path(arg)
        except PathError as exc:
            raise PredicateError(where, str(exc)) from None
        other = arg
        if op == "eq_field":
            return lambda vals, ev: (lambda o: any(_value_in(v, *_hashable_set(o)) for v in vals))(
                ev.values(other)
            )
        return lambda vals, ev: (lambda o: any(not _value_in(v, *_hashable_set(o)) for v in vals))(
            ev.values(other)
        )
    raise PredicateError(where, f"unknown operator {op!r} (known: {', '.join(OPERATORS)})")


def _compile_field(field: str, spec: Any, where: str) -> Pred:
    try:
        parse_path(field)
    except PathError as exc:
        raise PredicateError(where, str(exc)) from None
    if isinstance(spec, dict):
        if not spec:
            raise PredicateError(where, "empty operator mapping")
        tests = [_compile_op(field, op, arg, f"{where}.{op}") for op, arg in spec.items()]
    elif isinstance(spec, list):
        tests = [_compile_op(field, "in", spec, where)]
    else:
        tests = [_compile_op(field, "equals", spec, where)]

    if len(tests) == 1:
        t0 = tests[0]
        return lambda ev: t0(ev.values(field), ev)

    def check(ev: Event) -> bool:
        vals = ev.values(field)
        return all(t(vals, ev) for t in tests)

    return check


def compile_predicate(node: Any, where: str = "match") -> Pred:
    """Compile a predicate mapping. Raises :class:`PredicateError` with a precise location."""
    if isinstance(node, list):
        # A bare list is shorthand for `all`.
        parts = [compile_predicate(n, f"{where}[{i}]") for i, n in enumerate(node)]
        return lambda ev: all(p(ev) for p in parts)
    if not isinstance(node, dict):
        raise PredicateError(where, f"predicate must be a mapping, got {type(node).__name__}")
    if not node:
        raise PredicateError(where, "empty predicate")
    preds: list[Pred] = []
    for key, spec in node.items():
        if not isinstance(key, str):
            raise PredicateError(where, f"field name must be a string, got {key!r}")
        sub = f"{where}.{key}"
        if key == "all":
            if not isinstance(spec, list) or not spec:
                raise PredicateError(sub, "'all' expects a non-empty list of predicates")
            parts = [compile_predicate(n, f"{sub}[{i}]") for i, n in enumerate(spec)]
            preds.append(lambda ev, parts=parts: all(p(ev) for p in parts))
        elif key == "any":
            if not isinstance(spec, list) or not spec:
                raise PredicateError(sub, "'any' expects a non-empty list of predicates")
            parts = [compile_predicate(n, f"{sub}[{i}]") for i, n in enumerate(spec)]
            preds.append(lambda ev, parts=parts: any(p(ev) for p in parts))
        elif key == "not":
            inner = compile_predicate(spec, sub)
            preds.append(lambda ev, inner=inner: not inner(ev))
        else:
            preds.append(_compile_field(key, spec, sub))
    if len(preds) == 1:
        return preds[0]
    # Order cheap event-name checks first is done by the author; evaluate in order with short-circuit.
    return lambda ev: all(p(ev) for p in preds)


def required_event_names(node: Any) -> frozenset[str] | None:
    """Return the set of eventNames a predicate can possibly match, or ``None`` if unconstrained.

    Used by the engine to index rules by eventName so that most rules are
    never evaluated for most events.
    """
    if isinstance(node, list):
        sets = [required_event_names(n) for n in node]
        known = [s for s in sets if s is not None]
        if not known:
            return None
        out = known[0]
        for s in known[1:]:
            out = out & s
        return frozenset(out)
    if not isinstance(node, dict):
        return None
    constraints: list[frozenset[str]] = []
    for key, spec in node.items():
        if key == "eventName":
            if isinstance(spec, str):
                constraints.append(frozenset([spec]))
            elif isinstance(spec, list) and all(isinstance(s, str) for s in spec):
                constraints.append(frozenset(spec))
            elif isinstance(spec, dict):
                if isinstance(spec.get("equals"), str):
                    constraints.append(frozenset([spec["equals"]]))
                elif isinstance(spec.get("in"), list) and all(isinstance(s, str) for s in spec["in"]):
                    constraints.append(frozenset(spec["in"]))
        elif key == "all" and isinstance(spec, list):
            r = required_event_names(spec)
            if r is not None:
                constraints.append(r)
        elif key == "any" and isinstance(spec, list):
            subs = [required_event_names(n) for n in spec]
            if subs and all(s is not None for s in subs):
                u: frozenset[str] = frozenset()
                for s in subs:
                    u = u | s  # type: ignore[operator]
                constraints.append(u)
    if not constraints:
        return None
    out = constraints[0]
    for c in constraints[1:]:
        out = out & c
    return out

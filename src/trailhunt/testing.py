"""Rule unit testing (``trailhunt rules test``).

Each rule may embed ``tests: {positive: [...], negative: [...]}``. A case is
``{name?, expect?, events: [...]}``. Events are ordinary CloudTrail records
with sensible defaults filled in, plus a few helper keys:

``_at``        offset from the case start (``30s``, ``5m``, ``8d``); default: previous + 1s
``_repeat``    emit the event N times
``_interval``  spacing between repeats (default ``1s``)
``_cycle``     ``{field.path: [v1, v2, ...]}`` - value used by repeat i is ``v[i % len]``
``_user``      shorthand for an IAMUser identity (``_user: alice``)
``_role``      shorthand for an AssumedRole identity (``_role: RoleName/session``)

A positive case passes when the rule fires at least once (or exactly
``expect`` times); a negative case passes when it does not fire (or fires
exactly ``expect`` times).
"""

from __future__ import annotations

import copy
import zlib
from dataclasses import dataclass
from typing import Any

from trailhunt.engine import Engine
from trailhunt.event import Event
from trailhunt.rules import Rule
from trailhunt.timeutil import iso, parse_duration, parse_time

TEST_ACCOUNT = "111111111111"
BASE_TIME = parse_time("2026-01-05T00:00:00Z") or 0.0
DEFAULT_UA = "aws-cli/2.15.30 Python/3.11.8 Linux/6.1.0 exe/x86_64.ubuntu.22"


def user_identity(name: str, account: str = TEST_ACCOUNT) -> dict[str, Any]:
    return {
        "type": "IAMUser",
        "principalId": f"AIDA{zlib.crc32(name.encode()):012d}",
        "arn": f"arn:aws:iam::{account}:user/{name}",
        "accountId": account,
        "accessKeyId": "AKIATESTKEY000000001",
        "userName": name,
    }


def role_identity(role_session: str, account: str = TEST_ACCOUNT) -> dict[str, Any]:
    role, _, session = role_session.partition("/")
    session = session or "session"
    return {
        "type": "AssumedRole",
        "principalId": f"AROATESTROLE0000001:{session}",
        "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
        "accountId": account,
        "accessKeyId": "ASIATESTKEY000000001",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "AROATESTROLE0000001",
                "arn": f"arn:aws:iam::{account}:role/{role}",
                "accountId": account,
                "userName": role,
            },
            "attributes": {"creationDate": "2026-01-05T00:00:00Z", "mfaAuthenticated": "false"},
        },
    }


def _set_path(doc: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def expand_case(events: list[dict[str, Any]], case_id: str = "case") -> list[dict[str, Any]]:
    """Expand helper keys and fill defaults; returns raw CloudTrail records."""
    out: list[dict[str, Any]] = []
    offset = -1.0
    n = 0
    for spec in events:
        spec = copy.deepcopy(spec)
        at = spec.pop("_at", None)
        repeat = int(spec.pop("_repeat", 1))
        interval = parse_duration(spec.pop("_interval", 1))
        cycle = spec.pop("_cycle", {}) or {}
        user = spec.pop("_user", None)
        role = spec.pop("_role", None)
        offset = parse_duration(at) if at is not None else offset + 1.0
        for i in range(repeat):
            rec = copy.deepcopy(spec)
            for path, values in cycle.items():
                _set_path(rec, path, values[i % len(values)])
            if user:
                rec["userIdentity"] = user_identity(str(user))
            elif role:
                rec["userIdentity"] = role_identity(str(role))
            rec.setdefault("userIdentity", user_identity("test-user"))
            rec.setdefault("eventVersion", "1.09")
            if "eventTime" not in rec:
                rec["eventTime"] = iso(BASE_TIME + offset + i * interval)
            rec.setdefault("awsRegion", "us-east-1")
            rec.setdefault("sourceIPAddress", "198.51.100.10")
            rec.setdefault("userAgent", DEFAULT_UA)
            rec.setdefault("recipientAccountId", TEST_ACCOUNT)
            rec.setdefault("eventType", "AwsApiCall")
            rec.setdefault("eventID", f"{case_id}-{n:05d}")
            n += 1
            out.append(rec)
        if repeat > 1:
            offset += (repeat - 1) * interval
    return out


@dataclass
class CaseResult:
    rule_id: str
    kind: str
    index: int
    name: str
    passed: bool
    fired: int
    message: str


def run_case(rule: Rule, events: list[dict[str, Any]], case_id: str = "case") -> int:
    recs = expand_case(events, case_id)
    evs = [e for e in (Event.from_record(r) for r in recs) if e is not None]
    evs.sort(key=lambda e: e.ts)
    engine = Engine([rule])
    return sum(1 for f in engine.run(evs) if f.rule_id == rule.id)


def run_rule_tests(rule: Rule) -> list[CaseResult]:
    results: list[CaseResult] = []
    tests = rule.tests or {}
    for kind in ("positive", "negative"):
        for i, case in enumerate(tests.get(kind, []) or []):
            events = (
                case["events"]
                if "events" in case
                else [{k: v for k, v in case.items() if k not in ("name", "expect")}]
            )
            name = str(case.get("name", f"{kind}[{i}]"))
            try:
                fired = run_case(rule, events, f"{rule.id}-{kind}-{i}")
            except Exception as exc:  # surface broken test data as a failure, not a crash
                results.append(CaseResult(rule.id, kind, i, name, False, 0, f"error: {exc!r}"))
                continue
            expect = case.get("expect")
            if kind == "positive":
                ok = fired == expect if expect is not None else fired >= 1
                want = f"exactly {expect}" if expect is not None else ">= 1"
            else:
                ok = fired == (expect or 0)
                want = f"exactly {expect or 0}"
            msg = "ok" if ok else f"expected {want} finding(s), got {fired}"
            results.append(CaseResult(rule.id, kind, i, name, ok, fired, msg))
    return results

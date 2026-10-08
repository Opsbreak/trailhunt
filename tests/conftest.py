from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from trailhunt.engine import Engine, Finding
from trailhunt.event import Event
from trailhunt.rules import Rule, load_rules_from_text
from trailhunt.testing import expand_case

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOGS = ROOT / "examples" / "sample-logs"


def ev(**fields: Any) -> Event:
    """Build one normalized event using the rule-test defaults (``_user``, ``_at`` ... supported)."""
    recs = expand_case([fields], "t")
    e = Event.from_record(recs[0])
    assert e is not None
    return e


def events(*specs: dict[str, Any]) -> list[Event]:
    recs = expand_case(list(specs), "t")
    out = [e for e in (Event.from_record(r) for r in recs) if e is not None]
    out.sort(key=lambda e: e.ts)
    return out


def rule(yaml_text: str) -> Rule:
    rules, errors = load_rules_from_text(yaml_text, "test")
    assert not errors, errors
    assert len(rules) == 1
    return rules[0]


def run(r: Rule | list[Rule], evs: list[Event], state: dict[str, Any] | None = None) -> list[Finding]:
    return Engine(r if isinstance(r, list) else [r], state=state).run(evs)


@pytest.fixture(scope="session")
def generator_module():
    path = ROOT / "examples" / "generate_dataset.py"
    spec = importlib.util.spec_from_file_location("generate_dataset", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["generate_dataset"] = mod
    spec.loader.exec_module(mod)
    return mod

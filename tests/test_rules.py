from __future__ import annotations

import pytest

from trailhunt.rules import RULE_TYPES, RuleError, collect_rules, load_rules, load_rules_from_text
from trailhunt.testing import run_rule_tests

BUILTIN, BUILTIN_ERRORS = collect_rules()

VALID = """
id: ok-rule
title: ok
type: match
severity: low
match: {eventName: X}
"""


def errors_for(text: str) -> list[str]:
    _, errors = load_rules_from_text(text, "f.yaml")
    return errors


def test_builtin_pack_loads_cleanly():
    assert BUILTIN_ERRORS == []
    assert len(BUILTIN) >= 18
    assert {r.type for r in BUILTIN} == set(RULE_TYPES)


@pytest.mark.parametrize("r", BUILTIN, ids=lambda r: r.id)
def test_builtin_rule_tests_pass(r):
    results = run_rule_tests(r)
    kinds = {c.kind for c in results}
    assert kinds == {"positive", "negative"}, f"{r.id} needs positive and negative tests"
    failed = [f"{c.kind}:{c.name}: {c.message}" for c in results if not c.passed]
    assert not failed, failed


@pytest.mark.parametrize("r", BUILTIN, ids=lambda r: r.id)
def test_builtin_rule_metadata(r):
    assert r.attack, "every built-in rule maps to ATT&CK"
    assert r.description and r.falsepositives


def test_valid_rule():
    assert errors_for(VALID) == []


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        (("severity: low", "severity: urgent"), "severity: must be one of"),
        (("type: match", "type: magic"), "type: must be one of"),
        (("id: ok-rule", "id: Bad Id"), "id: required"),
        (("match: {eventName: X}", "match: {eventName: X}\ntreshold: 3"), "treshold: unknown key"),
        (("match: {eventName: X}", "match: {eventName: {regex: '('}}"), "invalid regex"),
        (
            ("match: {eventName: X}", "match: {eventName: X}\nattack: [TA0001]"),
            "not a MITRE ATT&CK technique",
        ),
        (("match: {eventName: X}", "nothing: 1"), "match: required"),
    ],
)
def test_validation_messages(patch, message):
    old, new = patch
    errs = errors_for(VALID.replace(old, new))
    assert any(message in e for e in errs), errs
    assert all(e.startswith("f.yaml: ") for e in errs)


def test_threshold_validation():
    errs = errors_for("""
id: t1
title: t
type: threshold
severity: low
match: {eventName: X}
window: 5 minutes
threshold: 0
""")
    assert any("window" in e and "invalid duration" in e for e in errs)
    assert any("threshold: expected an integer" in e for e in errs)


def test_sequence_validation():
    errs = errors_for("""
id: s1
title: s
type: sequence
severity: low
within: 1h
steps:
  - {match: {eventName: A}, absent: true}
  - {match: {eventName: B}, count: 0, colour: red}
""")
    joined = "\n".join(errs)
    assert "only the last step" in joined
    assert "first step cannot be 'absent'" in joined
    assert "requires 'within'" in joined
    assert "steps[1].count" in joined
    assert "steps[1].colour: unknown step key" in joined


def test_sequence_needs_two_steps_and_suppress_not_allowed():
    errs = errors_for("""
id: s2
title: s
type: sequence
severity: low
within: 1h
suppress: 1h
steps:
  - {match: {eventName: A}}
""")
    joined = "\n".join(errs)
    assert "at least 2 steps" in joined
    assert "suppress: unknown key" in joined


def test_new_value_validation():
    errs = errors_for("""
id: n1
title: n
type: new_value
severity: low
value: awsRegion
baseline: forever
on_new_group: maybe
""")
    joined = "\n".join(errs)
    assert "baseline" in joined and "on_new_group" in joined


def test_test_block_validation():
    errs = errors_for(VALID + "tests:\n  positive:\n    - events: []\n  maybe: []\n")
    joined = "\n".join(errs)
    assert "tests.maybe" in joined and "non-empty list" in joined


def test_yaml_syntax_error_is_reported():
    errs = errors_for("id: [unclosed\n")
    assert errs and "YAML error" in errs[0]


def test_multi_document_and_list_files():
    rules, errs = load_rules_from_text(VALID + "---\n" + VALID.replace("ok-rule", "ok-two"), "f")
    assert not errs and [r.id for r in rules] == ["ok-rule", "ok-two"]
    rules, errs = load_rules_from_text("- " + VALID.strip().replace("\n", "\n  "), "f")
    assert not errs and len(rules) == 1


def test_load_from_directory_and_duplicate_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(VALID)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.yml").write_text(VALID)
    rules, errs = collect_rules([str(tmp_path)], builtin=False)
    assert len(rules) == 1
    assert any("duplicate rule id" in e for e in errs)
    with pytest.raises(RuleError):
        load_rules([str(tmp_path)], builtin=False)


def test_custom_rule_id_clash_with_builtin(tmp_path):
    (tmp_path / "x.yaml").write_text(VALID.replace("ok-rule", "root-account-usage"))
    _, errs = collect_rules([str(tmp_path)])
    assert any("duplicate rule id" in e for e in errs)


def test_missing_rules_path():
    _, errs = collect_rules(["does/not/exist"], builtin=False)
    assert errs == ["does/not/exist: rules path does not exist"]


def test_failing_rule_test_is_reported():
    rules, _ = load_rules_from_text(
        VALID + "tests:\n  positive:\n    - {eventName: Y}\n  negative:\n    - {eventName: X}\n", "f"
    )
    results = run_rule_tests(rules[0])
    assert [c.passed for c in results] == [False, False]
    assert "expected >= 1" in results[0].message

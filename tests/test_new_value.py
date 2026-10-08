from __future__ import annotations

import json

from conftest import events, rule, run
from trailhunt.engine import Engine

REGION = """
id: nv-region
title: new region
type: new_value
severity: low
group_by: [actor]
value: awsRegion
baseline: 7d
"""


def call(region: str, at: str, user: str = "alice") -> dict:
    return {"eventName": "DescribeInstances", "awsRegion": region, "_at": at, "_user": user}


def test_values_seen_while_learning_are_not_flagged():
    assert run(rule(REGION), events(call("us-east-1", "0s"), call("eu-west-1", "6d"))) == []


def test_new_value_after_baseline_flagged_once():
    f = run(rule(REGION), events(call("us-east-1", "0s"), call("eu-west-1", "8d"), call("eu-west-1", "8d1h")))
    assert len(f) == 1
    assert f[0].details["new_value"] == "eu-west-1"
    assert f[0].details["known_values"] == ["us-east-1"]


def test_baseline_known_value_not_flagged():
    assert run(rule(REGION), events(call("us-east-1", "0s"), call("us-east-1", "9d"))) == []


def test_new_group_learn_vs_alert():
    evs = events(
        call("us-east-1", "0s"), call("eu-west-1", "8d", user="newbie"), call("ap-south-1", "8d1h", "newbie")
    )
    learn = run(rule(REGION), evs)
    assert [f.details["new_value"] for f in learn] == ["ap-south-1"]
    alert = run(rule(REGION + "on_new_group: alert\n"), evs)
    assert [f.details["new_value"] for f in alert] == ["eu-west-1", "ap-south-1"]


def test_state_round_trip_across_runs(tmp_path):
    r = rule(REGION)
    first = Engine([r])
    first.run(events(call("us-east-1", "0s"), call("us-west-2", "3d")))
    state = json.loads(json.dumps(first.export_state()))  # must be JSON serializable

    # Second run: data starts 10 days later; baseline comes from the state, so it is already complete.
    later = events(call("us-west-2", "10d"), call("sa-east-1", "10d1h"))
    second = Engine([r], state=state).run(later)
    assert [f.details["new_value"] for f in second] == ["sa-east-1"]
    # without state the same data is still "learning"
    assert Engine([r]).run(later) == []


def test_state_ignored_when_rule_definition_changes():
    r = rule(REGION)
    eng = Engine([r])
    eng.run(events(call("us-east-1", "0s")))
    state = eng.export_state()
    changed = rule(REGION.replace("value: awsRegion", "value: sourceIPAddress"))
    det = Engine([changed], state=state).detectors[0]
    assert det.groups == {}


def test_export_state_preserves_rules_not_loaded_this_run():
    r = rule(REGION)
    prev = {"version": 1, "rules": {"some-other-rule": {"signature": "x", "groups": {}}}}
    out = Engine([r]).export_state(prev)
    assert "some-other-rule" in out["rules"] and "nv-region" in out["rules"]


def test_transformed_value_and_filter():
    r = rule("""
id: nv-net
title: new net
type: new_value
severity: low
match: {sourceIPAddress: {cidr: ["0.0.0.0/0"]}}
value: sourceIPAddress|net16
baseline: 1d
""")
    evs = events(
        {"eventName": "X", "sourceIPAddress": "198.51.100.1"},
        {"eventName": "X", "sourceIPAddress": "198.51.7.7", "_at": "2d"},
        {"eventName": "X", "sourceIPAddress": "s3.amazonaws.com", "_at": "2d"},
        {"eventName": "X", "sourceIPAddress": "203.0.113.9", "_at": "3d"},
    )
    f = run(r, evs)
    assert [x.details["new_value"] for x in f] == ["203.0.0.0/16"]

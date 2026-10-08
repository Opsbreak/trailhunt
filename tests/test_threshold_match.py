from __future__ import annotations

from conftest import events, rule, run

DENIED = """
id: t-denied
title: denied
type: threshold
severity: medium
match: {errorCode: AccessDenied}
group_by: [actor]
window: 5m
threshold: 3
"""

DISTINCT = """
id: t-distinct
title: distinct
type: threshold
severity: medium
match: {eventName: SendCommand}
window: 10m
distinct: requestParameters.instanceIds
threshold: 4
"""


def denied(at: str, user: str = "a") -> dict:
    return {"eventName": "ListUsers", "errorCode": "AccessDenied", "_at": at, "_user": user}


def test_threshold_fires_at_exactly_n():
    r = rule(DENIED)
    assert len(run(r, events(denied("0s"), denied("10s"), denied("20s")))) == 1
    assert run(r, events(denied("0s"), denied("10s"))) == []


def test_window_boundary_is_inclusive():
    r = rule(DENIED)
    # first and third event exactly 5m apart: still within the window
    assert len(run(r, events(denied("0s"), denied("1m"), denied("5m")))) == 1


def test_window_expiry_one_second_late():
    r = rule(DENIED)
    assert run(r, events(denied("0s"), denied("1m"), denied("5m1s"))) == []


def test_sliding_window_drops_only_old_events():
    r = rule(DENIED)
    f = run(r, events(denied("0s"), denied("4m"), denied("8m"), denied("8m30s")))
    assert len(f) == 1
    assert f[0].event_count == 3  # 4m, 8m, 8m30s (0s expired)


def test_groups_are_independent():
    r = rule(DENIED)
    assert run(r, events(denied("0s", "a"), denied("1s", "b"), denied("2s", "a"), denied("3s", "b"))) == []


def test_rearm_after_firing():
    r = rule(DENIED)
    f = run(r, events(*[denied(f"{i}s") for i in range(6)]))
    assert len(f) == 2
    assert f[0].fingerprint != f[1].fingerprint


def test_suppress_mutes_rearmed_alerts():
    r = rule(DENIED + "suppress: 1h\n")
    assert len(run(r, events(*[denied(f"{i}s") for i in range(9)]))) == 1
    later = [denied(f"{7200 + i}s") for i in range(3)]
    assert len(run(r, events(*[denied(f"{i}s") for i in range(3)], *later))) == 2


def test_distinct_counts_list_elements_and_ignores_repeats():
    r = rule(DISTINCT)
    one_call = events(
        {"eventName": "SendCommand", "requestParameters": {"instanceIds": ["i-1", "i-2", "i-3", "i-4"]}}
    )
    assert len(run(r, one_call)) == 1
    repeats = events(
        *[
            {"eventName": "SendCommand", "requestParameters": {"instanceIds": ["i-1", "i-2"]}, "_at": f"{i}s"}
            for i in range(20)
        ]
    )
    assert run(r, repeats) == []


def test_distinct_details_list_values():
    r = rule(DISTINCT)
    f = run(
        r,
        events(
            *[
                {"eventName": "SendCommand", "requestParameters": {"instanceIds": [f"i-{i}"]}, "_at": f"{i}m"}
                for i in range(4)
            ]
        ),
    )
    assert f[0].details["distinct_count"] == 4
    assert f[0].details["values"] == ["i-0", "i-1", "i-2", "i-3"]


def test_match_rule_and_fingerprint_stability():
    r = rule("""
id: m1
title: m
type: match
severity: high
match: {eventName: StopLogging}
""")
    evs = events({"eventName": "StopLogging"}, {"eventName": "StartLogging"})
    f1, f2 = run(r, evs), run(r, evs)
    assert len(f1) == 1
    assert f1[0].fingerprint == f2[0].fingerprint
    assert f1[0].to_dict()["events"][0]["eventName"] == "StopLogging"


def test_engine_dedups_identical_findings():
    r = rule("""
id: m1
title: m
type: match
severity: high
match: {eventName: StopLogging}
""")
    evs = events(
        {"eventName": "StopLogging", "eventID": "same"}, {"eventName": "StopLogging", "eventID": "same"}
    )
    assert len(run(r, evs)) == 1


def test_disabled_rule_does_not_run():
    r = rule("""
id: m1
title: m
type: match
severity: high
enabled: false
match: {eventName: StopLogging}
""")
    assert run(r, events({"eventName": "StopLogging"})) == []

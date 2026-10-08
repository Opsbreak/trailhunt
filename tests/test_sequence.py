from __future__ import annotations

from conftest import events, rule, run
from trailhunt.engine import Engine, SequenceDetector

ABC = """
id: seq-abc
title: abc
type: sequence
severity: high
by: [actor]
within: 1h
steps:
  - {name: a, match: {eventName: A}}
  - {name: b, match: {eventName: B}, within: 10m}
  - {name: c, match: {eventName: C}}
"""

ABSENT = """
id: seq-absent
title: stop without start
type: sequence
severity: high
by: [requestParameters.name]
within: 2h
steps:
  - {name: stop, match: {eventName: StopLogging}}
  - {name: start, match: {eventName: StartLogging}, absent: true, within: 30m}
"""

USERNAME = """
id: seq-user
title: user chain
type: sequence
severity: high
by: [requestParameters.userName]
within: 1h
steps:
  - {match: {eventName: CreateUser}}
  - {match: {eventName: CreateAccessKey}}
"""


def e(name: str, at: str, user: str = "u1", **kw) -> dict:
    return {"eventName": name, "_at": at, "_user": user, **kw}


def test_ordered_steps_fire_once():
    f = run(rule(ABC), events(e("A", "0s"), e("B", "1m"), e("C", "2m")))
    assert len(f) == 1
    assert [x.event_name for x in f[0].events] == ["A", "B", "C"]
    assert f[0].actor.endswith("user/u1")


def test_wrong_order_does_not_fire():
    assert run(rule(ABC), events(e("B", "0s"), e("A", "1m"), e("C", "2m"))) == []


def test_steps_for_different_keys_do_not_join():
    assert run(rule(ABC), events(e("A", "0s", "u1"), e("B", "1m", "u2"), e("C", "2m", "u1"))) == []


def test_per_step_within():
    r = rule(ABC)
    assert run(r, events(e("A", "0s"), e("B", "10m"), e("C", "11m")))  # boundary is inclusive
    assert run(r, events(e("A", "0s"), e("B", "10m1s"), e("C", "11m"))) == []


def test_total_within():
    r = rule(ABC)
    assert run(r, events(e("A", "0s"), e("B", "5m"), e("C", "61m"))) == []


def test_restart_after_expiry_uses_the_newer_partial_match():
    f = run(rule(ABC), events(e("A", "0s"), e("A", "50m"), e("B", "55m"), e("C", "70m")))
    assert len(f) == 1
    assert f[0].first_ts == f[0].events[0].ts and f[0].events[0].event_name == "A"


def test_join_key_can_be_a_request_parameter():
    r = rule(USERNAME)
    evs = events(
        {"eventName": "CreateUser", "requestParameters": {"userName": "x"}, "_user": "attacker"},
        {
            "eventName": "CreateAccessKey",
            "requestParameters": {"userName": "x"},
            "_user": "other",
            "_at": "5m",
        },
    )
    f = run(r, evs)
    assert len(f) == 1 and f[0].group == {"requestParameters.userName": "x"}


def test_events_missing_the_join_key_are_ignored():
    r = rule(USERNAME)
    assert run(r, events({"eventName": "CreateUser"}, {"eventName": "CreateAccessKey", "_at": "1m"})) == []


def test_absent_step_fires_when_window_passes():
    r = rule(ABSENT)
    f = run(
        r,
        events(
            {"eventName": "StopLogging", "requestParameters": {"name": "t"}},
            {"eventName": "ListBuckets", "_at": "31m"},
        ),
    )
    assert len(f) == 1
    assert "absent" in f[0].details


def test_absent_step_cancelled_by_the_event():
    r = rule(ABSENT)
    assert (
        run(
            r,
            events(
                {"eventName": "StopLogging", "requestParameters": {"name": "t"}},
                {"eventName": "StartLogging", "requestParameters": {"name": "t"}, "_at": "30m"},
                {"eventName": "ListBuckets", "_at": "2h"},
            ),
        )
        == []
    )


def test_absent_cancel_must_match_the_key():
    r = rule(ABSENT)
    f = run(
        r,
        events(
            {"eventName": "StopLogging", "requestParameters": {"name": "t"}},
            {"eventName": "StartLogging", "requestParameters": {"name": "other"}, "_at": "5m"},
            {"eventName": "ListBuckets", "_at": "40m"},
        ),
    )
    assert len(f) == 1


def test_absent_pending_at_end_of_data_is_not_reported():
    r = rule(ABSENT)
    assert (
        run(
            r,
            events(
                {"eventName": "StopLogging", "requestParameters": {"name": "t"}},
                {"eventName": "ListBuckets", "_at": "10m"},
            ),
        )
        == []
    )


def test_repeated_step_with_count_and_greedy_tail():
    r = rule("""
id: seq-brute
title: brute
type: sequence
severity: high
by: [actor]
within: 30m
steps:
  - {match: {eventName: ConsoleLogin, responseElements.ConsoleLogin: Failure}, count: 3, within: 5m}
  - {match: {eventName: ConsoleLogin, responseElements.ConsoleLogin: Success}}
""")
    fail = {"eventName": "ConsoleLogin", "responseElements": {"ConsoleLogin": "Failure"}}
    ok = {"eventName": "ConsoleLogin", "responseElements": {"ConsoleLogin": "Success"}}
    f = run(r, events({**fail, "_repeat": 5, "_interval": "10s"}, {**ok, "_at": "2m"}))
    assert len(f) == 1 and f[0].event_count == 6
    # failures spread wider than the step window never reach the count
    assert run(r, events({**fail, "_repeat": 3, "_interval": "4m"}, {**ok, "_at": "9m"})) == []


def test_state_is_bounded_per_key_and_step():
    r = rule(ABC)
    det = SequenceDetector(r)
    for ev in events(*[e("A", f"{i}s") for i in range(1000)]):
        det.on_event(ev)
    assert len(det.state) == 1
    assert len(next(iter(det.state.values()))) == 1


def test_sweep_expires_stale_partial_matches():
    r = rule(ABC)
    eng = Engine([r])
    det = eng.detectors[0]
    evs = events(e("A", "0s", "u1"), e("A", "1s", "u2"))
    for ev in evs:
        eng.process(ev)
    assert len(det.state) == 2
    det.sweep(evs[-1].ts + 7200)
    assert det.state == {}

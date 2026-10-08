from __future__ import annotations

import json

import pytest

from trailhunt.event import Event, ua_family
from trailhunt.timeutil import parse_duration, parse_time

BASE = {"eventTime": "2026-01-05T10:00:00Z", "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"}


def mk(ui: dict, **extra) -> Event:
    e = Event.from_record({**BASE, "userIdentity": ui, **extra})
    assert e is not None
    return e


def test_iam_user_actor():
    e = mk(
        {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
            "userName": "alice",
            "accessKeyId": "AKIAEXAMPLE",
        }
    )
    assert e.actor == "arn:aws:iam::123456789012:user/alice"
    assert e.actor_name == "alice" and e.access_key_id == "AKIAEXAMPLE" and not e.is_root


def test_root_actor():
    e = mk({"type": "Root", "arn": "arn:aws:iam::123456789012:root", "accountId": "123456789012"})
    assert e.is_root and e.actor == "arn:aws:iam::123456789012:root" and e.actor_name == "root"


def test_assumed_role_maps_sessions_to_role():
    def session(name: str) -> Event:
        return mk(
            {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::123456789012:assumed-role/deployer/{name}",
                "accountId": "123456789012",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "arn": "arn:aws:iam::123456789012:role/ci/deployer",
                        "userName": "deployer",
                    }
                },
            }
        )

    a, b = session("gha-1"), session("gha-2")
    assert a.actor == b.actor == "arn:aws:iam::123456789012:role/ci/deployer"
    assert (a.session_name, b.session_name) == ("gha-1", "gha-2")
    assert a.actor_name == "deployer"


def test_assumed_role_without_session_issuer_is_parsed_from_arn():
    e = mk(
        {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/app/i-0abc",
            "principalId": "AROAX:i-0abc",
        }
    )
    assert e.actor == "arn:aws:iam::123456789012:role/app"
    assert e.session_name == "i-0abc"


def test_identity_center_session_keeps_the_human():
    role = "AWSReservedSSO_Admin_0123456789abcdef"
    e = mk(
        {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::123456789012:assumed-role/{role}/maya@example.com",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "userName": role,
                    "arn": f"arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/{role}",
                }
            },
        }
    )
    assert e.actor.endswith(f"{role}/maya@example.com")
    assert e.session_name == "maya@example.com"


def test_service_account_and_failed_login_identities():
    assert (
        mk({"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}).actor
        == "service:lambda.amazonaws.com"
    )
    assert (
        mk({"type": "AWSAccount", "accountId": "999988887777", "principalId": "X:y"}).actor
        == "account:999988887777"
    )
    failed = mk({"type": "IAMUser", "accountId": "123456789012", "userName": "bob", "accessKeyId": ""})
    assert failed.actor == "arn:aws:iam::123456789012:user/bob"
    assert failed.access_key_id is None


@pytest.mark.parametrize(
    ("ua", "family"),
    [
        ("aws-cli/2.15.30 Python/3.11.8 Linux/6.6.9", "aws-cli"),
        ("[aws-cli/2.15.30 Python/3.11.8]", "aws-cli"),
        ("Boto3/1.34.0 md/Botocore#1.34.0 Python/3.12.1", "boto3"),
        (
            "APN/1.0 HashiCorp/1.0 Terraform/1.9.5 terraform-provider-aws/5.66.0 aws-sdk-go-v2/1.30.4",
            "terraform",
        ),
        ("aws-sdk-go/1.50.8 (go1.22.5; linux; amd64) amazon-ssm-agent/3.3.808.0", "sdk-go"),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "console"),
        ("AWS Internal", "aws-internal"),
        ("config.amazonaws.com", "aws-service"),
        ("", "none"),
        ("python-requests/2.31.0", "python-requests"),
    ],
)
def test_ua_family(ua, family):
    assert ua_family(ua) == family


def test_mfa_from_console_login_and_session_attributes():
    login = mk({"type": "IAMUser", "arn": "arn:aws:iam::1:user/a"}, additionalEventData={"MFAUsed": "Yes"})
    assert login.mfa is True
    sess = mk(
        {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::1:assumed-role/r/s",
            "sessionContext": {"attributes": {"mfaAuthenticated": "false"}},
        }
    )
    assert sess.mfa is False
    assert mk({"type": "IAMUser", "arn": "arn:aws:iam::1:user/a"}).mfa is None


def test_athena_style_lowercase_and_json_string_columns():
    rec = {
        "eventtime": "2026-01-05T10:00:00Z",
        "eventname": "CreateUser",
        "eventsource": "iam.amazonaws.com",
        "useridentity": json.dumps(
            {"type": "IAMUser", "arn": "arn:aws:iam::1:user/a", "accesskeyid": "AKIA1"}
        ),
        "requestparameters": json.dumps({"userName": "x"}),
    }
    e = Event.from_record(rec)
    assert e is not None
    assert e.event_name == "CreateUser" and e.actor == "arn:aws:iam::1:user/a"
    assert e.access_key_id == "AKIA1"
    assert e.values("requestParameters.userName") == ["x"]


def test_cloudtrail_lake_event_json_column():
    inner = {**BASE, "userIdentity": {"type": "Root", "accountId": "1"}}
    e = Event.from_record({"eventJson": json.dumps(inner), "eventTime": "ignored"})
    assert e is not None and e.is_root


def test_record_without_time_is_rejected():
    assert Event.from_record({"eventName": "X"}) is None
    assert Event.from_record({"eventName": "X", "eventTime": "yesterday"}) is None


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-05T10:00:00Z",
        "2026-01-05T10:00:00.123Z",
        "2026-01-05T10:00:00+00:00",
        "2026-01-05 10:00:00",
        "2026-01-05T12:00:00+02:00",
        1767607200,
        1767607200000,
    ],
)
def test_time_parsing_variants(value):
    assert parse_time(value) == 1767607200.0 or abs(parse_time(value) - 1767607200.0) < 1


def test_durations():
    assert parse_duration("90s") == 90
    assert parse_duration("5m") == 300
    assert parse_duration("1.5h") == 5400
    assert parse_duration("7d") == 7 * 86400
    assert parse_duration(30) == 30
    assert parse_duration("1h30m") == 5400
    assert parse_duration("5m1s") == 301
    with pytest.raises(ValueError):
        parse_duration("soon")


def test_summary_mentions_key_parameters():
    e = mk(
        {"type": "IAMUser", "arn": "arn:aws:iam::1:user/a"},
        eventName="CreateAccessKey",
        eventSource="iam.amazonaws.com",
        requestParameters={"userName": "victim"},
        errorCode="AccessDenied",
    )
    assert e.summary() == "iam:CreateAccessKey userName=victim [AccessDenied]"

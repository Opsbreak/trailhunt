from __future__ import annotations

import pytest

from conftest import ev
from trailhunt.predicate import PredicateError, compile_predicate, required_event_names

E = ev(
    eventSource="ec2.amazonaws.com",
    eventName="AuthorizeSecurityGroupIngress",
    sourceIPAddress="203.0.113.77",
    userAgent="aws-cli/2.15.30 Python/3.11.8 Linux/6.6.9 exe/x86_64.kali.2024",
    requestParameters={
        "groupId": "sg-123",
        "dryRun": False,
        "ipPermissions": {
            "items": [{"fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]
        },
        "userName": "test-user",
        "count": "12",
    },
    _user="test-user",
)


def m(node) -> bool:
    return compile_predicate(node)(E)


def test_scalar_is_equals_and_list_is_in():
    assert m({"eventName": "AuthorizeSecurityGroupIngress"})
    assert not m({"eventName": "RevokeSecurityGroupIngress"})
    assert m({"eventName": ["X", "AuthorizeSecurityGroupIngress"]})


def test_equals_is_loose_for_bools_and_numbers():
    assert m({"requestParameters.dryRun": False})
    assert m({"requestParameters.dryRun": "false"})
    assert m({"requestParameters.ipPermissions.items.fromPort": "22"})
    assert m({"requestParameters.count": 12})


def test_not_equals_and_not_in():
    assert m({"eventName": {"not_equals": "X"}})
    assert not m({"eventName": {"not_in": ["AuthorizeSecurityGroupIngress"]}})
    assert m({"missing.field": {"not_in": ["a"]}})


def test_iequals():
    assert m({"eventName": {"iequals": "authorizesecuritygroupingress"}})


def test_glob():
    assert m({"eventName": {"glob": "Authorize*"}})
    assert m({"eventName": {"glob": ["Revoke*", "*Ingress"]}})
    assert not m({"eventName": {"glob": "authorize*"}})  # case-sensitive
    assert m({"eventName": {"not_glob": "Revoke*"}})


def test_regex():
    assert m({"userAgent": {"regex": "(?i)KALI"}})
    assert not m({"userAgent": {"regex": "^Boto3"}})
    assert m({"userAgent": {"not_regex": "^Boto3"}})


def test_cidr_ipv4_ipv6_and_networks():
    assert m({"sourceIPAddress": {"cidr": "203.0.113.0/24"}})
    assert m({"sourceIPAddress": {"cidr": ["10.0.0.0/8", "203.0.0.0/16"]}})
    assert not m({"sourceIPAddress": {"cidr": "10.0.0.0/8"}})
    assert m({"sourceIPAddress": {"not_cidr": "10.0.0.0/8"}})
    assert m({"requestParameters.ipPermissions.items.ipRanges.items.cidrIp": {"cidr": "0.0.0.0/0"}})
    e6 = ev(eventName="X", sourceIPAddress="2001:db8::5")
    assert compile_predicate({"sourceIPAddress": {"cidr": "2001:db8::/32"}})(e6)
    assert not compile_predicate({"sourceIPAddress": {"cidr": "0.0.0.0/0"}})(e6)


def test_cidr_ignores_non_ip_values():
    svc = ev(eventName="X", sourceIPAddress="cloudformation.amazonaws.com")
    assert not compile_predicate({"sourceIPAddress": {"cidr": ["0.0.0.0/0", "::/0"]}})(svc)


def test_exists():
    assert m({"requestParameters.groupId": {"exists": True}})
    assert m({"errorCode": {"exists": False}})
    assert not m({"errorCode": {"exists": True}})


def test_startswith_endswith_contains():
    assert m({"eventName": {"startswith": "Authorize"}})
    assert m({"eventName": {"endswith": ["Egress", "Ingress"]}})
    assert m({"userAgent": {"contains": "kali"}})
    assert not m({"userAgent": {"contains": "parrot"}})


def test_numeric_comparisons():
    p = "requestParameters.ipPermissions.items.fromPort"
    assert m({p: {"gt": 21}}) and m({p: {"gte": 22}}) and m({p: {"lt": 23}}) and m({p: {"lte": 22}})
    assert not m({p: {"gt": 22}})
    assert m({"requestParameters.count": {"gte": 10}})  # numeric strings are compared as numbers
    assert m({p: {"gte": 1, "lte": 1024}})  # several operators are ANDed


def test_field_comparisons():
    assert m({"requestParameters.userName": {"eq_field": "userIdentity.userName"}})
    assert not m({"requestParameters.userName": {"ne_field": "userIdentity.userName"}})
    # a missing comparison field counts as "different"
    assert m({"requestParameters.userName": {"ne_field": "userIdentity.nothing"}})


def test_derived_fields():
    assert m(
        {"actor": "arn:aws:iam::111111111111:user/test-user", "actor_type": "IAMUser", "ua_family": "aws-cli"}
    )
    assert m({"src_ip": {"cidr": "203.0.113.0/24"}, "is_root": False})


def test_boolean_composition():
    assert m(
        {"all": [{"eventName": {"startswith": "Auth"}}, {"sourceIPAddress": {"cidr": "203.0.113.0/24"}}]}
    )
    assert m({"any": [{"eventName": "X"}, {"eventName": "AuthorizeSecurityGroupIngress"}]})
    assert not m({"any": [{"eventName": "X"}, {"eventName": "Y"}]})
    assert m({"not": {"eventName": "X"}})
    assert m([{"eventName": {"startswith": "A"}}, {"not": {"errorCode": {"exists": True}}}])


@pytest.mark.parametrize(
    ("node", "message"),
    [
        ({"eventName": {"bogus": 1}}, "unknown operator"),
        ({"eventName": {"regex": "("}}, "invalid regex"),
        ({"sourceIPAddress": {"cidr": "300.1.1.1/8"}}, "invalid CIDR"),
        ({"eventName": {"in": "notalist"}}, "expects a list"),
        ({"eventName": {"equals": ["a"]}}, "expects a scalar"),
        ({"eventName": {"gt": "abc"}}, "expects a number"),
        ({"eventName": {"exists": "yes"}}, "expects true or false"),
        ({"any": []}, "non-empty list"),
        ({}, "empty predicate"),
        ("eventName", "must be a mapping"),
        ({"a|nope": 1}, "unknown transform"),
    ],
)
def test_compile_errors(node, message):
    with pytest.raises(PredicateError, match=message):
        compile_predicate(node)


def test_compile_error_location():
    with pytest.raises(PredicateError) as exc:
        compile_predicate({"any": [{"eventName": "x"}, {"userAgent": {"regex": "["}}]})
    assert "match.any[1].userAgent.regex" in str(exc.value)


def test_required_event_names():
    assert required_event_names({"eventName": "A"}) == {"A"}
    assert required_event_names({"eventName": ["A", "B"], "x": 1}) == {"A", "B"}
    assert required_event_names({"any": [{"eventName": "A"}, {"eventName": {"in": ["B"]}}]}) == {"A", "B"}
    assert required_event_names({"any": [{"eventName": "A"}, {"x": 1}]}) is None
    assert required_event_names({"eventName": {"glob": "A*"}}) is None
    assert required_event_names({"all": [{"eventName": ["A", "B"]}, {"eventName": "B"}]}) == {"B"}

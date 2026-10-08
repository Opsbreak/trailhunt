from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from trailhunt.fieldpath import PathError, parse_path, resolve

DOC = {
    "a": {"b": {"c": 1}},
    "items": [{"id": "x", "tags": ["t1", "t2"]}, {"id": "y", "tags": ["t3"]}, {"other": True}],
    "nested": [[{"v": 1}], [{"v": 2}]],
    "doc": json.dumps({"Statement": [{"Principal": {"AWS": ["arn:aws:iam::222233334444:root", "*"]}}]}),
    "encoded": quote(json.dumps({"Statement": {"Action": "*"}})),
    "ip": "203.0.113.77",
    "ip6": "2001:db8:abcd:12::1",
    "none": None,
}


def test_nested_dict():
    assert resolve(DOC, "a.b.c") == [1]


def test_missing_and_null_resolve_to_empty():
    assert resolve(DOC, "a.x.c") == []
    assert resolve(DOC, "none") == []


def test_list_traversal_collects_all_elements():
    assert resolve(DOC, "items.id") == ["x", "y"]
    assert resolve(DOC, "items.tags") == ["t1", "t2", "t3"]


def test_numeric_index():
    assert resolve(DOC, "items.1.id") == ["y"]
    assert resolve(DOC, "items.9.id") == []


def test_nested_lists_are_flattened():
    assert resolve(DOC, "nested.v") == [1, 2]


def test_json_transform_then_path():
    assert resolve(DOC, "doc|json.Statement.Principal.AWS") == ["arn:aws:iam::222233334444:root", "*"]


def test_json_transform_url_encoded_document():
    assert resolve(DOC, "encoded|json.Statement.Action") == ["*"]


def test_account_transform():
    assert resolve(DOC, "doc|json.Statement.Principal.AWS|account") == ["222233334444", "*"]
    assert resolve({"x": "not-an-arn"}, "x|account") == []


def test_net_transforms():
    assert resolve(DOC, "ip|net16") == ["203.0.0.0/16"]
    assert resolve(DOC, "ip|net24") == ["203.0.113.0/24"]
    assert resolve(DOC, "ip6|net16") == ["2001:db8:abcd::/48"]
    assert resolve({"ip": "ec2.amazonaws.com"}, "ip|net16") == []


def test_len_lower_upper_str():
    assert resolve(DOC, "items|len") == [3]
    assert resolve({"s": "MiXed"}, "s|lower") == ["mixed"]
    assert resolve({"s": "MiXed"}, "s|upper") == ["MIXED"]
    assert resolve({"b": True}, "b|str") == ["true"]


def test_invalid_json_transform_yields_nothing():
    assert resolve({"d": "{not json"}, "d|json.x") == []


def test_path_errors():
    with pytest.raises(PathError):
        parse_path("")
    with pytest.raises(PathError):
        parse_path("a..b")
    with pytest.raises(PathError, match="unknown transform"):
        parse_path("a|nope")

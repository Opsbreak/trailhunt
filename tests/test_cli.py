from __future__ import annotations

import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

from trailhunt import __version__
from trailhunt.cli import main
from trailhunt.testing import expand_case


@pytest.fixture()
def logs(tmp_path: Path) -> Path:
    recs = expand_case(
        [
            {"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "_user": "alice"},
            {
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "_user": "mallory",
                "requestParameters": {"userName": "alice"},
                "_at": "1m",
            },
            {
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "_user": "mallory",
                "requestParameters": {"name": "main"},
                "_at": "2m",
            },
            {"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "_user": "alice", "_at": "3h"},
        ],
        "cli",
    )
    p = tmp_path / "trail.json.gz"
    p.write_bytes(gzip.compress(json.dumps({"Records": recs}).encode()))
    return p


def test_hunt_text(logs, capsys):
    assert main(["hunt", str(logs)]) == 0
    out = capsys.readouterr()
    assert "[CRITICAL] cloudtrail-logging-disabled" in out.out
    assert "[CRITICAL] cloudtrail-logging-not-restarted" in out.out
    assert "[MEDIUM] iam-access-key-for-other-user" in out.out
    assert "3 findings" in out.out
    assert "events/s" in out.err


def test_hunt_jsonl_and_json(logs, capsys):
    main(["hunt", str(logs), "--format", "jsonl", "-q"])
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert {x["rule_id"] for x in lines} == {
        "cloudtrail-logging-disabled",
        "cloudtrail-logging-not-restarted",
        "iam-access-key-for-other-user",
    }
    for x in lines:
        assert len(x["fingerprint"]) == 24 and x["events"][0]["eventID"].startswith("cli-")
    main(["hunt", str(logs), "--format", "json", "-q"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["total"] == 3 and doc["summary"]["by_severity"] == {"critical": 2, "medium": 1}


def test_hunt_markdown(logs, capsys):
    main(["hunt", str(logs), "--format", "markdown", "-q"])
    out = capsys.readouterr().out
    assert out.startswith("# trailhunt findings") and "| critical | `cloudtrail-logging-disabled`" in out


def test_fail_on_and_min_severity(logs, capsys):
    assert main(["hunt", str(logs), "-q", "--fail-on", "critical"]) == 1
    assert main(["hunt", str(logs), "-q", "--rule-id", "iam-*", "--fail-on", "high"]) == 0
    capsys.readouterr()
    main(["hunt", str(logs), "-q", "--min-severity", "high", "--format", "jsonl"])
    assert all(json.loads(x)["severity"] == "critical" for x in capsys.readouterr().out.splitlines())


def test_output_file_and_since_until(logs, tmp_path, capsys):
    out = tmp_path / "f.jsonl"
    main(["hunt", str(logs), "--format", "jsonl", "-o", str(out), "--until", "2026-01-05T00:01:30Z"])
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    assert [r["rule_id"] for r in rows] == ["iam-access-key-for-other-user"]
    assert "written to" in capsys.readouterr().err


def test_state_file_persists_baseline(tmp_path, capsys):
    def write(name: str, specs: list[dict]) -> str:
        p = tmp_path / name
        p.write_text("\n".join(json.dumps(r) for r in expand_case(specs, name)))
        return str(p)

    week1 = write(
        "w1.jsonl",
        [
            {"eventName": "DescribeInstances", "awsRegion": "ca-central-1", "_user": "bob"},
            {"eventName": "DescribeInstances", "awsRegion": "ca-central-1", "_user": "bob", "_at": "8d"},
        ],
    )
    week3 = write(
        "w3.jsonl",
        [{"eventName": "DescribeInstances", "awsRegion": "ap-east-1", "_user": "bob", "_at": "20d"}],
    )
    state = tmp_path / "state.json"
    main(
        ["hunt", week1, "--state", str(state), "-q", "--rule-id", "new-region-for-actor", "--format", "jsonl"]
    )
    assert capsys.readouterr().out == ""
    assert "new-region-for-actor" in json.loads(state.read_text())["rules"]
    main(
        ["hunt", week3, "--state", str(state), "-q", "--rule-id", "new-region-for-actor", "--format", "jsonl"]
    )
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [r["details"]["new_value"] for r in rows] == ["ap-east-1"]
    # without the state file the third week alone is just the start of a new baseline
    main(["hunt", week3, "-q", "--rule-id", "new-region-for-actor", "--format", "jsonl"])
    assert capsys.readouterr().out == ""


def test_timeline(logs, capsys):
    assert main(["timeline", str(logs), "--actor", "mallory"]) == 0
    out = capsys.readouterr().out
    assert "Timeline for mallory" in out
    assert ">> [CRITICAL] cloudtrail-logging-disabled" in out
    assert "iam:CreateAccessKey userName=alice" in out
    assert main(["timeline", str(logs), "--actor", "nobody"]) == 1
    capsys.readouterr()
    main(["timeline", str(logs), "--actor", "alice", "--display-since", "2026-01-05T01:00:00Z"])
    out = capsys.readouterr().out
    assert "showing    : events since 2026-01-05T01:00:00Z (1)" in out
    assert "03:00:00Z" in out and "00:00:00Z           s3:ListBuckets" not in out


def test_stats(logs, capsys):
    assert main(["stats", str(logs)]) == 0
    out = capsys.readouterr().out
    assert "4 events" in out and "Top actors" in out and "s3:ListBuckets" in out
    main(["stats", str(logs), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["total_events"] == 4 and doc["top_events"][0] == {"value": "s3:ListBuckets", "count": 2}


def test_rules_commands(tmp_path, capsys):
    assert main(["rules", "list"]) == 0
    assert "root-account-usage" in capsys.readouterr().out
    main(["rules", "list", "--format", "json"])
    assert len(json.loads(capsys.readouterr().out)) >= 18
    assert main(["rules", "validate"]) == 0
    assert main(["rules", "test"]) == 0
    assert "0 failed" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x1\ntitle: t\ntype: match\nseverity: loud\nmatch: {eventName: A}\n")
    assert main(["rules", "validate", "--rules", str(bad)]) == 1
    assert "severity: must be one of" in capsys.readouterr().out
    assert main(["hunt", str(bad), "--rules", str(bad)]) == 2


def test_rules_test_reports_failures(tmp_path, capsys):
    r = tmp_path / "r.yaml"
    r.write_text(
        "id: x1\ntitle: t\ntype: match\nseverity: low\nmatch: {eventName: A}\n"
        "tests:\n  positive:\n    - {eventName: B}\n"
    )
    assert main(["rules", "test", "--rules", str(r), "--no-builtin"]) == 1
    assert "FAIL x1" in capsys.readouterr().out


def test_usage_errors(capsys):
    assert main(["hunt", "no/such/path"]) == 2
    assert main(["hunt", ".", "--rule-id", "zzz-nothing"]) == 2
    assert main(["hunt", ".", "--since", "last tuesday"]) == 2
    assert "trailhunt:" in capsys.readouterr().err


def test_module_entry_point_version():
    out = subprocess.run(
        [sys.executable, "-m", "trailhunt", "--version"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == f"trailhunt {__version__}"

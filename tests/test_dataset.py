"""End-to-end detection quality on the synthetic dataset (recall + precision)."""

from __future__ import annotations

import os

import pytest

from conftest import SAMPLE_LOGS
from trailhunt.engine import Engine
from trailhunt.ingest import IngestStats, discover_files, events_from_records, iter_events
from trailhunt.rules import load_rules

EXPECTED_ATTACK_RULES = {
    "access-denied-storm",
    "cloudtrail-config-weakened",
    "cloudtrail-logging-disabled",
    "cloudtrail-logging-not-restarted",
    "console-brute-force-success",
    "console-login-without-mfa",
    "ec2-userdata-modified",
    "enumeration-burst",
    "iam-access-key-for-other-user",
    "iam-admin-policy-attached",
    "iam-login-profile-for-other-user",
    "iam-persistence-new-admin-user",
    "iam-role-trust-external-principal",
    "kms-key-disabled-or-scheduled-deletion",
    "lambda-function-url-public",
    "new-region-for-actor",
    "new-source-network-for-actor",
    "new-user-agent-for-actor",
    "offensive-tool-user-agent",
    "region-sweep",
    "root-account-usage",
    "s3-bucket-made-public",
    "s3-public-access-block-removed",
    "secrets-bulk-retrieval",
    "security-group-opened-to-world",
    "security-monitoring-disabled",
    "snapshot-shared-externally",
    "ssm-sendcommand-burst",
    "sts-new-cross-account-role",
}

ACCOUNT = "111122223333"


@pytest.fixture(scope="module")
def sample_findings():
    stats = IngestStats()
    findings = Engine(load_rules()).run(iter_events([str(SAMPLE_LOGS)], stats))
    return findings, stats


def test_sample_dataset_is_committed_and_small():
    files = discover_files(str(SAMPLE_LOGS))  # long-path safe on Windows
    assert files, "run: python examples/generate_dataset.py --force"
    assert sum(os.path.getsize(f) for f in files) < 2 * 1024 * 1024


def test_sample_yields_exactly_the_expected_rules(sample_findings):
    findings, stats = sample_findings
    assert stats.malformed == 0 and stats.events > 10000
    assert {f.rule_id for f in findings} == EXPECTED_ATTACK_RULES


def test_sample_findings_point_at_the_right_actors(sample_findings):
    findings, _ = sample_findings
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    backup = f"arn:aws:iam::{ACCOUNT}:user/backup-svc"
    backdoor = f"arn:aws:iam::{ACCOUNT}:user/svc-backup-monitor"
    assert by_rule["iam-persistence-new-admin-user"][0].group == {
        "requestParameters.userName": "svc-backup-monitor"
    }
    assert by_rule["iam-persistence-new-admin-user"][0].actor == backup
    assert by_rule["enumeration-burst"][0].actor == backup
    assert by_rule["secrets-bulk-retrieval"][0].actor == backdoor
    assert by_rule["console-brute-force-success"][0].actor == f"arn:aws:iam::{ACCOUNT}:user/legacy-admin"
    assert {f.details["new_value"] for f in by_rule["new-user-agent-for-actor"]} == {"aws-cli"}
    # every finding of the key-compromise incident happened after the 7-day baseline
    assert min(f.first_ts for f in findings) >= 1756684800 + 7 * 86400


def test_generator_is_deterministic_and_matches_the_committed_sample(generator_module):
    a = generator_module.generate(seed=7, days=9)
    b = generator_module.generate(seed=7, days=9)
    assert a == b
    committed = sorted(e.event_id for e in iter_events([str(SAMPLE_LOGS)]))
    assert committed == sorted(r["eventID"] for r in a)


def test_generator_tree_layout_round_trips(generator_module, tmp_path):
    recs = generator_module.generate(seed=3, days=2, attack=False)
    n_files = generator_module.write_cloudtrail_tree(recs, str(tmp_path), seed=3)
    files = discover_files(str(tmp_path))
    assert len(files) == n_files
    assert all(os.path.basename(f).startswith(f"{ACCOUNT}_CloudTrail_") for f in files)
    assert all(f"CloudTrail{os.sep}" in f for f in files)
    got = list(iter_events([str(tmp_path)]))
    assert len(got) == len(recs)
    assert [e.ts for e in got] == sorted(e.ts for e in got)  # shuffled files come out ordered


@pytest.mark.parametrize("seed", [7, 2024])
def test_benign_only_dataset_has_no_findings(generator_module, seed):
    recs = generator_module.generate(seed=seed, days=14, attack=False)
    findings = Engine(load_rules()).run(events_from_records(recs))
    assert findings == [], [(f.rule_id, f.actor) for f in findings]

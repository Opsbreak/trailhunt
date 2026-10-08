#!/usr/bin/env python3
"""Generate a deterministic, realistic synthetic CloudTrail dataset.

The dataset models one production account (111122223333) of a small SaaS
company over several days, with benign activity from:

* a GitHub Actions deploy role (OIDC, Terraform + AWS CLI, from runner IP pools)
* an API Lambda function reading its secrets
* an EC2 fleet whose SSM agents check in
* a nightly backup job using an IAM user access key (boto3, on-prem IP)
* two humans signing in through IAM Identity Center (console + CLI)
* a legacy IAM admin who signs in daily with MFA
* a third-party monitoring vendor assuming a role from its own account
* AWS Config and AWS services acting on the account's behalf

With ``--attack`` (the default) three incidents are embedded after a 7-day
baseline:

1. Day 8 (2026-09-08 03:12Z): console brute force against ``legacy-admin``
   followed by a successful sign-in without MFA.
2. Day 9 (2026-09-09 01:47Z): unexpected root console sign-in.
3. Day 9 (14:02Z onwards): the backup user's access key is used from a Kali
   box: identity check, enumeration (with many AccessDenied), a region sweep,
   then persistence (backdoor admin user with key and console password),
   a cross-account trust backdoor, defense evasion (GuardDuty, Config,
   CloudTrail selectors, StopLogging), exfiltration prep (snapshot and RDS
   snapshot shared out, bucket made public, secrets harvested), execution
   (SSM fan-out, user-data change, SSH opened, public Lambda URL) and
   impact (KMS key scheduled for deletion).

Output is laid out exactly like a CloudTrail S3 export::

    <out>/AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/<acct>_CloudTrail_<region>_<ts>Z_<id>.json.gz

Usage::

    python examples/generate_dataset.py --out examples/sample-logs --force
    python examples/generate_dataset.py --no-attack --out /tmp/benign --force
    python examples/generate_dataset.py --jsonl events.jsonl
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import random
import shutil
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

ACCOUNT = "111122223333"
ATTACKER_ACCOUNT = "444455556666"
VENDOR_ACCOUNT = "999988887777"
HOME_REGION = "ca-central-1"
DEFAULT_START = "2026-09-01"

UA_CLI = "aws-cli/2.17.40 md/awscrt#0.21.2 ua/2.0 os/linux#6.5.0-1025-azure md/arch#x86_64 lang/python#3.11.9 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/distrib#ubuntu.22 command/{cmd}"
UA_TF = "APN/1.0 HashiCorp/1.0 Terraform/1.9.5 (+https://www.terraform.io) terraform-provider-aws/5.66.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.30.4 ua/2.0 os/linux lang/go#1.22.6 md/GOOS#linux md/GOARCH#amd64"
UA_JS = "aws-sdk-js/3.637.0 ua/2.1 os/linux#5.10.223-232.873.amzn2.x86_64 lang/js md/nodejs#20.17.0 api/secrets-manager#3.637.0 exec-env/AWS_Lambda_nodejs20.x"
UA_SSM = "aws-sdk-go/1.50.8 (go1.22.5; linux; amd64) amazon-ssm-agent/3.3.808.0"
UA_BOTO = "Boto3/1.35.10 md/Botocore#1.35.10 ua/2.0 os/linux#5.15.0-119-generic md/arch#x86_64 lang/python#3.10.12 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.35.10"
UA_BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
UA_LAPTOP_CLI = "aws-cli/2.17.33 md/awscrt#0.20.11 ua/2.0 os/macos#23.6.0 md/arch#arm64 lang/python#3.11.9 md/pyimpl#CPython cfg/retry-mode#standard md/installer#source command/{cmd}"
UA_VENDOR = "aws-sdk-go/1.55.5 (go1.22.6; linux; amd64) vendor-cloud-collector/7.4.1"
UA_KALI = "aws-cli/2.15.30 md/awscrt#0.19.19 ua/2.0 os/linux#6.6.15-amd64 md/arch#x86_64 lang/python#3.11.8 md/pyimpl#CPython exe/x86_64.kali.2024 prompt/off command/{cmd}"
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

READ_PREFIXES = ("Describe", "List", "Get", "Lookup", "Search", "Filter", "BatchGet", "Head")


def _long(path: str) -> str:
    """Use Windows extended-length paths so deep AWSLogs trees work without LongPathsEnabled."""
    prefix = "\\\\?\\"  # \\?\
    if os.name == "nt" and not path.startswith(prefix):
        full = os.path.abspath(path)
        if len(full) >= 200:
            return prefix + full
    return path


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Generator:
    def __init__(self, seed: int, start: datetime, days: int) -> None:
        self.rng = random.Random(seed)
        self.start = start
        self.days = days
        self.records: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ helpers
    def uid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def day_ts(self, day: int, hour: float = 0.0) -> float:
        return (self.start + timedelta(days=day)).timestamp() + hour * 3600

    def jitter(self, ts: float, spread: float) -> float:
        return ts + self.rng.uniform(0, spread)

    def emit(
        self,
        ts: float,
        ident: dict[str, Any],
        service: str,
        name: str,
        region: str,
        ip: str,
        ua: str,
        *,
        params: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        error: str | None = None,
        extra: dict[str, Any] | None = None,
        event_type: str = "AwsApiCall",
    ) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "eventVersion": "1.09",
            "userIdentity": ident,
            "eventTime": _iso(ts),
            "eventSource": f"{service}.amazonaws.com",
            "eventName": name,
            "awsRegion": region,
            "sourceIPAddress": ip,
            "userAgent": ua.replace("{cmd}", _cli_cmd(service, name)),
        }
        if error:
            rec["errorCode"] = error
            rec["errorMessage"] = (
                f"User: {ident.get('arn', 'principal')} is not authorized to perform: {service}:{name}"
                if "Denied" in error or "Unauthorized" in error
                else "The request failed"
            )
        rec["requestParameters"] = params
        rec["responseElements"] = response
        if extra:
            rec.update(extra)
        rec["requestID"] = self.uid()
        rec["eventID"] = self.uid()
        rec["readOnly"] = name.startswith(READ_PREFIXES)
        rec["eventType"] = event_type
        rec["managementEvent"] = True
        rec["recipientAccountId"] = ACCOUNT
        rec["eventCategory"] = "Management"
        self.records.append(rec)
        return rec

    # ------------------------------------------------------------------ identities
    @staticmethod
    def iam_user(name: str, akid: str, uid: str) -> dict[str, Any]:
        return {
            "type": "IAMUser",
            "principalId": uid,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
            "accountId": ACCOUNT,
            "accessKeyId": akid,
            "userName": name,
        }

    @staticmethod
    def role(
        role: str,
        session: str,
        akid: str,
        role_id: str,
        *,
        mfa: bool = False,
        created: str = "2026-09-01T00:00:00Z",
    ) -> dict[str, Any]:
        return {
            "type": "AssumedRole",
            "principalId": f"{role_id}:{session}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}",
            "accountId": ACCOUNT,
            "accessKeyId": akid,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": role_id,
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}"
                    if not role.startswith("AWSReservedSSO_")
                    else f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/{role}",
                    "accountId": ACCOUNT,
                    "userName": role,
                },
                "attributes": {"creationDate": created, "mfaAuthenticated": "true" if mfa else "false"},
            },
        }

    @staticmethod
    def service(svc: str) -> dict[str, Any]:
        return {"type": "AWSService", "invokedBy": svc}

    def akid(self, prefix: str = "ASIA") -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        return prefix + "".join(self.rng.choice(alphabet) for _ in range(16))

    # ------------------------------------------------------------------ benign actors
    def ci_deploys(self, day: int, weekday: bool) -> None:
        pools = ["4.175.112.{}", "20.57.43.{}", "52.159.226.{}"]
        runs = self.rng.randint(5, 7) if weekday else 1
        if day == 0:
            runs = max(runs, len(pools))
        for i in range(runs):
            t = self.jitter(self.day_ts(day, 13), 9 * 3600)
            pool = pools[i % len(pools)] if day == 0 else self.rng.choice(pools)
            ip = pool.format(self.rng.randint(2, 250))
            run_id = 10_870_000_000 + day * 1000 + i * 37 + self.rng.randint(0, 30)
            session = f"gha-{run_id}"
            sub = "repo:opsbreak/platform:ref:refs/heads/main"
            self.emit(
                t,
                {
                    "type": "WebIdentityUser",
                    "principalId": f"token.actions.githubusercontent.com:sts.amazonaws.com:{sub}",
                    "userName": sub,
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "sts",
                "AssumeRoleWithWebIdentity",
                HOME_REGION,
                ip,
                "configure-aws-credentials-for-github-actions",
                params={
                    "roleArn": f"arn:aws:iam::{ACCOUNT}:role/github-actions-deploy",
                    "roleSessionName": session,
                    "durationSeconds": 3600,
                },
                response={
                    "assumedRoleUser": {
                        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/github-actions-deploy/{session}"
                    }
                },
            )
            ident = self.role(
                "github-actions-deploy", session, self.akid(), "AROAQ3DEPLOY0EXAMPLE1", created=_iso(t)
            )
            t += 3
            self.emit(t, ident, "sts", "GetCallerIdentity", HOME_REGION, ip, UA_CLI)
            plan = [
                ("ec2", "DescribeVpcs", HOME_REGION),
                ("ec2", "DescribeSubnets", HOME_REGION),
                ("ec2", "DescribeSecurityGroups", HOME_REGION),
                ("iam", "GetRole", "us-east-1"),
                ("iam", "ListAttachedRolePolicies", "us-east-1"),
                ("iam", "GetPolicy", "us-east-1"),
                ("iam", "GetPolicyVersion", "us-east-1"),
                ("elasticloadbalancing", "DescribeLoadBalancers", HOME_REGION),
                ("elasticloadbalancing", "DescribeTargetGroups", HOME_REGION),
                ("ecs", "DescribeServices", HOME_REGION),
                ("ecs", "DescribeTaskDefinition", HOME_REGION),
                ("lambda", "GetFunction20150331v2", HOME_REGION),
                ("ecr", "DescribeRepositories", HOME_REGION),
                ("logs", "DescribeLogGroups", HOME_REGION),
            ]
            for svc, name, region in plan:
                t += self.rng.uniform(0.2, 2.5)
                err = "AccessDenied" if name == "GetRole" and self.rng.random() < 0.08 else None
                self.emit(
                    t,
                    ident,
                    svc,
                    name,
                    region,
                    ip,
                    UA_TF,
                    params={"roleName": "orders-api-lambda"} if svc == "iam" and "Role" in name else None,
                    error=err,
                )
            t += 20
            self.emit(t, ident, "ecr", "GetAuthorizationToken", HOME_REGION, ip, UA_CLI)
            for name in (
                "BatchCheckLayerAvailability",
                "InitiateLayerUpload",
                "UploadLayerPart",
                "CompleteLayerUpload",
                "PutImage",
            ):
                t += self.rng.uniform(1, 6)
                self.emit(
                    t,
                    ident,
                    "ecr",
                    name,
                    HOME_REGION,
                    ip,
                    "docker/26.1.3 go/go1.21.10 git-commit/b72abbb",
                    params={"repositoryName": "orders-api"},
                )
            t += 30
            self.emit(
                t,
                ident,
                "ecs",
                "RegisterTaskDefinition",
                HOME_REGION,
                ip,
                UA_TF,
                params={"family": "orders-api"},
            )
            self.emit(
                t + 2,
                ident,
                "ecs",
                "UpdateService",
                HOME_REGION,
                ip,
                UA_TF,
                params={"cluster": "prod", "service": "orders-api"},
            )
            self.emit(
                t + 4,
                ident,
                "lambda",
                "UpdateFunctionCode20150331v2",
                HOME_REGION,
                ip,
                UA_TF,
                params={"functionName": "orders-webhook"},
            )

    def orders_lambda(self, day: int) -> None:
        ip_base = "35.182.{}.{}"
        for slot in range(72):
            t = self.jitter(self.day_ts(day, slot / 3), 600)
            session = "orders-api"
            self.emit(
                t,
                self.service("lambda.amazonaws.com"),
                "sts",
                "AssumeRole",
                HOME_REGION,
                "lambda.amazonaws.com",
                "lambda.amazonaws.com",
                params={
                    "roleArn": f"arn:aws:iam::{ACCOUNT}:role/orders-api-lambda",
                    "roleSessionName": session,
                },
            )
            ident = self.role("orders-api-lambda", session, self.akid(), "AROAQ3ORDERS0EXAMPLE")
            ip = ip_base.format(self.rng.randint(0, 255), self.rng.randint(1, 254))
            secrets = ["prod/orders/db"] + (["prod/orders/stripe"] if slot % 3 == 0 else [])
            for s in secrets:
                t += self.rng.uniform(0.05, 0.4)
                self.emit(
                    t,
                    ident,
                    "secretsmanager",
                    "GetSecretValue",
                    HOME_REGION,
                    ip,
                    UA_JS,
                    params={"secretId": f"arn:aws:secretsmanager:{HOME_REGION}:{ACCOUNT}:secret:{s}"},
                )
                self.emit(
                    t + 0.05,
                    self.service("secretsmanager.amazonaws.com"),
                    "kms",
                    "Decrypt",
                    HOME_REGION,
                    "secretsmanager.amazonaws.com",
                    "secretsmanager.amazonaws.com",
                    params={"encryptionAlgorithm": "SYMMETRIC_DEFAULT"},
                )

    FLEET = [
        "i-0a1f3c5e7b9d01234",
        "i-0b2e4d6f8a0c12345",
        "i-0c3d5e7f9b1d23456",
        "i-0d4c6e8a0b2e34567",
        "i-0e5b7d9f1c3f45678",
        "i-0f6a8c0e2d4a56789",
    ]

    def ec2_fleet(self, day: int) -> None:
        nats = ["15.222.18.40", "15.222.77.201"]
        for idx, inst in enumerate(self.FLEET):
            ident = self.role("app-ec2-role", inst, self.akid(), "AROAQ3APPEC20EXAMPLE")
            ip = nats[idx % 2]
            for h in range(24):
                t = self.jitter(self.day_ts(day, h), 3500)
                self.emit(
                    t,
                    ident,
                    "ssm",
                    "UpdateInstanceInformation",
                    HOME_REGION,
                    ip,
                    UA_SSM,
                    params={"instanceId": inst, "agentVersion": "3.3.808.0", "platformType": "Linux"},
                )
                if h % 6 == idx % 6:
                    self.emit(
                        t + 1,
                        ident,
                        "ssm",
                        "ListInstanceAssociations",
                        HOME_REGION,
                        ip,
                        UA_SSM,
                        params={"instanceId": inst},
                    )
                    self.emit(t + 2, ident, "ec2", "DescribeTags", HOME_REGION, ip, UA_SSM)

    def backup_job(self, day: int, ident: dict[str, Any]) -> None:
        ip = "142.112.40.17"
        t = self.jitter(self.day_ts(day, 3.05), 300)
        self.emit(
            t,
            ident,
            "ec2",
            "DescribeVolumes",
            HOME_REGION,
            ip,
            UA_BOTO,
            params={
                "filterSet": {"items": [{"name": "tag:backup", "valueSet": {"items": [{"value": "daily"}]}}]}
            },
        )
        for vol in (
            "vol-0aa11bb22cc33dd44",
            "vol-0bb22cc33dd44ee55",
            "vol-0cc33dd44ee55ff66",
            "vol-0dd44ee55ff66aa77",
        ):
            t += self.rng.uniform(1, 4)
            snap = f"snap-0{self.rng.getrandbits(64):016x}"
            self.emit(
                t,
                ident,
                "ec2",
                "CreateSnapshot",
                HOME_REGION,
                ip,
                UA_BOTO,
                params={"volumeId": vol, "description": "nightly"},
                response={"snapshotId": snap},
            )
        self.emit(
            t + 5,
            ident,
            "ec2",
            "DescribeSnapshots",
            HOME_REGION,
            ip,
            UA_BOTO,
            params={"ownersSet": {"items": [{"owner": "self"}]}},
        )
        for _ in range(4):
            t += self.rng.uniform(1, 3)
            self.emit(
                t + 6,
                ident,
                "ec2",
                "DeleteSnapshot",
                HOME_REGION,
                ip,
                UA_BOTO,
                params={"snapshotId": f"snap-0{self.rng.getrandbits(64):016x}"},
            )
        t += 15
        self.emit(
            t,
            ident,
            "rds",
            "CreateDBSnapshot",
            HOME_REGION,
            ip,
            UA_BOTO,
            params={
                "dBInstanceIdentifier": "orders-prod",
                "dBSnapshotIdentifier": f"orders-prod-nightly-{day:02d}",
            },
        )
        self.emit(t + 3, ident, "rds", "DescribeDBSnapshots", HOME_REGION, ip, UA_BOTO)
        self.emit(
            t + 60,
            ident,
            "ec2",
            "CopySnapshot",
            "us-west-2",
            ip,
            UA_BOTO,
            params={
                "sourceRegion": HOME_REGION,
                "sourceSnapshotId": f"snap-0{self.rng.getrandbits(64):016x}",
            },
        )
        self.emit(t + 62, ident, "ec2", "DescribeSnapshots", "us-west-2", ip, UA_BOTO)

    CONSOLE_CALLS = [
        ("ec2", "DescribeInstances"),
        ("ec2", "DescribeInstanceStatus"),
        ("cloudwatch", "DescribeAlarms"),
        ("cloudwatch", "GetMetricData"),
        ("s3", "ListBuckets"),
        ("s3", "GetBucketLocation"),
        ("logs", "DescribeLogGroups"),
        ("logs", "FilterLogEvents"),
        ("lambda", "ListFunctions20150331"),
        ("rds", "DescribeDBInstances"),
        ("ecs", "ListClusters"),
        ("ecs", "DescribeServices"),
        ("iam", "ListRoles"),
        ("cloudtrail", "LookupEvents"),
        ("guardduty", "ListFindings"),
        ("securityhub", "GetFindings"),
        ("kms", "ListAliases"),
        ("health", "DescribeEventAggregates"),
    ]

    def sso_human(
        self, day: int, who: str, role: str, role_id: str, weekday: bool, *, readonly: bool
    ) -> None:
        if not weekday and day != 0:
            return
        office = "24.114.73.{}"
        home = "70.53.168.{}"
        session_name = f"{who}@opsbreak.example"
        start = self.jitter(self.day_ts(day, 13.5), 3 * 3600)
        locations = [office, home] if day == 0 else [home if self.rng.random() < 0.25 else office]
        for li, loc in enumerate(locations):
            t = start + li * 4 * 3600
            ip = loc.format(self.rng.randint(2, 250))
            ident = self.role(role, session_name, self.akid(), role_id, created=_iso(t))
            self.emit(
                t,
                ident,
                "signin",
                "ConsoleLogin",
                "us-east-1",
                ip,
                UA_BROWSER,
                event_type="AwsConsoleSignIn",
                response={"ConsoleLogin": "Success"},
                extra={
                    "additionalEventData": {
                        "LoginTo": "https://console.aws.amazon.com/console/home",
                        "MobileVersion": "No",
                        "MFAUsed": "No",
                    }
                },
            )
            calls = self.rng.sample(self.CONSOLE_CALLS, self.rng.randint(8, 14))
            for ci, (svc, name) in enumerate(calls):
                t += self.rng.uniform(5, 240)
                ua = "AWS Internal" if ci % 4 == 3 else UA_BROWSER
                region = "us-east-1" if svc in ("iam", "s3", "health") else HOME_REGION
                self.emit(t, ident, svc, name, region, ip, ua, extra={"sessionCredentialFromConsole": "true"})
            # some CLI work from the laptop
            for svc, name in self.rng.sample(
                [
                    ("s3", "ListBuckets"),
                    ("ecs", "ListTasks"),
                    ("logs", "GetLogEvents"),
                    ("sts", "GetCallerIdentity"),
                    ("ec2", "DescribeInstances"),
                    ("rds", "DescribeDBClusters"),
                    ("ssm", "GetParameter"),
                ],
                self.rng.randint(3, 6),
            ):
                t += self.rng.uniform(30, 600)
                self.emit(t, ident, svc, name, HOME_REGION, ip, UA_LAPTOP_CLI)
            if readonly and self.rng.random() < 0.6:
                t += 60
                self.emit(
                    t,
                    ident,
                    "s3",
                    "PutBucketTagging",
                    "us-east-1",
                    ip,
                    UA_BROWSER,
                    params={"bucketName": "opsbreak-prod-assets"},
                    error="AccessDenied",
                )

    def legacy_admin(self, day: int, ident: dict[str, Any]) -> None:
        ip = f"24.114.73.{self.rng.randint(2, 250)}"
        t = self.jitter(self.day_ts(day, 16.5), 1800)
        self.emit(
            t,
            ident,
            "signin",
            "ConsoleLogin",
            "us-east-1",
            ip,
            UA_BROWSER,
            event_type="AwsConsoleSignIn",
            response={"ConsoleLogin": "Success"},
            extra={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/home",
                    "MobileVersion": "No",
                    "MFAUsed": "Yes",
                }
            },
        )
        for name in ("GetAccountSummary", "ListUsers", "ListAccessKeys"):
            t += self.rng.uniform(10, 90)
            self.emit(t, ident, "iam", name, "us-east-1", ip, UA_BROWSER)

    VENDOR_CALLS = [
        ("ec2", "DescribeInstances"),
        ("ec2", "DescribeVolumes"),
        ("cloudwatch", "ListMetrics"),
        ("cloudwatch", "GetMetricData"),
        ("cloudwatch", "DescribeAlarms"),
        ("lambda", "ListFunctions20150331"),
        ("rds", "DescribeDBInstances"),
        ("elasticloadbalancing", "DescribeLoadBalancers"),
        ("autoscaling", "DescribeAutoScalingGroups"),
        ("tag", "GetResources"),
    ]

    def vendor_monitor(self, day: int) -> None:
        regions = [HOME_REGION, "us-east-1", "us-west-2"]
        for slot in range(48):
            t = self.jitter(self.day_ts(day, slot / 2), 300)
            ip = f"3.233.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            self.emit(
                t,
                {
                    "type": "AWSAccount",
                    "principalId": "AROAVENDORCOLLECTOR01:vendor-collector",
                    "accountId": VENDOR_ACCOUNT,
                },
                "sts",
                "AssumeRole",
                "us-east-1",
                ip,
                UA_VENDOR,
                params={
                    "roleArn": f"arn:aws:iam::{ACCOUNT}:role/vendor-monitoring",
                    "roleSessionName": "vendor-collector",
                    "externalId": "HIDDEN_DUE_TO_SECURITY_REASONS",
                },
            )
            ident = self.role("vendor-monitoring", "vendor-collector", self.akid(), "AROAQ3VENDOR0EXAMPLE")
            region = regions[slot % len(regions)]
            for svc, name in self.VENDOR_CALLS:
                t += self.rng.uniform(0.1, 1.5)
                self.emit(t, ident, svc, name, region, ip, UA_VENDOR)

    CONFIG_CALLS = [
        "DescribeInstances",
        "DescribeVolumes",
        "DescribeSecurityGroups",
        "DescribeVpcs",
        "DescribeSubnets",
        "DescribeNetworkInterfaces",
        "DescribeRouteTables",
        "DescribeInternetGateways",
        "DescribeNatGateways",
        "DescribeNetworkAcls",
        "DescribeAddresses",
        "DescribeVpcEndpoints",
        "DescribeFlowLogs",
        "DescribeLaunchTemplates",
        "DescribeKeyPairs",
        "DescribeImages",
        "DescribeSnapshots",
        "DescribeTransitGateways",
        "DescribeCustomerGateways",
        "DescribeVpnGateways",
        "DescribeDhcpOptions",
        "DescribeEgressOnlyInternetGateways",
        "DescribeVpcPeeringConnections",
        "DescribePrefixLists",
        "DescribeInstanceAttribute",
        "DescribeSecurityGroupRules",
        "DescribeManagedPrefixLists",
        "DescribePlacementGroups",
    ]

    def aws_config(self, day: int) -> None:
        for h in (1, 7, 13, 19):
            t = self.jitter(self.day_ts(day, h), 600)
            ident = self.role(
                "AWSServiceRoleForConfig", "AWSConfig-Describe", self.akid(), "AROAQ3CONFIG0EXAMPLE"
            )
            ident["invokedBy"] = "config.amazonaws.com"
            for name in self.CONFIG_CALLS:
                t += self.rng.uniform(0.05, 0.8)
                self.emit(t, ident, "ec2", name, HOME_REGION, "config.amazonaws.com", "config.amazonaws.com")

    # ------------------------------------------------------------------ attacks
    def attack_brute_force(self, day: int) -> None:
        ip = "45.155.205.233"
        t = self.day_ts(day, 3.2)
        failed_ident = {
            "type": "IAMUser",
            "principalId": "AIDAQ3LEGACYADMIN0001",
            "accountId": ACCOUNT,
            "accessKeyId": "",
            "userName": "legacy-admin",
        }
        for _ in range(7):
            t += self.rng.uniform(12, 35)
            self.emit(
                t,
                failed_ident,
                "signin",
                "ConsoleLogin",
                "us-east-1",
                ip,
                UA_FIREFOX,
                event_type="AwsConsoleSignIn",
                response={"ConsoleLogin": "Failure"},
                extra={
                    "errorMessage": "Failed authentication",
                    "additionalEventData": {
                        "LoginTo": "https://console.aws.amazon.com/console/home",
                        "MobileVersion": "No",
                        "MFAUsed": "No",
                    },
                },
            )
        t += 41
        ident = self.iam_user("legacy-admin", "ASIAQ3LEGACYCONSOLE1", "AIDAQ3LEGACYADMIN0001")
        self.emit(
            t,
            ident,
            "signin",
            "ConsoleLogin",
            "us-east-1",
            ip,
            UA_FIREFOX,
            event_type="AwsConsoleSignIn",
            response={"ConsoleLogin": "Success"},
            extra={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/home",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                }
            },
        )
        for name in ("GetAccountSummary", "ListUsers", "ListAccessKeys", "GetAccountAuthorizationDetails"):
            t += self.rng.uniform(5, 40)
            self.emit(t, ident, "iam", name, "us-east-1", ip, UA_FIREFOX)

    def attack_root_login(self, day: int) -> None:
        ip = "24.114.73.88"
        t = self.day_ts(day, 1.78)
        ident = {
            "type": "Root",
            "principalId": ACCOUNT,
            "arn": f"arn:aws:iam::{ACCOUNT}:root",
            "accountId": ACCOUNT,
            "accessKeyId": "",
        }
        self.emit(
            t,
            ident,
            "signin",
            "ConsoleLogin",
            "us-east-1",
            ip,
            UA_BROWSER,
            event_type="AwsConsoleSignIn",
            response={"ConsoleLogin": "Success"},
            extra={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/billing/home",
                    "MobileVersion": "No",
                    "MFAUsed": "Yes",
                }
            },
        )
        for svc, name in (
            ("iam", "GetAccountSummary"),
            ("billingconsole", "GetBillingPreferences"),
            ("account", "GetContactInformation"),
        ):
            t += self.rng.uniform(20, 90)
            self.emit(t, ident, svc, name, "us-east-1", ip, UA_BROWSER)

    def attack_key_compromise(self, day: int, backup: dict[str, Any]) -> None:
        ip1, ip2 = "185.220.101.34", "185.220.101.47"
        t = self.day_ts(day, 14.0) + 131
        e = self.emit
        e(t, backup, "sts", "GetCallerIdentity", "us-east-1", ip1, UA_KALI)
        # --- discovery: what can this key do?
        enum = [
            ("iam", "ListUsers", None),
            ("iam", "ListRoles", None),
            ("iam", "ListGroups", None),
            ("iam", "ListPolicies", None),
            ("iam", "GetAccountAuthorizationDetails", None),
            ("iam", "ListAccessKeys", None),
            ("iam", "GetUser", None),
            ("iam", "ListAttachedUserPolicies", None),
            ("iam", "ListUserPolicies", None),
            ("iam", "GetUserPolicy", None),
            ("iam", "ListMFADevices", None),
            ("iam", "GetAccountPasswordPolicy", None),
            ("iam", "ListInstanceProfiles", None),
            ("ec2", "DescribeInstances", None),
            ("ec2", "DescribeVolumes", None),
            ("ec2", "DescribeSnapshots", None),
            ("ec2", "DescribeSecurityGroups", None),
            ("ec2", "DescribeVpcs", None),
            ("ec2", "DescribeKeyPairs", None),
            ("s3", "ListBuckets", "AccessDenied"),
            ("s3", "GetBucketPolicy", "AccessDenied"),
            ("s3", "GetBucketAcl", "AccessDenied"),
            ("secretsmanager", "ListSecrets", "AccessDeniedException"),
            ("lambda", "ListFunctions20150331", "AccessDeniedException"),
            ("lambda", "GetAccountSettings20160819", "AccessDeniedException"),
            ("kms", "ListKeys", "AccessDeniedException"),
            ("kms", "ListAliases", "AccessDeniedException"),
            ("cloudtrail", "DescribeTrails", "AccessDenied"),
            ("cloudtrail", "GetTrailStatus", "AccessDenied"),
            ("guardduty", "ListDetectors", "AccessDeniedException"),
            ("ssm", "DescribeParameters", "AccessDeniedException"),
            ("ssm", "GetParameters", "AccessDeniedException"),
            ("dynamodb", "ListTables", "AccessDeniedException"),
            ("sns", "ListTopics", "AuthorizationError"),
            ("sqs", "ListQueues", "AccessDenied"),
            ("organizations", "DescribeOrganization", "AccessDeniedException"),
            ("ecr", "DescribeRepositories", "AccessDeniedException"),
            ("eks", "ListClusters", "AccessDeniedException"),
            ("logs", "DescribeLogGroups", "AccessDeniedException"),
            ("ecs", "ListClusters", "AccessDeniedException"),
            ("rds", "DescribeDBInstances", None),
            ("rds", "DescribeDBSnapshots", None),
        ]
        for svc, name, err in enum:
            t += self.rng.uniform(2, 9)
            region = "us-east-1" if svc in ("iam", "s3", "organizations") else HOME_REGION
            e(t, backup, svc, name, region, ip1, UA_KALI, error=err)
        # --- region sweep
        for region in (
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-southeast-1",
            "ap-northeast-1",
        ):
            t += self.rng.uniform(4, 12)
            e(t, backup, "ec2", "DescribeInstances", region, ip1, UA_KALI)
            e(t + 1, backup, "ec2", "DescribeRegions", region, ip1, UA_KALI)
        # --- persistence through the over-privileged backup key
        t += 95
        user = "svc-backup-monitor"
        e(
            t,
            backup,
            "iam",
            "CreateUser",
            "us-east-1",
            ip1,
            UA_KALI,
            params={"userName": user},
            response={
                "user": {
                    "userName": user,
                    "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
                    "userId": "AIDAQ3BACKDOOR000001",
                }
            },
        )
        t += 40
        new_key = "AKIAQ3EXAMPLEMON0007"
        e(
            t,
            backup,
            "iam",
            "CreateAccessKey",
            "us-east-1",
            ip1,
            UA_KALI,
            params={"userName": user},
            response={"accessKey": {"accessKeyId": new_key, "status": "Active", "userName": user}},
        )
        t += 25
        e(
            t,
            backup,
            "iam",
            "AttachUserPolicy",
            "us-east-1",
            ip1,
            UA_KALI,
            params={"userName": user, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        )
        t += 25
        e(
            t,
            backup,
            "iam",
            "CreateLoginProfile",
            "us-east-1",
            ip1,
            UA_KALI,
            params={"userName": user, "passwordResetRequired": False},
        )
        # --- the attacker switches to the backdoor user
        mon = self.iam_user(user, new_key, "AIDAQ3BACKDOOR000001")
        t += 160
        e(t, mon, "sts", "GetCallerIdentity", "us-east-1", ip2, UA_KALI)
        t += 50
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [f"arn:aws:iam::{ACCOUNT}:root", f"arn:aws:iam::{ATTACKER_ACCOUNT}:root"]
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        e(
            t,
            mon,
            "iam",
            "UpdateAssumeRolePolicy",
            "us-east-1",
            ip2,
            UA_KALI,
            params={"roleName": "ops-admin", "policyDocument": json.dumps(trust)},
        )
        t += 70
        e(
            t,
            mon,
            "sts",
            "AssumeRole",
            "us-east-1",
            ip2,
            UA_KALI,
            params={
                "roleArn": f"arn:aws:iam::{ATTACKER_ACCOUNT}:role/xfer-staging",
                "roleSessionName": "sync",
            },
            response={
                "assumedRoleUser": {"arn": f"arn:aws:sts::{ATTACKER_ACCOUNT}:assumed-role/xfer-staging/sync"}
            },
        )
        # --- defense evasion
        t += 90
        e(
            t,
            mon,
            "guardduty",
            "DeleteDetector",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={"detectorId": "a2c8e6f1b3d5a7c9e1f3b5d7a9c1e3f5"},
        )
        t += 30
        e(
            t,
            mon,
            "config",
            "StopConfigurationRecorder",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={"configurationRecorderName": "default"},
        )
        t += 40
        e(
            t,
            mon,
            "cloudtrail",
            "PutEventSelectors",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={
                "trailName": "opsbreak-mgmt-trail",
                "eventSelectors": [
                    {"readWriteType": "All", "includeManagementEvents": False, "dataResources": []}
                ],
            },
        )
        t += 35
        e(
            t,
            mon,
            "cloudtrail",
            "StopLogging",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={"name": f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT}:trail/opsbreak-mgmt-trail"},
        )
        # --- exfiltration prep
        t += 120
        snap = "snap-0f1e2d3c4b5a69788"
        e(
            t,
            mon,
            "ec2",
            "CreateSnapshot",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={"volumeId": "vol-0aa11bb22cc33dd44", "description": "maintenance"},
            response={"snapshotId": snap},
        )
        t += 75
        e(
            t,
            mon,
            "ec2",
            "ModifySnapshotAttribute",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={
                "snapshotId": snap,
                "attributeType": "CREATE_VOLUME_PERMISSION",
                "createVolumePermission": {"add": {"items": [{"userId": ATTACKER_ACCOUNT}]}},
            },
        )
        t += 40
        e(
            t,
            mon,
            "rds",
            "ModifyDBSnapshotAttribute",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={
                "dBSnapshotIdentifier": "orders-prod-nightly-07",
                "attributeName": "restore",
                "valuesToAdd": [ATTACKER_ACCOUNT],
            },
        )
        t += 60
        bucket = "opsbreak-prod-backups"
        e(
            t,
            mon,
            "s3",
            "DeleteBucketPublicAccessBlock",
            "us-east-1",
            ip2,
            UA_KALI,
            params={"bucketName": bucket, "Host": f"{bucket}.s3.amazonaws.com", "publicAccessBlock": ""},
        )
        t += 30
        e(
            t,
            mon,
            "s3",
            "PutBucketPolicy",
            "us-east-1",
            ip2,
            UA_KALI,
            params={
                "bucketName": bucket,
                "bucketPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "x",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{bucket}/*",
                        }
                    ],
                },
            },
        )
        t += 80
        e(t, mon, "secretsmanager", "ListSecrets", HOME_REGION, ip2, UA_KALI)
        for s in (
            "prod/orders/db",
            "prod/orders/stripe",
            "prod/github/deploy-key",
            "prod/slack/webhook",
            "prod/sendgrid/api",
            "prod/auth/jwt-signing",
            "prod/redis/auth",
            "prod/okta/scim",
            "prod/datadog/api",
            "prod/pagerduty/token",
        ):
            t += self.rng.uniform(3, 11)
            e(t, mon, "secretsmanager", "GetSecretValue", HOME_REGION, ip2, UA_KALI, params={"secretId": s})
        # --- execution / exposure
        t += 70
        e(
            t,
            mon,
            "ec2",
            "AuthorizeSecurityGroupIngress",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={
                "groupId": "sg-0d2c4e6f8a0b1c2d3",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                        }
                    ]
                },
            },
        )
        t += 45
        e(
            t,
            mon,
            "ec2",
            "ModifyInstanceAttribute",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={"instanceId": self.FLEET[0], "userData": "<sensitiveDataRemoved>"},
        )
        t += 60
        targets = [
            *self.FLEET,
            "i-01a2b3c4d5e6f7a80",
            "i-02b3c4d5e6f7a8b91",
            "i-03c4d5e6f7a8b9ca2",
            "i-04d5e6f7a8b9cadb3",
            "i-05e6f7a8b9cadbec4",
            "i-06f7a8b9cadbecfd5",
        ]
        e(
            t,
            mon,
            "ssm",
            "SendCommand",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={
                "documentName": "AWS-RunShellScript",
                "instanceIds": targets,
                "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
            },
        )
        t += 90
        e(
            t,
            mon,
            "lambda",
            "CreateFunctionUrlConfig20211031",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={"functionName": "ops-healthcheck", "authType": "NONE"},
            response={
                "functionUrl": "https://abcdefghijklmnopqrstuvwxyz123456.lambda-url.ca-central-1.on.aws/"
            },
        )
        # --- impact
        t += 120
        e(
            t,
            mon,
            "kms",
            "ScheduleKeyDeletion",
            HOME_REGION,
            ip2,
            UA_KALI,
            params={
                "keyId": f"arn:aws:kms:{HOME_REGION}:{ACCOUNT}:key/7d3f1e2a-9b8c-4d5e-8f7a-6b5c4d3e2f1a",
                "pendingWindowInDays": 7,
            },
        )

    # ------------------------------------------------------------------ driver
    def run(self, attack: bool) -> list[dict[str, Any]]:
        backup = self.iam_user("backup-svc", "AKIAQ3EXAMPLEBKUP001", "AIDAQ3BACKUPSVC00001")
        legacy = self.iam_user("legacy-admin", "ASIAQ3LEGACYCONSOLE1", "AIDAQ3LEGACYADMIN0001")
        for day in range(self.days):
            weekday = (self.start + timedelta(days=day)).weekday() < 5
            self.ci_deploys(day, weekday)
            self.orders_lambda(day)
            self.ec2_fleet(day)
            self.backup_job(day, backup)
            self.sso_human(
                day,
                "maya.chen",
                "AWSReservedSSO_AdministratorAccess_8f2c1a6b9d0e3f45",
                "AROAQ3SSOADMIN0EXAMP",
                weekday,
                readonly=False,
            )
            self.sso_human(
                day,
                "dev.patel",
                "AWSReservedSSO_ReadOnlyAccess_3b9e7d1c5a2f4e68",
                "AROAQ3SSOREAD00EXAMP",
                weekday,
                readonly=True,
            )
            if weekday or day == 0:
                self.legacy_admin(day, legacy)
            self.vendor_monitor(day)
            self.aws_config(day)
        if attack and self.days >= 9:
            self.attack_brute_force(7)
            self.attack_root_login(8)
            self.attack_key_compromise(8, backup)
        self.records.sort(key=lambda r: r["eventTime"])
        return self.records


def generate(
    seed: int = 7, days: int = 9, start: str = DEFAULT_START, attack: bool = True
) -> list[dict[str, Any]]:
    """Return the generated records sorted by eventTime."""
    start_dt = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
    return Generator(seed, start_dt, days).run(attack)


def write_cloudtrail_tree(
    records: list[dict[str, Any]], out: str, seed: int = 7, file_minutes: int = 60
) -> int:
    """Write records as CloudTrail delivery files; returns the number of files written."""
    rng = random.Random(seed ^ 0x5EED)
    buckets: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    width = file_minutes * 60
    for r in records:
        ts = datetime.strptime(r["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        buckets[(r["awsRegion"], int(ts // width))].append(r)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    n = 0
    for (region, b), recs in sorted(buckets.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        recs = list(recs)
        rng.shuffle(recs)  # CloudTrail files are not internally ordered
        delivered = datetime.fromtimestamp((b + 1) * width + 300, tz=timezone.utc)
        day_dir = os.path.join(
            out,
            "AWSLogs",
            ACCOUNT,
            "CloudTrail",
            region,
            delivered.strftime("%Y"),
            delivered.strftime("%m"),
            delivered.strftime("%d"),
        )
        os.makedirs(_long(day_dir), exist_ok=True)
        uniq = "".join(rng.choice(alphabet) for _ in range(16))
        name = f"{ACCOUNT}_CloudTrail_{region}_{delivered.strftime('%Y%m%dT%H%M')}Z_{uniq}.json.gz"
        payload = json.dumps({"Records": recs}, separators=(",", ":")).encode()
        buf = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as gz:
            gz.write(payload)
        with open(_long(os.path.join(day_dir, name)), "wb") as fh:
            fh.write(buf.getvalue())
        n += 1
    return n


def write_jsonl(records: list[dict[str, Any]], path: str) -> None:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(_long(path), "wt", encoding="utf-8") as fh:  # type: ignore[operator]
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-logs"))
    ap.add_argument("--jsonl", help="write a single JSON Lines file instead of a CloudTrail tree")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--days", type=int, default=9, help="number of days (attacks need >= 9)")
    ap.add_argument("--start", default=DEFAULT_START, help="first day (YYYY-MM-DD, UTC)")
    ap.add_argument("--no-attack", action="store_true", help="benign activity only")
    ap.add_argument("--file-minutes", type=int, default=60, help="time span per delivery file")
    ap.add_argument("--force", action="store_true", help="replace an existing <out>/AWSLogs tree")
    args = ap.parse_args(argv)

    records = generate(args.seed, args.days, args.start, attack=not args.no_attack)
    if args.jsonl:
        write_jsonl(records, args.jsonl)
        print(f"wrote {len(records)} events to {args.jsonl}")
        return 0
    tree = os.path.join(args.out, "AWSLogs")
    if os.path.exists(tree):
        if not args.force:
            print(f"{tree} exists; use --force to replace it", file=sys.stderr)
            return 2
        shutil.rmtree(_long(tree))
    files = write_cloudtrail_tree(records, args.out, args.seed, args.file_minutes)
    print(f"wrote {len(records)} events in {files} files under {tree}")
    return 0


def _cli_cmd(service: str, name: str) -> str:
    out = []
    for ch in name:
        if ch.isupper() and out:
            out.append("-")
        out.append(ch.lower())
    return f"{service}.{''.join(out)}"


if __name__ == "__main__":
    raise SystemExit(main())

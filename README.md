# trailhunt

[![CI](https://github.com/Opsbreak/trailhunt/actions/workflows/ci.yml/badge.svg)](https://github.com/Opsbreak/trailhunt/actions/workflows/ci.yml)

**Offline AWS CloudTrail threat hunting with stateful correlation.**

trailhunt reads exported CloudTrail logs (the `AWSLogs/` tree from S3, `.json.gz`
files, or JSON Lines exports from CloudTrail Lake / Athena) and runs a YAML rule
engine over them that understands *time*: single-event matches, sliding-window
thresholds, multi-step sequences joined on any field (including "B did **not**
happen"), and first-seen anomalies against a learned or persisted baseline. It
needs no AWS credentials, no database and no SIEM - just Python and the logs.

It ships with 29 tested detections mapped to MITRE ATT&CK, a rule unit-test
runner, a per-actor timeline view, and a realistic synthetic dataset with an
embedded intrusion so you can see it work in one command.

Built by [Opsbreak](https://github.com/Opsbreak), a Canadian cloud and AI security company.

---

## Why

Raw CloudTrail is a firehose of JSON: one event per API call, scattered across
regions and five-minute files. Most free tooling looks at it **one event at a
time** ("was `StopLogging` called?"). That catches the loud stuff, but the
intrusions that matter are *shapes over time*:

* a service key that always uses boto3 from one IP suddenly calls from the AWS
  CLI on a new network, fans out 40 different `List*`/`Describe*` calls with half
  of them denied, then sweeps eight regions;
* `CreateUser` → `CreateAccessKey` → `AttachUserPolicy AdministratorAccess` on the
  **same new user** within minutes, possibly from different principals;
* `StopLogging` that is **not** followed by `StartLogging`.

Commercial SIEMs can correlate this, but they are expensive, need the data
shipped somewhere first, and are often unavailable when you are handed a bucket
of logs during an incident. trailhunt fills that gap: point it at the logs and
it correlates them locally, deterministically, in event time.

## Install

```bash
pipx install git+https://github.com/Opsbreak/trailhunt
# or, in a virtualenv
pip install git+https://github.com/Opsbreak/trailhunt
```

Requires Python 3.10+. The only runtime dependency is PyYAML.

## Quickstart (on the bundled sample data)

`examples/sample-logs/` is a 1.4 MB, 9-day synthetic CloudTrail export
(11,575 events in 591 gzip delivery files) for a fictional production account.
It contains lots of benign activity (a GitHub Actions deploy role, a Lambda API,
an EC2 fleet, a nightly backup job, two SSO humans, a monitoring vendor, AWS
Config) plus three embedded incidents - see
[`examples/generate_dataset.py`](examples/generate_dataset.py).

```bash
git clone https://github.com/Opsbreak/trailhunt && cd trailhunt
pip install -e .
trailhunt hunt examples/sample-logs
```

Real output, critical findings only (`--min-severity critical`):

```text
$ trailhunt hunt examples/sample-logs --min-severity critical
trailhunt: 11575 events from 591 files in 0.52s (22,314 events/s)
[CRITICAL] iam-persistence-new-admin-user - New IAM user created, given an access key and admin rights
  actor   : arn:aws:iam::111122223333:user/backup-svc
  when    : 2026-09-09T14:08:29Z .. 2026-09-09T14:09:34Z (3 events)
  group   : requestParameters.userName=svc-backup-monitor
  details : steps=[user created, access key created, admin privileges granted]; within=1h
  att&ck  : T1136.003, T1098.001, T1098.003
  id      : 79341a360c0b403232a26735
  events  :
    2026-09-09T14:08:29Z  iam:CreateUser userName=svc-backup-monitor  (us-east-1, 185.220.101.34) a01f21b1-c61e-43a5-898c-449d5a13770e
    2026-09-09T14:09:09Z  iam:CreateAccessKey userName=svc-backup-monitor  (us-east-1, 185.220.101.34) f0d270c9-2967-4f06-b06e-c020a555809a
    2026-09-09T14:09:34Z  iam:AttachUserPolicy userName=svc-backup-monitor policyArn=arn:aws:iam::aws:policy/AdministratorAccess  (us-east-1, 185.220.101.34) a952aa38-b571-4281-ba11-b2bd83c88759

[CRITICAL] cloudtrail-logging-disabled - CloudTrail logging stopped or trail deleted
  actor   : arn:aws:iam::111122223333:user/svc-backup-monitor
  when    : 2026-09-09T14:17:54Z (1 event)
  att&ck  : T1562.008
  id      : 7f06a906b0347d9826b938d2
  events  :
    2026-09-09T14:17:54Z  cloudtrail:StopLogging name=arn:aws:cloudtrail:ca-central-1:111122223333:trail/opsbreak-mgmt-trail  (ca-central-1, 185.220.101.47) 1581fb4c-8287-4683-9f59-0d5cc425082f

[CRITICAL] cloudtrail-logging-not-restarted - CloudTrail logging stopped and not restarted within 30 minutes
  actor   : arn:aws:iam::111122223333:user/svc-backup-monitor
  when    : 2026-09-09T14:17:54Z (1 event)
  group   : requestParameters.name=arn:aws:cloudtrail:ca-central-1:111122223333:trail/opsbreak-mgmt-trail
  details : steps=[logging stopped, logging restarted]; within=2h; absent=no 'logging restarted' within 30m
  att&ck  : T1562.008
  id      : 07a7979b1dc7c453ece05456
  events  :
    2026-09-09T14:17:54Z  cloudtrail:StopLogging name=arn:aws:cloudtrail:ca-central-1:111122223333:trail/opsbreak-mgmt-trail  (ca-central-1, 185.220.101.47) 1581fb4c-8287-4683-9f59-0d5cc425082f

3 findings (3 critical)
```

The full run reports `40 findings (3 critical, 14 high, 12 medium, 11 low)`.
This is the actual summary table from `trailhunt hunt examples/sample-logs --format markdown`:

| Severity | Rule | Actor | First seen | Events | ATT&CK |
|---|---|---|---|---|---|
| high | `console-brute-force-success` | `arn:aws:iam::111122223333:user/legacy-admin` | 2026-09-08T03:12:16Z | 8 | T1110.001, T1078.004 |
| low | `new-source-network-for-actor` | `arn:aws:iam::111122223333:user/legacy-admin` | 2026-09-08T03:12:16Z | 1 | T1078.004 |
| medium | `console-login-without-mfa` | `arn:aws:iam::111122223333:user/legacy-admin` | 2026-09-08T03:15:02Z | 1 | T1078.004 |
| high | `root-account-usage` | `arn:aws:iam::111122223333:root` | 2026-09-09T01:46:48Z | 1 | T1078.004 |
| medium | `enumeration-burst` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:02:11Z | 25 | T1580, T1087.004, T1069.003, T1526 |
| medium | `offensive-tool-user-agent` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:02:11Z | 1 | T1078.004 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:02:11Z | 1 | T1535 |
| low | `new-source-network-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:02:11Z | 1 | T1078.004 |
| low | `new-user-agent-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:02:11Z | 1 | T1078.004 |
| medium | `access-denied-storm` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:03:44Z | 15 | T1580, T1526 |
| medium | `region-sweep` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:05:42Z | 5 | T1580, T1535 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:06:00Z | 1 | T1535 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:06:05Z | 1 | T1535 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:06:22Z | 1 | T1535 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:06:34Z | 1 | T1535 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:06:45Z | 1 | T1535 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:06:54Z | 1 | T1535 |
| critical | `iam-persistence-new-admin-user` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:08:29Z | 3 | T1136.003, T1098.001, T1098.003 |
| medium | `iam-access-key-for-other-user` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:09:09Z | 1 | T1098.001 |
| medium | `iam-admin-policy-attached` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:09:34Z | 1 | T1098.003 |
| high | `iam-login-profile-for-other-user` | `arn:aws:iam::111122223333:user/backup-svc` | 2026-09-09T14:09:59Z | 1 | T1098 |
| medium | `offensive-tool-user-agent` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:12:39Z | 1 | T1078.004 |
| high | `iam-role-trust-external-principal` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:13:29Z | 1 | T1098.003, T1199 |
| medium | `sts-new-cross-account-role` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:14:39Z | 1 | T1550.001, T1078.004 |
| high | `security-monitoring-disabled` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:16:09Z | 1 | T1562.001 |
| low | `new-region-for-actor` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:16:09Z | 1 | T1535 |
| high | `security-monitoring-disabled` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:16:39Z | 1 | T1562.001 |
| high | `cloudtrail-config-weakened` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:17:19Z | 1 | T1562.008 |
| critical | `cloudtrail-logging-disabled` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:17:54Z | 1 | T1562.008 |
| critical | `cloudtrail-logging-not-restarted` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:17:54Z | 1 | T1562.008 |
| high | `snapshot-shared-externally` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:21:09Z | 1 | T1537 |
| high | `snapshot-shared-externally` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:21:49Z | 1 | T1537 |
| medium | `s3-public-access-block-removed` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:22:49Z | 1 | T1562.001, T1530 |
| high | `s3-bucket-made-public` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:23:19Z | 1 | T1530, T1537 |
| high | `secrets-bulk-retrieval` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:24:43Z | 8 | T1555.006 |
| high | `security-group-opened-to-world` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:26:51Z | 1 | T1562.007, T1133 |
| medium | `ec2-userdata-modified` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:27:36Z | 1 | T1059.009, T1098 |
| high | `ssm-sendcommand-burst` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:28:36Z | 1 | T1651 |
| medium | `lambda-function-url-public` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:30:06Z | 1 | T1648, T1190 |
| high | `kms-key-disabled-or-scheduled-deletion` | `arn:aws:iam::111122223333:user/svc-backup-monitor` | 2026-09-09T14:32:06Z | 1 | T1485, T1486 |

Every one of the 29 built-in rules fires on the attack, and **none** fires on the
benign activity: the test suite regenerates benign-only datasets (14 days, two
seeds) and asserts zero findings. A 90-day run with the attack on days 8-9 also
produced exactly the same 40 findings - no false positives in the 80 benign days
that follow.

### Investigate an actor

`timeline` shows one principal's activity with findings annotated where they
completed. `--display-since` limits what is *printed* while the whole history
still feeds baselines and correlation (`--since` would drop that history).
Real output, trimmed with `--limit`:

```text
$ trailhunt timeline examples/sample-logs --actor backup-svc --display-since 2026-09-09T14:00:00Z --bucket 15m --limit 12
Timeline for backup-svc
  actor      : arn:aws:iam::111122223333:user/backup-svc (189 events)
  events     : 189   first: 2026-09-01T03:04:50Z   last: 2026-09-09T14:09:59Z
  source IPs : 142.112.40.17 (126), 185.220.101.34 (63)
  regions    : ca-central-1 (133), us-east-1 (24), us-west-2 (20), us-east-2 (2), us-west-1 (2), eu-west-1 (2), eu-central-1 (2), ap-southeast-1 (2)
  clients    : boto3 (126), aws-cli (63)
  findings   : 17
  showing    : events since 2026-09-09T14:00:00Z (63)

Activity per 15m (only non-empty buckets; ! = finding)
  2026-09-09 14:00  |########################################|    63 !!!!!

Events (consecutive identical calls collapsed)
  2026-09-09T14:02:11Z           sts:GetCallerIdentity  [us-east-1 185.220.101.34]
                                 >> [MEDIUM] offensive-tool-user-agent: API call from an offensive security distribution or tool
                                 >> [LOW] new-region-for-actor: Actor active in a region it has never used
                                 >> [LOW] new-source-network-for-actor: Actor calling from a network (/16) it has never used
                                 >> [LOW] new-user-agent-for-actor: Actor using a client family it has never used
  2026-09-09T14:02:14Z           iam:ListUsers  [us-east-1 185.220.101.34]
  2026-09-09T14:02:19Z           iam:ListRoles  [us-east-1 185.220.101.34]
  2026-09-09T14:02:22Z           iam:ListGroups  [us-east-1 185.220.101.34]
  2026-09-09T14:02:24Z           iam:ListPolicies  [us-east-1 185.220.101.34]
  2026-09-09T14:02:30Z           iam:GetAccountAuthorizationDetails  [us-east-1 185.220.101.34]
  2026-09-09T14:02:39Z           iam:ListAccessKeys  [us-east-1 185.220.101.34]
  2026-09-09T14:02:48Z           iam:GetUser  [us-east-1 185.220.101.34]
  2026-09-09T14:02:55Z           iam:ListAttachedUserPolicies  [us-east-1 185.220.101.34]
  2026-09-09T14:02:58Z           iam:ListUserPolicies  [us-east-1 185.220.101.34]
  2026-09-09T14:03:05Z           iam:GetUserPolicy  [us-east-1 185.220.101.34]
  2026-09-09T14:03:09Z           iam:ListMFADevices  [us-east-1 185.220.101.34]
  ... output limited to 12 lines (51 events not shown; use --limit)
```

`--actor` accepts the actor key, an ARN, an access key id, a user/role name or a session name.

### Other commands

```bash
trailhunt stats examples/sample-logs --top 5          # top actors, events, errors, regions, IPs, clients
trailhunt hunt logs/ --format jsonl > findings.jsonl  # one JSON finding per line (SIEM/ticket friendly)
trailhunt hunt logs/ --format markdown -o report.md   # incident report
trailhunt hunt logs/ --fail-on high                   # exit 1 if anything >= high (CI / scheduled jobs)
trailhunt hunt logs/ --since 2026-09-01 --until 2026-09-10 --rule-id 'iam-*'
zcat export.jsonl.gz | trailhunt hunt -              # stdin
trailhunt rules list | validate | test
```

Exit codes: `0` success, `1` findings at/above `--fail-on` (or failing rule tests /
invalid rules for `rules validate|test`), `2` usage or input error.

## Input and normalization

* **Formats:** CloudTrail delivery files (`{"Records": [...]}`), plain or gzip;
  JSON Lines / NDJSON (streamed line by line, plain or gzip, e.g. CloudTrail Lake
  or Athena exports, including lower-cased Athena column names, nested objects
  serialized as JSON strings and `eventJson` columns); JSON arrays; single events;
  directories (recursive; `CloudTrail-Digest` files skipped); `-` for stdin.
* **Ordering:** files in a directory are ordered by the delivery timestamp in
  CloudTrail object names (`..._CloudTrail_<region>_YYYYMMDDTHHMMZ_...`), so an
  `AWSLogs/` tree is read near-chronologically across regions; a bounded reorder
  buffer (`--reorder-buffer`, default 20,000 events) restores strict time order.
  Events that arrive later than the buffer can absorb are still processed and
  counted as `late` in the run summary.
* **Duplicates:** duplicate deliveries are dropped by `eventID` (bounded LRU).
* **Actors:** every event gets a stable `actor` key:

  | userIdentity.type | actor |
  |---|---|
  | `Root` | `arn:aws:iam::<acct>:root` |
  | `IAMUser` | the user ARN (also derived for failed logins that carry only a user name) |
  | `AssumedRole` | the **role** ARN from `sessionContext.sessionIssuer` (all CI runs / Lambda invocations / instances of a role are one actor; the session name is kept in `session_name`). IAM Identity Center roles (`AWSReservedSSO_*`) keep the session (the human): `<role-arn>/<session>` |
  | `AWSService` | `service:<invokedBy>` |
  | `AWSAccount` | `account:<accountId>` |
  | `FederatedUser`, `SAMLUser`, `WebIdentityUser`, `IdentityCenterUser` | ARN / `type:userName` |

* **Derived fields** usable in rules: `actor`, `actor_type`, `actor_name`,
  `session_name`, `access_key_id`, `account_id`, `is_root`, `src_ip`, `ua_family`
  (`aws-cli`, `boto3`, `terraform`, `console`, `sdk-go`, `aws-service`, ...),
  `region`, `service`, `error`, `mfa`, `time`.

## Rule language

Rules are YAML (one per document, `---`-separated, or a list). Common keys:

```yaml
id: my-rule                 # unique, lowercase
title: Human readable title
type: match | threshold | sequence | new_value
severity: info | low | medium | high | critical
description: What it detects and why it matters.
attack: [T1098.001]         # MITRE ATT&CK technique ids (validated format)
falsepositives: [Known benign causes]
references: [https://...]   # optional
enabled: true               # optional
tests: {positive: [...], negative: [...]}   # see "Testing rules"
```

### Predicates

Used by `match` (and as filters by every other type):

```yaml
match:
  eventSource: iam.amazonaws.com              # scalar -> equals
  eventName: [CreateAccessKey, CreateLoginProfile]   # list -> in
  errorCode: {exists: false}                  # mapping -> operators, ANDed
  sourceIPAddress: {cidr: ["0.0.0.0/0", "::/0"]}
  requestParameters.userName: {exists: true, ne_field: userIdentity.userName}
  any:
    - userAgent: {regex: "(?i)kali"}
    - not: {ua_family: [console, aws-internal]}
```

* Several keys in one mapping are ANDed; `all: [...]`, `any: [...]`, `not: {...}` compose.
* **Field paths** are dotted; lists are traversed automatically
  (`requestParameters.ipPermissions.items.ipRanges.items.cidrIp` yields every CIDR),
  numeric segments index (`resources.0.ARN`). A path that resolves to several
  values matches if **any** value matches (`not_*` operators: if **none** does).
* **Operators:** `equals`, `not_equals`, `iequals`, `in`, `not_in`, `glob`, `not_glob`,
  `regex`, `not_regex`, `cidr`, `not_cidr` (IPv4/IPv6, addresses or networks),
  `exists`, `startswith`, `endswith`, `contains`, `gt`, `gte`, `lt`, `lte`,
  `eq_field`, `ne_field` (compare with another field of the same event).
  Equality is loose for booleans and numbers (`false` == `"false"`, `22` == `"22"`).
* **Transforms** (`field|transform`): `json` (parse an embedded JSON document,
  URL-decoding it first if needed - IAM policy documents), `account` (12-digit
  account id from an ARN), `net16` / `net24` (IPv4 /16 or /24, IPv6 /48 or /64),
  `lower`, `upper`, `str`, `len`. They chain with paths:
  `requestParameters.policyDocument|json.Statement.Principal.AWS|account`.
* Quote YAML 1.1 booleans you mean as strings: `MFAUsed: "No"`.

### 1. `match` - single event

```yaml
id: iam-access-key-for-other-user
title: Access key created for another IAM user
type: match
severity: medium
match:
  eventName: CreateAccessKey
  errorCode: {exists: false}
  requestParameters.userName: {exists: true, ne_field: userIdentity.userName}
suppress: 1h            # optional: after an alert, mute the same suppress_by key for 1h
suppress_by: [actor]    # default [actor]
```

### 2. `threshold` - count or count-distinct in a sliding window

```yaml
id: enumeration-burst
type: threshold
match:
  eventName: {regex: "^(List|Describe|Get)"}
  ua_family: {not_in: [console, aws-internal, aws-service]}
group_by: [actor]        # default [actor]; several fields allowed
window: 10m
distinct: eventName      # omit to count events
threshold: 25            # fire when count/distinct >= 25 within the window
suppress: 1h
```

The window is inclusive (events exactly `window` apart are together). After
firing, the group re-arms, so an ongoing storm produces one finding per
`threshold` new events unless `suppress` mutes it. A `distinct` field that is
a list counts each element (`SendCommand` to 12 instances in one call = 12).

### 3. `sequence` - ordered steps joined on a key

```yaml
id: iam-persistence-new-admin-user
type: sequence
by: [requestParameters.userName]   # join key (default [actor]); steps may override with their own `by`
within: 1h                         # max span from first to last step
steps:
  - name: user created
    match: {eventName: CreateUser, errorCode: {exists: false}}
  - name: access key created
    match: {eventName: CreateAccessKey, errorCode: {exists: false}}
  - name: admin privileges granted
    within: 30m                    # optional: max gap since the previous step
    match:
      any:
        - {eventName: AttachUserPolicy, requestParameters.policyArn: {glob: "*:policy/AdministratorAccess"}}
        - {eventName: PutUserPolicy, requestParameters.policyDocument|json.Statement.Action: "*"}
```

* `count: N` makes a step require N matches (brute force: 5 failed logins, then a
  success). Extra matches before the next step are attached to the finding.
* `absent: true` on the **last** step means "this did **not** happen within the
  step's `within`":

```yaml
id: cloudtrail-logging-not-restarted
type: sequence
by: [requestParameters.name]
within: 2h
steps:
  - {name: logging stopped, match: {eventName: StopLogging, errorCode: {exists: false}}}
  - {name: logging restarted, absent: true, within: 30m, match: {eventName: StartLogging}}
```

Implementation: a per-key state machine that keeps **at most one partial match per
step per key** (a newer partial match at the same step replaces an older one, which
has strictly less time left), so memory is bounded by keys x steps regardless of
volume. Expiry is checked lazily on access and by a periodic sweep; `absent` steps
use an event-time timer heap. Absence is only concluded once the data passes the
deadline - a pending absence at the end of the input is not reported.

### 4. `new_value` - first seen

```yaml
id: new-source-network-for-actor
type: new_value
match:                                   # optional filter
  actor_type: {not_in: [AWSService]}
  sourceIPAddress: {cidr: ["0.0.0.0/0", "::/0"]}   # skips "s3.amazonaws.com"-style sources
group_by: [actor]                        # [] = one global group
value: sourceIPAddress|net16             # one path, or a list for a composite value
baseline: 7d                             # learning period from the start of the data
on_new_group: learn                      # learn (default) or alert for groups first seen after the baseline
```

Values seen during the baseline are learned silently; afterwards each new
value for a group is reported once. With `--state FILE`, baselines are loaded at
start and saved at the end (atomically), so a daily job keeps learning across runs
and the learning period counts from the first data ever seen. Stored state is
ignored automatically if the rule's `group_by`/`value`/`match` change.

## Built-in rules

Generated by `trailhunt rules list --format markdown`:

| Rule | Type | Severity | ATT&CK | Logic |
|---|---|---|---|---|
| `cloudtrail-logging-disabled` | match | critical | T1562.008 | single event |
| `cloudtrail-logging-not-restarted` | sequence | critical | T1562.008 | logging stopped -> NOT logging restarted within 2h |
| `iam-persistence-new-admin-user` | sequence | critical | T1136.003, T1098.001, T1098.003 | user created -> access key created -> admin privileges granted within 1h |
| `cloudtrail-config-weakened` | match | high | T1562.008 | single event |
| `console-brute-force-success` | sequence | high | T1110.001, T1078.004 | failed sign-ins -> successful sign-in within 30m |
| `iam-login-profile-for-other-user` | match | high | T1098 | single event |
| `iam-role-trust-external-principal` | match | high | T1098.003, T1199 | single event |
| `kms-key-disabled-or-scheduled-deletion` | match | high | T1485, T1486 | single event |
| `root-account-usage` | match | high | T1078.004 | single event (suppress 1h per actor) |
| `s3-bucket-made-public` | match | high | T1530, T1537 | single event |
| `secrets-bulk-retrieval` | threshold | high | T1555.006 | >= 8 distinct requestParameters.secretId per actor in 10m |
| `security-group-opened-to-world` | match | high | T1562.007, T1133 | single event |
| `security-monitoring-disabled` | match | high | T1562.001 | single event |
| `snapshot-shared-externally` | match | high | T1537 | single event |
| `ssm-sendcommand-burst` | threshold | high | T1651 | >= 10 distinct requestParameters.instanceIds per actor in 15m |
| `access-denied-storm` | threshold | medium | T1580, T1526 | >= 15 events per actor in 5m (suppress 1h per actor) |
| `console-login-without-mfa` | match | medium | T1078.004 | single event |
| `ec2-userdata-modified` | match | medium | T1059.009, T1098 | single event |
| `enumeration-burst` | threshold | medium | T1580, T1087.004, T1069.003, T1526 | >= 25 distinct eventName per actor in 10m (suppress 1h per actor) |
| `iam-access-key-for-other-user` | match | medium | T1098.001 | single event |
| `iam-admin-policy-attached` | match | medium | T1098.003 | single event |
| `lambda-function-url-public` | match | medium | T1648, T1190 | single event |
| `offensive-tool-user-agent` | match | medium | T1078.004 | single event (suppress 1h per actor,src_ip) |
| `region-sweep` | threshold | medium | T1580, T1535 | >= 5 distinct awsRegion per actor in 15m (suppress 1h per actor) |
| `s3-public-access-block-removed` | match | medium | T1562.001, T1530 | single event |
| `sts-new-cross-account-role` | new_value | medium | T1550.001, T1078.004 | new requestParameters.roleArn per actor after 7d |
| `new-region-for-actor` | new_value | low | T1535 | new awsRegion per actor after 7d |
| `new-source-network-for-actor` | new_value | low | T1078.004 | new sourceIPAddress\|net16 per actor after 7d |
| `new-user-agent-for-actor` | new_value | low | T1078.004 | new ua_family per actor after 7d |

Rule sources live in [`src/trailhunt/rules/builtin/`](src/trailhunt/rules/builtin/);
each documents its false-positive cases.

## Findings

Every finding carries the rule id, title, severity, type, actor, first/last
time, the contributing events (eventID, time, eventName, source, region, IP,
error and a one-line summary with the key request parameters; up to 50 events
are kept, `event_count` has the total), ATT&CK ids, the group key, rule-specific
details (counts, distinct values, the new value, sequence steps) and a
**fingerprint**: a stable hash of rule id + group + contributing event IDs (or the
new value for `new_value` rules). Re-running on the same data yields the same
fingerprints, so they can be used to de-duplicate tickets across runs.

## Writing and testing your own rules

Put YAML files in a directory and add it with `--rules DIR` (repeatable; the
built-in pack is still loaded unless `--no-builtin`). Rule ids must be unique.

Rules embed their own unit tests. Events are ordinary CloudTrail records with
defaults filled in (an IAM user identity, time, region, IP, user agent, eventID),
plus helpers: `_at` (offset from the case start: `30s`, `5m`, `8d`), `_repeat` +
`_interval`, `_cycle` (`{field.path: [values...]}` per repeat), `_user: alice`
and `_role: RoleName/session` identity shorthands (test identities live in
account `111111111111`, cases start at `2026-01-05T00:00:00Z`).

```yaml
id: acme-prod-role-from-laptop
title: Production deploy role used outside CI
type: match
severity: high
attack: [T1078.004]
description: The deploy role should only ever be used by GitHub Actions.
falsepositives: [Break-glass deploys]
match:
  actor_name: github-actions-deploy
  not:
    sourceIPAddress: {cidr: [4.175.0.0/16, 20.57.0.0/16]}
tests:
  positive:
    - {eventName: UpdateService, _role: github-actions-deploy/me, sourceIPAddress: 198.51.100.7}
  negative:
    - {eventName: UpdateService, _role: github-actions-deploy/gha-1, sourceIPAddress: 4.175.1.2}
    - name: other role
      events:
        - {eventName: UpdateService, _role: other/x, sourceIPAddress: 198.51.100.7}
```

```bash
trailhunt rules validate --rules my-rules/   # schema check with file / rule / key-path errors
trailhunt rules test --rules my-rules/ -v    # run every positive and negative case
```

Validation is strict on purpose - typos are errors, not silently ignored keys:

```text
$ trailhunt rules validate --rules my-rules/x.yaml --no-builtin
my-rules/x.yaml: rule 'acme-x': treshold: unknown key for a 'threshold' rule (allowed: attack, author, description, distinct, enabled, falsepositives, group_by, id, match, references, severity, suppress, suppress_by, tags, tests, threshold, title, type, window)
my-rules/x.yaml: rule 'acme-x': threshold: required for 'threshold' rules
my-rules/x.yaml: rule 'acme-x': match.any[1].userAgent.regex: invalid regex: missing ), unterminated subpattern at position 0
my-rules/x.yaml: rule 'acme-y': steps[0].absent: only the last step of a sequence may be 'absent'
my-rules/x.yaml: rule 'acme-y': steps[0].absent: the first step cannot be 'absent'

5 error(s); 0 valid rule(s)
```

A positive case passes when the rule fires at least once (or exactly `expect: N`
times); a negative case passes when it does not fire. See
[CONTRIBUTING.md](CONTRIBUTING.md) for contributing rules upstream.

## Performance

Measured on the bundled sample and on a larger generated dataset, single process,
Windows 11, Python 3.13, Intel Core (28 logical CPUs; trailhunt uses one):

| Input | Events | Wall time | Throughput |
|---|---|---|---|
| `examples/sample-logs` (591 `.json.gz` files, 1.4 MB) | 11,575 | 0.52 s | ~22,000 events/s |
| 90-day dataset, 5,856 `.json.gz` files | 112,563 | 6.2-6.8 s | ~16,500-18,200 events/s |
| same 90 days as one JSON Lines file (117 MB) | 112,563 | 4.6 s | ~24,400 events/s |
| detection engine only (pre-parsed events, all 29 rules) | 112,563 | 2.2 s | ~50,000 events/s |

Numbers are end to end (decompression, JSON parsing, normalization, reordering,
all 29 rules, output) as reported by the run summary line. Notes:

* Rules are indexed by `eventName`, so most rules are never evaluated for most
  events; only rules without an `eventName` constraint run on every event.
* Memory is dominated by the reorder buffer, not detector state: peak traced
  Python memory was 109 MB with the default `--reorder-buffer 20000` and 33 MB
  with `--reorder-buffer 2000` (same findings, 0 late events) on the 90-day tree.
  Detector state is bounded by windows and key counts (sequence state is keys x steps).
* JSON Lines input is streamed; a single CloudTrail delivery file is loaded whole
  (they are small by design).
* Many small files cost more than one large file (per-file open/gzip overhead).
* trailhunt is single-threaded; for very large estates, split by account or time
  and run in parallel (stateful rules only correlate within one run).

## Limitations

* **Offline only.** There is no S3 or CloudTrail Lake fetching; export or sync the
  logs first (`aws s3 sync s3://bucket/AWSLogs/ ./AWSLogs/`).
* **Management events focus.** The rules target management events. Data events
  (S3 object access, Lambda invoke) are ingested and can be used in custom rules,
  but there are no built-in data-event detections yet.
* **Correlation is per run.** Only `new_value` baselines persist (`--state`).
  Threshold windows and partial sequences do not carry across separate runs, so a
  sequence split across two runs' inputs is not joined.
* **Absent steps** must be last in a sequence, and are not concluded when the data
  ends before the deadline.
* **Sequence semantics** keep the most recent partial match per step and key; this
  bounds memory but means overlapping instances of the same chain for the same key
  are reported once.
* **Approximations:** `security-group-opened-to-world` checks CIDR and port across
  all permissions of a call, not per permission; `s3-bucket-made-public` does not
  evaluate policy `Condition`s; IAM policy evaluation is not modelled.
* **Late events.** Events more out of order than the reorder buffer are still
  processed (and counted) but may miss windows. Increase `--reorder-buffer` for
  unusual inputs.
* **Synthetic validation.** The precision and recall checks run on synthetic
  data. Expect to tune thresholds and allowlists (with `not:` filters in your
  own rules) for your environment; the `falsepositives` notes say where.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest                      # unit, engine, CLI and end-to-end dataset tests
trailhunt rules test        # rule unit tests
python examples/generate_dataset.py --force               # regenerate the sample (deterministic)
python examples/generate_dataset.py --no-attack --days 14 --jsonl benign.jsonl
```

## Security

Please report vulnerabilities privately - see [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE). Copyright (c) 2026 Opsbreak Inc.

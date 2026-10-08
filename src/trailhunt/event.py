"""CloudTrail event normalization.

Every raw record is wrapped in an :class:`Event` exposing the original
document plus derived, analysis-friendly fields:

========== ==================================================================
actor        stable principal key (see :func:`derive_actor`)
actor_type   userIdentity.type (Root, IAMUser, AssumedRole, AWSService, ...)
actor_name   short human readable name (user name, role name, ...)
session_name assumed-role / federated session name, if any
access_key_id  access key used for the call, if any
account_id   account of the calling principal
is_root      True for the account root user
src_ip       sourceIPAddress
ua_family    coarse user agent family (aws-cli, boto3, console, terraform, ...)
region       awsRegion
service      eventSource without ``.amazonaws.com``
error        errorCode
mfa          True/False when MFA usage is known, else missing
time         ISO-8601 event time
========== ==================================================================

Derived fields can be used in rules exactly like raw paths (``actor``,
``ua_family``); raw CloudTrail keys are camelCase so the names never clash.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from typing import Any

from trailhunt.fieldpath import parse_path, resolve_segments
from trailhunt.timeutil import iso, parse_time

DERIVED_FIELDS = frozenset(
    {
        "actor",
        "actor_type",
        "actor_name",
        "session_name",
        "access_key_id",
        "account_id",
        "is_root",
        "src_ip",
        "ua_family",
        "region",
        "service",
        "error",
        "mfa",
        "time",
    }
)

_JSON_STRING_FIELDS = (
    "userIdentity",
    "requestParameters",
    "responseElements",
    "additionalEventData",
    "resources",
    "serviceEventDetails",
    "tlsDetails",
    "insightDetails",
)

_CANONICAL_TOP = {
    k.lower(): k
    for k in (
        "eventVersion",
        "userIdentity",
        "eventTime",
        "eventSource",
        "eventName",
        "awsRegion",
        "sourceIPAddress",
        "userAgent",
        "errorCode",
        "errorMessage",
        "requestParameters",
        "responseElements",
        "additionalEventData",
        "requestID",
        "eventID",
        "readOnly",
        "resources",
        "eventType",
        "apiVersion",
        "managementEvent",
        "recipientAccountId",
        "serviceEventDetails",
        "sharedEventID",
        "vpcEndpointId",
        "eventCategory",
        "tlsDetails",
        "sessionCredentialFromConsole",
        "invokedBy",
    )
}
_CANONICAL_IDENTITY = {
    k.lower(): k
    for k in (
        "type",
        "principalId",
        "arn",
        "accountId",
        "accessKeyId",
        "userName",
        "sessionContext",
        "sessionIssuer",
        "attributes",
        "mfaAuthenticated",
        "creationDate",
        "invokedBy",
        "webIdFederationData",
        "sourceIdentity",
        "identityProvider",
        "onBehalfOf",
        "credentialId",
        "federatedProvider",
        "ec2RoleDelivery",
        "assumedRoot",
    )
}


def _canon_identity(v: Any) -> Any:
    if isinstance(v, dict):
        return {
            _CANONICAL_IDENTITY.get(k.lower(), k) if isinstance(k, str) else k: _canon_identity(x)
            for k, x in v.items()
        }
    return v


def normalize_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Repair records coming from CloudTrail Lake / Athena style exports.

    * ``eventJson`` / ``eventjson`` string columns are expanded.
    * Lower-cased Athena column names are mapped back to CloudTrail camelCase.
    * Nested objects serialized as JSON strings are decoded.
    """
    ej = rec.get("eventJson") or rec.get("eventjson")
    if isinstance(ej, str):
        try:
            inner = json.loads(ej)
            if isinstance(inner, dict):
                rec = inner
        except ValueError:
            pass
    lowercase = "eventTime" not in rec and "eventtime" in rec
    if lowercase:
        rec = {_CANONICAL_TOP.get(k.lower(), k) if isinstance(k, str) else k: v for k, v in rec.items()}
    for key in _JSON_STRING_FIELDS:
        v = rec.get(key)
        if isinstance(v, str) and v[:1] in ("{", "["):
            with contextlib.suppress(ValueError):
                rec[key] = json.loads(v)
    if lowercase and isinstance(rec.get("userIdentity"), dict):
        rec["userIdentity"] = _canon_identity(rec["userIdentity"])
    if isinstance(rec.get("userIdentity"), str) and rec["userIdentity"].lower() in ("", "null"):
        rec["userIdentity"] = {}
    return rec


def _arn_tail(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]


def _role_arn_from_session_arn(arn: str) -> str | None:
    # arn:aws:sts::123456789012:assumed-role/RoleName/session
    try:
        prefix, rest = arn.split(":assumed-role/", 1)
    except ValueError:
        return None
    partition_acct = prefix.split(":")
    if len(partition_acct) < 5:
        return None
    partition, acct = partition_acct[1], partition_acct[4]
    role_name = rest.split("/", 1)[0]
    return f"arn:{partition}:iam::{acct}:role/{role_name}"


def derive_actor(ui: dict[str, Any], raw: dict[str, Any]) -> tuple[str, str, str, str | None, str | None]:
    """Return ``(actor, actor_type, actor_name, session_name, account_id)``.

    * Root -> ``arn:aws:iam::<acct>:root``
    * IAMUser -> the user ARN
    * AssumedRole -> the *role* ARN (sessionContext.sessionIssuer), so every
      session of a role (CI runs, Lambda invocations) shares one actor. For IAM
      Identity Center roles (``AWSReservedSSO_*``) the session name identifies
      a human, so it is appended: ``<role-arn>/<session>``.
    * AWSService -> ``service:<invokedBy>``
    * AWSAccount -> ``account:<accountId>``
    * anything else -> ARN, access key or principal id.
    """
    t = ui.get("type") or ("AWSService" if raw.get("invokedBy") else "Unknown")
    arn = ui.get("arn") or ""
    acct = ui.get("accountId") or None
    session: str | None = None
    if t == "Root":
        a = acct or raw.get("recipientAccountId") or "unknown"
        return (arn or f"arn:aws:iam::{a}:root", t, "root", None, acct)
    if t == "IAMUser":
        name = ui.get("userName") or (_arn_tail(arn) if arn else ui.get("principalId") or "unknown")
        a = acct or raw.get("recipientAccountId") or "unknown"
        return (arn or f"arn:aws:iam::{a}:user/{name}", t, name, None, acct)
    if t == "AssumedRole":
        sc = ui.get("sessionContext") or {}
        issuer = sc.get("sessionIssuer") or {} if isinstance(sc, dict) else {}
        role_arn = issuer.get("arn") if issuer.get("type", "Role") == "Role" else None
        if not role_arn and arn:
            role_arn = _role_arn_from_session_arn(arn)
        role_name = issuer.get("userName") or (_arn_tail(role_arn) if role_arn else "unknown-role")
        if arn and ":assumed-role/" in arn:
            session = arn.rsplit("/", 1)[-1]
        else:
            pid = ui.get("principalId") or ""
            session = pid.split(":", 1)[1] if ":" in pid else None
        if not role_arn:
            role_arn = arn or f"role:{ui.get('principalId', 'unknown')}"
        if role_name.startswith("AWSReservedSSO_") and session:
            return (f"{role_arn}/{session}", t, f"{role_name}/{session}", session, acct)
        return (role_arn, t, role_name, session, acct)
    if t == "FederatedUser":
        session = _arn_tail(arn) if arn else None
        return (
            arn or f"federated:{ui.get('principalId', 'unknown')}",
            t,
            session or "federated",
            session,
            acct,
        )
    if t == "AWSService":
        svc = ui.get("invokedBy") or raw.get("invokedBy") or raw.get("sourceIPAddress") or "unknown"
        return (f"service:{svc}", t, svc, None, acct)
    if t == "AWSAccount":
        a = acct or "unknown"
        return (f"account:{a}", t, a, None, acct)
    if t in ("SAMLUser", "WebIdentityUser"):
        name = ui.get("userName") or ui.get("principalId") or "unknown"
        return (f"{t}:{name}", t, name, None, acct)
    if t == "IdentityCenterUser":
        obo = ui.get("onBehalfOf") or {}
        name = obo.get("userId") if isinstance(obo, dict) else None
        name = name or ui.get("userName") or ui.get("principalId") or "unknown"
        return (f"identitycenter:{name}", t, name, None, acct)
    key = arn or ui.get("accessKeyId") or ui.get("principalId") or ui.get("userName") or "unknown"
    return (key, t, _arn_tail(key) if key.startswith("arn:") else key, None, acct)


_UA_RULES: tuple[tuple[str, str], ...] = (
    # IaC tools embed the SDK they use in their user agent, so they go first.
    ("terraform", "terraform"),
    ("pulumi", "pulumi"),
    ("aws-cdk", "cdk"),
    ("aws-cli/", "aws-cli"),
    ("boto3/", "boto3"),
    ("botocore/", "boto3"),
    ("aws-sdk-go", "sdk-go"),
    ("aws-sdk-java", "sdk-java"),
    ("aws-sdk-js", "sdk-js"),
    ("aws-sdk-nodejs", "sdk-js"),
    ("aws-sdk-dotnet", "sdk-dotnet"),
    ("aws-sdk-ruby", "sdk-ruby"),
    ("aws-sdk-php", "sdk-php"),
    ("aws-sdk-rust", "sdk-rust"),
    ("aws-sdk-cpp", "sdk-cpp"),
    ("aws-powershell", "powershell"),
    ("awspowershell", "powershell"),
    ("cloudformation", "cloudformation"),
    ("python-requests", "python-requests"),
    ("curl/", "curl"),
    ("go-http-client", "go-http"),
    ("console.amazonaws.com", "console"),
    ("signin.amazonaws.com", "console"),
    ("console.ec2.amazonaws.com", "console"),
    ("s3console", "console"),
    ("mozilla/", "console"),
    ("aws internal", "aws-internal"),
)


def ua_family(ua: str | None) -> str:
    if not ua:
        return "none"
    low = ua.lower().lstrip("[")
    for needle, fam in _UA_RULES:
        if needle in low:
            return fam
    if low.endswith(".amazonaws.com"):
        return "aws-service"
    head = low.split("/", 1)[0].split(" ", 1)[0]
    return head[:32] or "other"


def _mfa(raw: dict[str, Any], ui: dict[str, Any]) -> bool | None:
    aed = raw.get("additionalEventData")
    if isinstance(aed, dict) and "MFAUsed" in aed:
        return str(aed["MFAUsed"]).lower() == "yes"
    sc = ui.get("sessionContext")
    if isinstance(sc, dict):
        attrs = sc.get("attributes")
        if isinstance(attrs, dict) and "mfaAuthenticated" in attrs:
            return str(attrs["mfaAuthenticated"]).lower() == "true"
    return None


_SUMMARY_KEYS = (
    "userName",
    "roleName",
    "roleArn",
    "policyArn",
    "policyName",
    "bucketName",
    "name",
    "trailName",
    "snapshotId",
    "dBSnapshotIdentifier",
    "instanceId",
    "instanceIds",
    "groupId",
    "secretId",
    "keyId",
    "functionName",
    "authType",
    "detectorId",
    "configurationRecorderName",
    "attributeName",
    "documentName",
    "roleSessionName",
    "volumeId",
    "imageId",
)


@dataclass(slots=True, frozen=True)
class EventRef:
    """A compact, serializable reference to an event kept inside findings and detector state."""

    ts: float
    event_id: str
    event_name: str
    service: str
    region: str
    actor: str
    src_ip: str
    error: str | None
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventID": self.event_id,
            "eventTime": iso(self.ts),
            "eventName": self.event_name,
            "eventSource": f"{self.service}.amazonaws.com" if self.service else "",
            "awsRegion": self.region,
            "actor": self.actor,
            "sourceIPAddress": self.src_ip,
            "errorCode": self.error,
            "summary": self.summary,
        }


_DERIVED_GETTERS: dict[str, Any] = {
    "actor": lambda e: e.actor,
    "actor_type": lambda e: e.actor_type,
    "actor_name": lambda e: e.actor_name,
    "session_name": lambda e: e.session_name,
    "access_key_id": lambda e: e.access_key_id,
    "account_id": lambda e: e.account_id,
    "is_root": lambda e: e.is_root,
    "src_ip": lambda e: e.src_ip or None,
    "ua_family": lambda e: e.ua_family,
    "region": lambda e: e.region or None,
    "service": lambda e: e.service or None,
    "error": lambda e: e.error_code,
    "mfa": lambda e: e.mfa,
    "time": lambda e: iso(e.ts),
}


class Event:
    """A normalized CloudTrail event."""

    __slots__ = (
        "_derived",
        "_ref",
        "access_key_id",
        "account_id",
        "actor",
        "actor_name",
        "actor_type",
        "error_code",
        "event_id",
        "event_name",
        "event_source",
        "is_root",
        "mfa",
        "raw",
        "region",
        "service",
        "session_name",
        "src_ip",
        "ts",
        "ua_family",
        "user_agent",
    )

    def __init__(self, raw: dict[str, Any], ts: float) -> None:
        self.raw = raw
        self.ts = ts
        ui = raw.get("userIdentity")
        if not isinstance(ui, dict):
            ui = {}
        self.event_id = str(raw.get("eventID") or "")
        self.event_name = str(raw.get("eventName") or "")
        self.event_source = str(raw.get("eventSource") or "")
        self.service = self.event_source.removesuffix(".amazonaws.com")
        self.region = str(raw.get("awsRegion") or "")
        self.actor, self.actor_type, self.actor_name, self.session_name, self.account_id = derive_actor(
            ui, raw
        )
        self.access_key_id = ui.get("accessKeyId") or None
        self.is_root = self.actor_type == "Root"
        self.src_ip = str(raw.get("sourceIPAddress") or "")
        self.user_agent = str(raw.get("userAgent") or "")
        self.ua_family = ua_family(self.user_agent)
        self.error_code = raw.get("errorCode") or None
        self.mfa = _mfa(raw, ui)
        self._derived: dict[str, Any] | None = None
        self._ref: EventRef | None = None

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> Event | None:
        if not isinstance(rec, dict):
            return None
        rec = normalize_record(rec)
        ts = parse_time(rec.get("eventTime"))
        if ts is None:
            return None
        return cls(rec, ts)

    def derived(self) -> dict[str, Any]:
        """All derived fields as a dictionary (used by ``--format json`` style consumers)."""
        d = self._derived
        if d is None:
            d = {name: getter(self) for name, getter in _DERIVED_GETTERS.items()}
            self._derived = d
        return d

    def values(self, path: str) -> list[Any]:
        """Resolve a field path (raw or derived) to a flat list of values.

        (A per-event memo of results was measured to be slower than this
        direct walk, so there is none.)
        """
        segs = parse_path(path)
        first = segs[0][0]
        if first in DERIVED_FIELDS:
            root: Any = {first: _DERIVED_GETTERS[first](self)}
        else:
            root = self.raw
        # Fast path: plain dictionary walk without lists or transforms (the common case).
        cur = root
        for key, transforms in segs:
            if transforms or not isinstance(cur, dict):
                return resolve_segments(root, segs)
            cur = cur.get(key)
            if cur is None:
                return []
        if isinstance(cur, list):
            return resolve_segments(root, segs)
        return [cur]

    def first(self, path: str) -> Any:
        v = self.values(path)
        return v[0] if v else None

    def summary(self) -> str:
        parts = [f"{self.service}:{self.event_name}"]
        rp = self.raw.get("requestParameters")
        if isinstance(rp, dict):
            shown = 0
            for k in _SUMMARY_KEYS:
                if k in rp and shown < 3:
                    v = rp[k]
                    if isinstance(v, dict) and isinstance(v.get("items"), list):
                        v = [i.get("instanceId", i) if isinstance(i, dict) else i for i in v["items"]]
                    if isinstance(v, list):
                        txt = ",".join(str(x) for x in v[:3]) + (f",+{len(v) - 3}" if len(v) > 3 else "")
                    elif isinstance(v, (dict,)):
                        continue
                    else:
                        txt = str(v)
                    if len(txt) > 80:
                        txt = txt[:77] + "..."
                    parts.append(f"{k}={txt}")
                    shown += 1
        if self.event_name == "ConsoleLogin":
            re_ = self.raw.get("responseElements")
            if isinstance(re_, dict) and re_.get("ConsoleLogin"):
                parts.append(f"result={re_['ConsoleLogin']}")
            if self.mfa is not None:
                parts.append(f"mfa={'yes' if self.mfa else 'no'}")
        if self.error_code:
            parts.append(f"[{self.error_code}]")
        return " ".join(parts)

    def ref(self) -> EventRef:
        r = self._ref
        if r is None:
            r = EventRef(
                ts=self.ts,
                event_id=self.event_id,
                event_name=self.event_name,
                service=self.service,
                region=self.region,
                actor=self.actor,
                src_ip=self.src_ip,
                error=self.error_code,
                summary=self.summary(),
            )
            self._ref = r
        return r

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Event({iso(self.ts)} {self.service}:{self.event_name} {self.actor})"

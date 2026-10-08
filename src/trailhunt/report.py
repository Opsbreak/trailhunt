"""Finding renderers: text, json, jsonl, markdown."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from trailhunt.engine import Finding
from trailhunt.rules import SEV_RANK, SEVERITIES
from trailhunt.timeutil import iso

TEXT_EVENTS = 8


def _fmt_detail_value(v: Any) -> str:
    if isinstance(v, list):
        shown = ", ".join(str(x) for x in v[:8])
        return f"[{shown}{', ...' if len(v) > 8 else ''}]"
    return str(v)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s: c[s] for s in reversed(SEVERITIES) if c[s]}


def summary_line(findings: list[Finding]) -> str:
    if not findings:
        return "0 findings"
    counts = ", ".join(f"{n} {s}" for s, n in severity_counts(findings).items())
    return f"{len(findings)} finding{'s' if len(findings) != 1 else ''} ({counts})"


def render_text(findings: list[Finding]) -> str:
    lines: list[str] = []
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id} - {f.title}")
        lines.append(f"  actor   : {f.actor}")
        span = iso(f.first_ts) if f.first_ts == f.last_ts else f"{iso(f.first_ts)} .. {iso(f.last_ts)}"
        lines.append(f"  when    : {span} ({f.event_count} event{'s' if f.event_count != 1 else ''})")
        if f.group and list(f.group) != ["actor"]:
            lines.append("  group   : " + ", ".join(f"{k}={v}" for k, v in f.group.items()))
        if f.details:
            det = "; ".join(
                f"{k}={_fmt_detail_value(v)}" for k, v in f.details.items() if k != "known_values"
            )
            lines.append(f"  details : {det}")
        if f.attack:
            lines.append(f"  att&ck  : {', '.join(f.attack)}")
        lines.append(f"  id      : {f.fingerprint}")
        lines.append("  events  :")
        for e in f.events[:TEXT_EVENTS]:
            lines.append(f"    {iso(e.ts)}  {e.summary}  ({e.region or '-'}, {e.src_ip or '-'}) {e.event_id}")
        if f.event_count > TEXT_EVENTS:
            lines.append(f"    ... {f.event_count - TEXT_EVENTS} more")
        lines.append("")
    lines.append(summary_line(findings))
    return "\n".join(lines)


def render_jsonl(findings: list[Finding]) -> str:
    return "\n".join(json.dumps(f.to_dict(), sort_keys=False) for f in findings) + ("\n" if findings else "")


def render_json(findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
    doc = {
        "summary": {"total": len(findings), "by_severity": severity_counts(findings), **(meta or {})},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2) + "\n"


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(findings: list[Finding]) -> str:
    out = ["# trailhunt findings", "", f"**{summary_line(findings)}**", ""]
    if not findings:
        return "\n".join(out) + "\n"
    out += ["| Severity | Rule | Actor | First seen | Events | ATT&CK |", "|---|---|---|---|---|---|"]
    for f in findings:
        out.append(
            f"| {f.severity} | `{f.rule_id}` | `{_md_escape(f.actor)}` | {iso(f.first_ts)} | {f.event_count} "
            f"| {', '.join(f.attack)} |"
        )
    out.append("")
    for f in findings:
        out += [f"## [{f.severity.upper()}] {_md_escape(f.title)}", ""]
        out.append(f"- **Rule:** `{f.rule_id}` ({f.rule_type})")
        out.append(f"- **Actor:** `{_md_escape(f.actor)}`")
        out.append(f"- **Window:** {iso(f.first_ts)} - {iso(f.last_ts)}")
        if f.attack:
            out.append(f"- **ATT&CK:** {', '.join(f.attack)}")
        if f.details:
            out.append(
                "- **Details:** "
                + "; ".join(f"{k}={_md_escape(_fmt_detail_value(v))}" for k, v in f.details.items())
            )
        out.append(f"- **Fingerprint:** `{f.fingerprint}`")
        out += ["", "| Time | Event | Region | Source IP | Event ID |", "|---|---|---|---|---|"]
        for e in f.events:
            out.append(
                f"| {iso(e.ts)} | {_md_escape(e.summary)} | {e.region} | {e.src_ip} | `{e.event_id}` |"
            )
        if f.event_count > len(f.events):
            out.append(f"\n_{f.event_count - len(f.events)} more events omitted._")
        out.append("")
    return "\n".join(out) + "\n"


def filter_findings(findings: list[Finding], min_severity: str | None) -> list[Finding]:
    if not min_severity:
        return findings
    floor = SEV_RANK[min_severity]
    return [f for f in findings if SEV_RANK[f.severity] >= floor]

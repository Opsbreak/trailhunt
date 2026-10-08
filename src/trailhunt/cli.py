"""Command line interface.

Exit codes: 0 = success, 1 = findings at or above ``--fail-on`` (or failing
rule tests / invalid rules), 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import json
import os
import sys
import time
from collections.abc import Sequence
from typing import Any

from trailhunt import __version__
from trailhunt.analysis import build_timeline, compute_stats, render_stats, render_timeline
from trailhunt.engine import Engine, sort_findings
from trailhunt.ingest import IngestStats, iter_events
from trailhunt.pathutil import long_path
from trailhunt.report import (
    filter_findings,
    render_json,
    render_jsonl,
    render_markdown,
    render_text,
    summary_line,
)
from trailhunt.rules import SEV_RANK, SEVERITIES, Rule, collect_rules
from trailhunt.testing import run_rule_tests
from trailhunt.timeutil import DurationError, format_duration, parse_cli_time, parse_duration


class CliError(Exception):
    pass


def _err(msg: str) -> None:
    print(f"trailhunt: {msg}", file=sys.stderr)


def _add_rule_args(p: argparse.ArgumentParser, *, with_filter: bool = True) -> None:
    p.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="extra rule file or directory (repeatable); built-in rules are included unless --no-builtin",
    )
    p.add_argument("--no-builtin", action="store_true", help="do not load the built-in rule pack")
    if with_filter:
        p.add_argument(
            "--rule-id",
            action="append",
            default=[],
            metavar="ID",
            help="only run rules whose id matches (glob, repeatable)",
        )


def _add_input_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="CloudTrail file(s) or directories (.json, .json.gz, JSON Lines); '-' for stdin",
    )
    p.add_argument("--since", help="ignore events before this time (ISO-8601)")
    p.add_argument("--until", help="ignore events at or after this time (ISO-8601)")
    p.add_argument(
        "--reorder-buffer",
        type=int,
        default=20000,
        metavar="N",
        help="events held to restore time order (default 20000)",
    )


def _load_rules(args: argparse.Namespace) -> list[Rule]:
    rules, errors = collect_rules(args.rules, builtin=not args.no_builtin)
    if errors:
        raise CliError("invalid rules:\n  " + "\n  ".join(errors))
    pats = getattr(args, "rule_id", None) or []
    if pats:
        rules = [r for r in rules if any(fnmatch.fnmatchcase(r.id, p) for p in pats)]
        if not rules:
            raise CliError(f"no rule matches --rule-id {' '.join(pats)}")
    return rules


def _time_window(args: argparse.Namespace) -> tuple[float | None, float | None]:
    try:
        since = parse_cli_time(args.since) if args.since else None
        until = parse_cli_time(args.until) if args.until else None
    except ValueError as exc:
        raise CliError(str(exc)) from None
    return since, until


def _check_paths(paths: list[str]) -> None:
    for p in paths:
        if p != "-" and not os.path.exists(long_path(p)):
            raise CliError(f"{p}: no such file or directory")


def _report_ingest(stats: IngestStats, elapsed: float, quiet: bool) -> None:
    for e in stats.errors[:10]:
        _err(f"warning: {e}")
    if len(stats.errors) > 10:
        _err(f"warning: ... {len(stats.errors) - 10} more input warnings")
    if quiet:
        return
    rate = stats.events / elapsed if elapsed > 0 else 0.0
    extra = []
    if stats.duplicates:
        extra.append(f"{stats.duplicates} duplicates dropped")
    if stats.malformed:
        extra.append(f"{stats.malformed} malformed")
    if stats.late:
        extra.append(f"{stats.late} late beyond reorder buffer")
    if stats.filtered:
        extra.append(f"{stats.filtered} outside --since/--until")
    tail = f" ({', '.join(extra)})" if extra else ""
    print(
        f"trailhunt: {stats.events} events from {stats.files} files in {elapsed:.2f}s "
        f"({rate:,.0f} events/s){tail}",
        file=sys.stderr,
    )


def _load_state(path: str | None) -> dict[str, Any] | None:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot read state file {path}: {exc}") from None
    if not isinstance(data, dict):
        raise CliError(f"state file {path} is not a JSON object")
    return data


def _save_state(path: str, state: dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, separators=(",", ":"))
    os.replace(tmp, path)


def cmd_hunt(args: argparse.Namespace) -> int:
    _check_paths(args.paths)
    rules = _load_rules(args)
    since, until = _time_window(args)
    state = _load_state(args.state)
    engine = Engine(rules, state=state)
    stats = IngestStats()
    t0 = time.perf_counter()
    findings = engine.run(
        iter_events(args.paths, stats, since=since, until=until, reorder=args.reorder_buffer)
    )
    elapsed = time.perf_counter() - t0
    _report_ingest(stats, elapsed, args.quiet)
    if args.state:
        _save_state(args.state, engine.export_state(state))
    findings = filter_findings(sort_findings(findings), args.min_severity)
    meta = {"events": stats.events, "files": stats.files, "rules": len(rules)}
    if args.format == "json":
        text = render_json(findings, meta)
    elif args.format == "jsonl":
        text = render_jsonl(findings)
    elif args.format == "markdown":
        text = render_markdown(findings)
    else:
        text = render_text(findings) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        if not args.quiet:
            _err(f"{summary_line(findings)} written to {args.output}")
    else:
        sys.stdout.write(text)
    if args.fail_on:
        floor = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] >= floor for f in findings):
            return 1
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    _check_paths(args.paths)
    rules = _load_rules(args)
    since, until = _time_window(args)
    try:
        bucket = parse_duration(args.bucket)
    except DurationError as exc:
        raise CliError(str(exc)) from None
    if bucket <= 0:
        raise CliError("--bucket must be > 0")
    stats = IngestStats()
    tl = build_timeline(
        iter_events(args.paths, stats, since=since, until=until, reorder=args.reorder_buffer),
        rules,
        args.actor,
    )
    for e in stats.errors[:10]:
        _err(f"warning: {e}")
    try:
        display_since = parse_cli_time(args.display_since) if args.display_since else None
    except ValueError as exc:
        raise CliError(str(exc)) from None
    sys.stdout.write(render_timeline(tl, bucket=bucket, limit=args.limit, display_since=display_since))
    return 0 if tl.events else 1


def cmd_stats(args: argparse.Namespace) -> int:
    _check_paths(args.paths)
    since, until = _time_window(args)
    stats = IngestStats()
    st = compute_stats(iter_events(args.paths, stats, since=since, until=until, reorder=args.reorder_buffer))
    for e in stats.errors[:10]:
        _err(f"warning: {e}")
    sys.stdout.write(render_stats(st, args.top, args.format))
    return 0


def _rule_row(r: Rule) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": r.id,
        "type": r.type,
        "severity": r.severity,
        "title": r.title,
        "attack": r.attack,
        "source": r.source,
    }
    if r.type == "threshold":
        d["logic"] = (
            f">= {r.threshold} {'distinct ' + r.distinct if r.distinct else 'events'} "
            f"per {','.join(r.group_by)} in {format_duration(r.window)}"
        )
    elif r.type == "sequence":
        chain = " -> ".join(("NOT " if s.absent else "") + s.name for s in r.steps)
        d["logic"] = f"{chain} within {format_duration(r.within)}"
    elif r.type == "new_value":
        d["logic"] = (
            f"new {','.join(r.value)} per {','.join(r.group_by) or 'all'} after {format_duration(r.baseline)}"
        )
    else:
        d["logic"] = "single event"
    if r.suppress:
        d["logic"] += f" (suppress {format_duration(r.suppress)} per {','.join(r.suppress_by)})"
    return d


def cmd_rules(args: argparse.Namespace) -> int:
    if args.action == "validate":
        rules, errors = collect_rules(args.rules, builtin=not args.no_builtin)
        if errors:
            for e in errors:
                print(e)
            print(f"\n{len(errors)} error(s); {len(rules)} valid rule(s)")
            return 1
        print(f"OK: {len(rules)} rule(s) valid")
        return 0
    rules = _load_rules(args)
    if args.action == "list":
        rows = [_rule_row(r) for r in sorted(rules, key=lambda r: (-r.rank, r.id))]
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        elif args.format == "markdown":
            print("| Rule | Type | Severity | ATT&CK | Logic |")
            print("|---|---|---|---|---|")
            for d in rows:
                logic = d["logic"].replace("|", "\\|")
                print(f"| `{d['id']}` | {d['type']} | {d['severity']} | {', '.join(d['attack'])} | {logic} |")
        else:
            w = max(len(d["id"]) for d in rows) if rows else 10
            for d in rows:
                print(f"{d['severity']:<9} {d['type']:<10} {d['id']:<{w}}  {d['title']}")
            print(f"\n{len(rows)} rules")
        return 0
    # test
    total = failed = untested = 0
    for r in rules:
        results = run_rule_tests(r)
        if not results:
            untested += 1
            if args.verbose:
                print(f"SKIP {r.id}: no tests")
            continue
        bad = [c for c in results if not c.passed]
        total += len(results)
        failed += len(bad)
        if bad or args.verbose:
            status = "FAIL" if bad else "PASS"
            print(f"{status} {r.id} ({len(results) - len(bad)}/{len(results)})")
            for c in results:
                if not c.passed or args.verbose:
                    print(f"    {'ok  ' if c.passed else 'FAIL'} {c.kind}: {c.name} - {c.message}")
    print(
        f"{len(rules)} rules, {total} test cases: {total - failed} passed, {failed} failed"
        + (f", {untested} rules without tests" if untested else "")
    )
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trailhunt",
        description="Offline AWS CloudTrail threat hunting with stateful correlation.",
    )
    p.add_argument("--version", action="version", version=f"trailhunt {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("hunt", help="run detection rules over CloudTrail logs")
    _add_input_args(h)
    _add_rule_args(h)
    h.add_argument("--format", choices=["text", "jsonl", "json", "markdown"], default="text")
    h.add_argument("-o", "--output", help="write findings to a file instead of stdout")
    h.add_argument("--min-severity", choices=SEVERITIES, help="hide findings below this severity")
    h.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at or above this severity")
    h.add_argument("--state", metavar="FILE", help="baseline state for new_value rules (read and updated)")
    h.add_argument("-q", "--quiet", action="store_true", help="no progress/summary on stderr")
    h.set_defaults(func=cmd_hunt)

    t = sub.add_parser("timeline", help="per-actor activity timeline annotated with findings")
    _add_input_args(t)
    _add_rule_args(t)
    t.add_argument(
        "--actor", required=True, help="actor key, ARN, access key id, user/role name or session name"
    )
    t.add_argument("--bucket", default="1h", help="histogram bucket size (default 1h)")
    t.add_argument("--limit", type=int, default=400, help="max detail lines (default 400)")
    t.add_argument(
        "--display-since",
        metavar="TIME",
        help="only display activity from TIME on; unlike --since, older events still feed baselines "
        "and correlation",
    )
    t.set_defaults(func=cmd_timeline)

    s = sub.add_parser("stats", help="top actors, events, errors, regions, IPs")
    _add_input_args(s)
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.set_defaults(func=cmd_stats)

    r = sub.add_parser("rules", help="list, validate or test rules")
    r.add_argument("action", choices=["list", "validate", "test"])
    _add_rule_args(r)
    r.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="for 'list'")
    r.add_argument("-v", "--verbose", action="store_true", help="for 'test': show every case")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        _err(str(exc))
        return 2
    except BrokenPipeError:  # pragma: no cover - e.g. `trailhunt hunt ... | head`
        with contextlib.suppress(Exception):
            sys.stdout.close()
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

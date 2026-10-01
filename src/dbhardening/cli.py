"""Command line: assess and report here; collect, run-sql, harden and wait are added by their modules' tasks."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from dbhardening.findings import Finding, assess
from dbhardening.report import render_html, render_markdown, summary_text
from dbhardening.settings import load_settings
from dbhardening.snapshot import SnapshotError, load_snapshot

RANK = {"High": 3, "Medium": 2, "Low": 1}
ENGINE_CHOICES = ("mssql", "postgres")


def gate_failed(findings: Sequence[Finding], fail_on: str) -> bool:
    """True if a finding, or a not-evaluated check, is at or above the threshold."""
    limit = RANK[fail_on]
    return any(RANK[f.severity] >= limit for f in findings)


def cmd_assess(args: argparse.Namespace) -> int:
    settings = load_settings(args.settings)
    findings = assess(load_snapshot(args.snapshot), settings)
    for f in findings:
        print("\t".join((f.check_id, f.severity, f.status, f.object, f.detail)))
    print(summary_text(findings))
    if args.json:
        args.json.write_text(json.dumps([f.to_dict() for f in findings], indent=2) + "\n", encoding="utf-8")
    if args.fail_on and gate_failed(findings, args.fail_on):
        print(f"FAIL: findings at or above {args.fail_on} remain (not-evaluated checks count too).", file=sys.stderr)
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    settings = load_settings(args.settings)
    before_s, after_s = load_snapshot(args.before), load_snapshot(args.after)
    before, after = assess(before_s, settings), assess(after_s, settings)
    args.html.write_text(render_html(before_s, after_s, before, after), encoding="utf-8")
    args.markdown.write_text(render_markdown(before_s, after_s, before, after), encoding="utf-8")
    return 0


def _register_core(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("assess", help="run the checks on a snapshot")
    p.add_argument("snapshot", type=Path)
    p.add_argument("--settings", type=Path)
    p.add_argument("--fail-on", choices=list(RANK))
    p.add_argument("--json", type=Path)
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("report", help="before/after report (HTML + Markdown)")
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--html", type=Path, required=True)
    p.add_argument("--markdown", type=Path, required=True)
    p.add_argument("--settings", type=Path)
    p.set_defaults(func=cmd_report)


REGISTRARS: list[Callable[[argparse._SubParsersAction], None]] = [_register_core]  # type: ignore[type-arg]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dbhardening")
    sub = parser.add_subparsers(required=True)
    for register in REGISTRARS:
        register(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (SnapshotError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

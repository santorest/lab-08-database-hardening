"""Command line: collect, assess, report, run-sql, harden and wait."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

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


def connector(engine: str) -> Callable[..., Any]:
    from dbhardening.connect import mssql_connect, pg_connect

    if engine == "mssql":
        return lambda database=None, encrypt=True: mssql_connect(database, encrypt)
    return lambda database=None, encrypt=True: pg_connect(database)


def cmd_collect(args: argparse.Namespace) -> int:
    from dbhardening.collect_mssql import collect_mssql
    from dbhardening.collect_pg import collect_postgres
    from dbhardening.dbapi import describe_error
    from dbhardening.snapshot import save_snapshot

    settings = load_settings(args.settings)[args.engine]
    try:
        if args.engine == "mssql":
            snapshot = collect_mssql(connector("mssql"), settings)
        else:
            snapshot = collect_postgres(connector("postgres"), settings)
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001 - connection refused, login failed: a usage problem, exit 2
        print(f"error: cannot collect from {args.engine}: {describe_error(exc)}", file=sys.stderr)
        return 2
    save_snapshot(snapshot, args.out)
    print(f"{args.engine}: {len(snapshot['datasets'])} datasets -> {args.out}")
    return 0


def cmd_wait(args: argparse.Namespace) -> int:
    from dbhardening.dbapi import describe_error, rows

    connect = connector(args.engine)
    deadline = time.monotonic() + args.timeout
    last = "no attempt"
    while True:
        try:
            with closing(connect(None)) as conn:
                rows(conn, "SELECT 1 AS ready")
            return 0
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            last = describe_error(exc)
        if time.monotonic() >= deadline:
            print(f"error: {args.engine} not ready after {args.timeout}s: {last}", file=sys.stderr)
            return 2
        time.sleep(2)


def _register_collect(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("collect", help="read-only snapshot of a server")
    p.add_argument("--engine", choices=ENGINE_CHOICES, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--settings", type=Path)
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("wait", help="wait until the server accepts a login")
    p.add_argument("--engine", choices=ENGINE_CHOICES, required=True)
    p.add_argument("--timeout", type=int, default=120)
    p.set_defaults(func=cmd_wait)


def cmd_run_sql(args: argparse.Namespace) -> int:
    from dbhardening.sqlrunner import apply_scripts

    directory = args.dir or Path("harden") / args.engine
    connect = connector(args.engine)
    applied = apply_scripts(args.engine, directory, lambda database: connect(database), os.environ)
    print(f"{args.engine}: applied {len(applied)} script(s) from {directory}: {', '.join(applied)}")
    return 0


def _register_sql(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("run-sql", help="apply the NN-name.sql scripts of a directory in order")
    p.add_argument("--engine", choices=ENGINE_CHOICES, required=True)
    p.add_argument("--dir", type=Path, required=True)
    p.set_defaults(func=cmd_run_sql)

    p = sub.add_parser("harden", help="apply harden/<engine>/ (re-runnable)")
    p.add_argument("--engine", choices=ENGINE_CHOICES, required=True)
    p.add_argument("--dir", type=Path)
    p.set_defaults(func=cmd_run_sql)


REGISTRARS: list[Callable[[argparse._SubParsersAction], None]] = [  # type: ignore[type-arg]
    _register_core,
    _register_collect,
    _register_sql,
]


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

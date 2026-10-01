"""Before/after report in Markdown (job summary, write-up) and HTML (self-contained, deterministic)."""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from typing import Any

from dbhardening.findings import SEVERITIES, Finding, catalog_for
from dbhardening.snapshot import SnapshotError

ENGINE_NAMES = {"mssql": "SQL Server", "postgres": "PostgreSQL"}
ROWS = (("High", "High"), ("Medium", "Medium"), ("Low", "Low"), ("NotEvaluated", "Checks not evaluated"))


def summarize(findings: Sequence[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    not_evaluated = set()
    for f in findings:
        if f.status == "Finding":
            counts[f.severity] += 1
        else:
            not_evaluated.add(f.check_id)
    counts["NotEvaluated"] = len(not_evaluated)
    return counts


def summary_text(findings: Sequence[Finding]) -> str:
    c = summarize(findings)
    return f"High: {c['High']}, Medium: {c['Medium']}, Low: {c['Low']}, not evaluated: {c['NotEvaluated']} check(s)"


def _result(findings: Sequence[Finding], check_id: str) -> str:
    mine = [f for f in findings if f.check_id == check_id]
    if any(f.status == "NotEvaluated" for f in mine):
        return "not evaluated"
    return f"{len(mine)} finding(s)" if mine else "pass"


def _engine(before: Mapping[str, Any], after: Mapping[str, Any]) -> str:
    engine = str(before.get("engine"))
    if after.get("engine") != engine or engine not in ENGINE_NAMES:
        raise SnapshotError("before and after snapshots must come from the same engine")
    return engine


def _md(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(
    before_snapshot: Mapping[str, Any],
    after_snapshot: Mapping[str, Any],
    before: Sequence[Finding],
    after: Sequence[Finding],
) -> str:
    engine = _engine(before_snapshot, after_snapshot)
    sb, sa = summarize(before), summarize(after)
    lines = [
        f"## {ENGINE_NAMES[engine]}: before and after hardening",
        "",
        f"Server {_md(after_snapshot.get('server_version', ''))}; collected {before_snapshot.get('collected_at')} "
        f"(before) and {after_snapshot.get('collected_at')} (after).",
        "",
        "| Severity | Before | After |",
        "|---|---|---|",
        *[f"| {label} | {sb[key]} | {sa[key]} |" for key, label in ROWS],
        "",
        "| Check | Title | Before | After |",
        "|---|---|---|---|",
    ]
    for spec in catalog_for(engine):
        before_result, after_result = _result(before, spec.check_id), _result(after, spec.check_id)
        lines.append(f"| {spec.check_id} | {_md(spec.title)} | {before_result} | {after_result} |")
    return "\n".join(lines) + "\n"


def _detail_table(findings: Sequence[Finding]) -> list[str]:
    e = html.escape
    out = ["<table><tr><th>Check</th><th>Severity</th><th>Status</th><th>Object</th><th>Detail</th></tr>"]
    for f in findings:
        out.append(
            f'<tr><td>{e(f.check_id)}</td><td class="{e(f.severity)}">{e(f.severity)}</td><td>{e(f.status)}</td>'
            f"<td>{e(f.object)}</td><td>{e(f.detail)}</td></tr>"
        )
    out.append("</table>")
    return out


def render_html(
    before_snapshot: Mapping[str, Any],
    after_snapshot: Mapping[str, Any],
    before: Sequence[Finding],
    after: Sequence[Finding],
) -> str:
    engine = _engine(before_snapshot, after_snapshot)
    e = html.escape
    sb, sa = summarize(before), summarize(after)
    name = ENGINE_NAMES[engine]
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{e(name)} hardening report</title>",
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1b1f24}"
        "table{border-collapse:collapse;margin:.5rem 0 1.5rem}th,td{border:1px solid #d0d7de;padding:.35rem .6rem;"
        "text-align:left;vertical-align:top}th{background:#f6f8fa}.High{color:#a40e26;font-weight:600}"
        ".Medium{color:#9a6700;font-weight:600}.Low{color:#0969da}</style></head><body>",
        f"<h1>{e(name)}: before and after hardening</h1>",
        f"<p>Server {e(str(after_snapshot.get('server_version', '')))} &middot; collected "
        f"{e(str(before_snapshot.get('collected_at')))} (before) and {e(str(after_snapshot.get('collected_at')))} "
        "(after)</p>",
        "<h2>Summary</h2><table><tr><th>Severity</th><th>Before</th><th>After</th></tr>",
        *[f"<tr><td>{e(label)}</td><td>{sb[key]}</td><td>{sa[key]}</td></tr>" for key, label in ROWS],
        "</table><table><tr><th>Check</th><th>Title</th><th>Before</th><th>After</th></tr>",
    ]
    for spec in catalog_for(engine):
        parts.append(
            f"<tr><td>{e(spec.check_id)}</td><td>{e(spec.title)}</td><td>{e(_result(before, spec.check_id))}</td>"
            f"<td>{e(_result(after, spec.check_id))}</td></tr>"
        )
    parts.append("</table><h2>Findings before hardening</h2>")
    parts += _detail_table(before)
    parts.append("<h2>Findings after hardening</h2>")
    parts += _detail_table(after)
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"

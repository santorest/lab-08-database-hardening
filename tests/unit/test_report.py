from __future__ import annotations

import pytest

from dbhardening.findings import CATALOG, assess, check
from dbhardening.report import render_html, render_markdown, summarize, summary_text
from dbhardening.snapshot import SnapshotError, dataset_unavailable

from .helpers import SETTINGS, snap


@pytest.fixture
def toys():
    @check("ZZ-01", engine="mssql", title="Toy <b>", severity="High", needs=["toys"], remediation="Fix.", area="T")
    def toy(data, settings):
        return [(row["name"], row["detail"]) for row in data["toys"]]

    yield
    del CATALOG["ZZ-01"]


def test_summarize_counts_findings_and_not_evaluated_checks(toys):
    findings = assess(snap("mssql", toys=[{"name": "a", "detail": "x"}, {"name": "b", "detail": "y"}]), SETTINGS)
    counts = summarize(findings)
    assert counts["High"] == 2
    # every real check is not evaluated in this snapshot (no data), plus none for the toy
    assert counts["NotEvaluated"] == len({f.check_id for f in findings if f.status == "NotEvaluated"})
    assert summary_text(findings).startswith("High: 2, Medium: 0, Low: 0, not evaluated: ")


def test_markdown_compares_before_and_after(toys):
    before_s = snap("mssql", toys=[{"name": "a", "detail": "x"}])
    after_s = snap("mssql", toys=[])
    md = render_markdown(before_s, after_s, assess(before_s, SETTINGS), assess(after_s, SETTINGS))
    assert md.startswith("## SQL Server: before and after hardening")
    assert "| High | 1 | 0 |" in md
    assert "| ZZ-01 | Toy <b> | 1 finding(s) | pass |" in md


def test_markdown_escapes_pipes(toys):
    s = snap("mssql", toys=[{"name": "a|b", "detail": "x"}])
    s["server_version"] = "16.0 | evil"
    md = render_markdown(s, s, assess(s, SETTINGS), assess(s, SETTINGS))
    assert "16.0 \\| evil" in md


def test_html_escapes_everything_from_the_server(toys):
    s = snap("mssql", toys=[{"name": "<script>alert(1)</script>", "detail": "\"quoted\" & 'single'"}])
    page = render_html(s, s, assess(s, SETTINGS), assess(s, SETTINGS))
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&quot;quoted&quot; &amp; &#x27;single&#x27;" in page
    assert "Toy &lt;b&gt;" in page


def test_html_is_deterministic(toys):
    s = snap("mssql", toys=[{"name": "a", "detail": "x"}])
    f = assess(s, SETTINGS)
    assert render_html(s, s, f, f) == render_html(s, s, f, f)


def test_report_refuses_mixed_engines(toys):
    a, b = snap("mssql"), snap("postgres")
    with pytest.raises(SnapshotError, match="same engine"):
        render_markdown(a, b, assess(a, SETTINGS), assess(b, SETTINGS))


def test_not_evaluated_shows_in_the_check_table(toys):
    s = snap("mssql", toys=dataset_unavailable("denied"))
    md = render_markdown(s, s, assess(s, SETTINGS), assess(s, SETTINGS))
    assert "| ZZ-01 | Toy <b> | not evaluated | not evaluated |" in md

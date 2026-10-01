from __future__ import annotations

import json
from pathlib import Path

import pytest

from dbhardening.cli import main
from dbhardening.findings import CATALOG, CheckSpec, check
from dbhardening.snapshot import dataset_unavailable, save_snapshot

from .helpers import snap


@pytest.fixture
def toys():
    @check("ZZ-01", engine="mssql", title="Toy", severity="Medium", needs=["toys"], remediation="Fix.", area="T")
    def toy(data, settings):
        return [(row["name"], "bad") for row in data["toys"]]

    yield
    del CATALOG["ZZ-01"]


def write(tmp_path: Path, name: str, snapshot) -> Path:
    path = tmp_path / name
    save_snapshot(snapshot, path)
    return path


def only_toys(**datasets):
    """An mssql snapshot with just the given datasets (real checks, once they exist, are not evaluated)."""
    return snap("mssql", **datasets)


def test_assess_prints_findings_and_exits_zero(tmp_path, toys, capsys):
    path = write(tmp_path, "s.json", only_toys(toys=[{"name": "a"}]))
    assert main(["assess", str(path)]) == 0
    out = capsys.readouterr().out
    assert "ZZ-01\tMedium\tFinding\ta\tbad" in out
    assert "Medium: 1" in out


def test_fail_on_threshold(tmp_path, toys):
    path = write(tmp_path, "s.json", only_toys(toys=[{"name": "a"}]))
    assert main(["assess", str(path), "--fail-on", "Medium"]) == 1


def test_fail_on_counts_not_evaluated(tmp_path, monkeypatch):
    # a High check without its data cannot prove the server is clean: the gate must fail, not pass silently
    monkeypatch.setattr("dbhardening.findings.load_checks", lambda: None)
    for key in list(CATALOG):
        monkeypatch.delitem(CATALOG, key)
    gadget = CheckSpec("ZZ-09", "mssql", "Gadget", "High", ("gadgets",), "Fix.", "T", lambda data, settings: [])
    monkeypatch.setitem(CATALOG, "ZZ-09", gadget)
    path = write(tmp_path, "s.json", only_toys())
    assert main(["assess", str(path), "--fail-on", "High"]) == 1


def test_fail_on_ignores_lower_severities(tmp_path, monkeypatch, toys):
    # only the toy (Medium) is in the catalog for this test
    monkeypatch.setattr("dbhardening.findings.load_checks", lambda: None)
    for key in [k for k in CATALOG if k != "ZZ-01"]:
        monkeypatch.delitem(CATALOG, key)
    path = write(tmp_path, "s.json", only_toys(toys=[{"name": "a"}]))
    assert main(["assess", str(path), "--fail-on", "High"]) == 0


def test_assess_json_output(tmp_path, toys):
    path = write(tmp_path, "s.json", only_toys(toys=[{"name": "a"}]))
    out = tmp_path / "f.json"
    assert main(["assess", str(path), "--json", str(out)]) == 0
    rows = json.loads(out.read_text(encoding="utf-8"))
    assert {"check_id": "ZZ-01", "object": "a"}.items() <= next(r for r in rows if r["check_id"] == "ZZ-01").items()


def test_bad_snapshot_exits_two(tmp_path, capsys):
    path = tmp_path / "s.json"
    path.write_text("{}", encoding="utf-8")
    assert main(["assess", str(path)]) == 2
    assert "error:" in capsys.readouterr().err


def test_report_writes_both_files(tmp_path, toys):
    before = write(tmp_path, "b.json", only_toys(toys=[{"name": "a"}]))
    after = write(tmp_path, "a.json", only_toys(toys=dataset_unavailable("x")))
    html, md = tmp_path / "r.html", tmp_path / "r.md"
    code = main(["report", "--before", str(before), "--after", str(after), "--html", str(html), "--markdown", str(md)])
    assert code == 0
    assert html.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "| ZZ-01 | Toy | 1 finding(s) | not evaluated |" in md.read_text(encoding="utf-8")

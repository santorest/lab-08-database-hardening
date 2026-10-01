from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from dbhardening.findings import CATALOG, Finding, assess, catalog_for, check
from dbhardening.settings import load_settings
from dbhardening.snapshot import (
    SnapshotError,
    dataset_ok,
    dataset_unavailable,
    load_snapshot,
    new_snapshot,
    save_snapshot,
    stable_view,
)

from .helpers import SETTINGS, snap


@pytest.fixture
def toy_check():
    """Registers a throwaway check for one test and removes it afterwards."""

    @check("ZZ-01", engine="mssql", title="Toy", severity="High", needs=["toys"], remediation="Fix.", area="Testing")
    def toy(data, settings):
        return [(row["name"], "bad toy") for row in data["toys"] if row["bad"]]

    yield toy
    del CATALOG["ZZ-01"]


def test_assess_runs_a_check_on_ok_data(toy_check):
    findings = [f for f in assess(snap("mssql", toys=[{"name": "a", "bad": True}]), SETTINGS) if f.check_id == "ZZ-01"]
    assert findings == [Finding("ZZ-01", "Toy", "High", "Finding", "a", "bad toy", "Fix.", "Testing")]


def test_assess_empty_ok_dataset_is_a_pass(toy_check):
    findings = [f for f in assess(snap("mssql", toys=[]), SETTINGS) if f.check_id == "ZZ-01"]
    assert findings == []


def test_assess_unavailable_dataset_is_not_evaluated(toy_check):
    s = snap("mssql", toys=dataset_unavailable("permission denied"))
    [finding] = [f for f in assess(s, SETTINGS) if f.check_id == "ZZ-01"]
    assert finding.status == "NotEvaluated"
    assert finding.detail == "Not evaluated: toys (permission denied)"


def test_assess_missing_dataset_is_not_evaluated(toy_check):
    [finding] = [f for f in assess(snap("mssql"), SETTINGS) if f.check_id == "ZZ-01"]
    assert finding.status == "NotEvaluated"
    assert "toys (not collected)" in finding.detail


def test_assess_malformed_dataset_is_not_evaluated(toy_check):
    s = snap("mssql", toys={"status": "ok"})  # no items
    [finding] = [f for f in assess(s, SETTINGS) if f.check_id == "ZZ-01"]
    assert finding.status == "NotEvaluated"
    assert "toys (malformed dataset)" in finding.detail


def test_assess_rejects_an_unknown_engine():
    with pytest.raises(SnapshotError, match="engine"):
        assess({"format": 1, "engine": "oracle", "datasets": {}}, SETTINGS)


def test_check_rejects_duplicates_and_bad_values(toy_check):
    with pytest.raises(ValueError, match="duplicate"):
        check("ZZ-01", engine="mssql", title="x", severity="High", needs=[], remediation="", area="")(lambda d, s: [])
    with pytest.raises(ValueError, match="engine"):
        check("ZZ-02", engine="oracle", title="x", severity="High", needs=[], remediation="", area="")
    with pytest.raises(ValueError, match="severity"):
        check("ZZ-03", engine="mssql", title="x", severity="Critical", needs=[], remediation="", area="")


def test_catalog_is_sorted_by_id(toy_check):
    ids = [spec.check_id for spec in catalog_for("mssql")]
    assert ids == sorted(ids)
    assert "ZZ-01" in ids


def test_settings_defaults_and_overrides(tmp_path: Path):
    assert SETTINGS["mssql"]["app_login"] == "clinic_app"
    override = tmp_path / "s.toml"
    override.write_text('[postgres]\nallowed_superusers = ["postgres", "dba"]\n', encoding="utf-8")
    assert load_settings(override)["postgres"]["allowed_superusers"] == ["postgres", "dba"]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[oracle]\nx = 1\n", "unknown settings section"),
        ("[mssql]\nnope = 1\n", "unknown setting mssql.nope"),
        ('[mssql]\napp_login = ["a"]\n', "mssql.app_login must be str"),
    ],
)
def test_settings_reject_bad_overrides(tmp_path: Path, text: str, message: str):
    override = tmp_path / "s.toml"
    override.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_settings(override)


def test_snapshot_round_trip_handles_driver_types(tmp_path: Path):
    s = new_snapshot(
        "postgres",
        "18.6",
        {"x": dataset_ok([{"when": datetime(2026, 1, 1, tzinfo=UTC), "n": Decimal("1.5")}])},
        collected_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    path = tmp_path / "s.json"
    save_snapshot(s, path)
    loaded = load_snapshot(path)
    assert loaded["collected_at"] == "2026-10-01T12:00:00Z"
    assert loaded["datasets"]["x"]["items"][0] == {"when": "2026-01-01 00:00:00+00:00", "n": "1.5"}


def test_load_snapshot_rejects_other_files(tmp_path: Path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"format": 99}), encoding="utf-8")
    with pytest.raises(SnapshotError, match="format-1"):
        load_snapshot(path)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SnapshotError, match="cannot read"):
        load_snapshot(path)


def test_stable_view_drops_volatile_parts():
    a = new_snapshot("mssql", "v", {"sessions": dataset_ok([{"id": 1}]), "logins": dataset_ok([{"n": "a"}])})
    b = new_snapshot(
        "mssql",
        "v",
        {"sessions": dataset_ok([{"id": 2}]), "logins": dataset_ok([{"n": "a"}])},
        collected_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    assert stable_view(a) == stable_view(b)
    assert "sessions" not in stable_view(a)["datasets"]

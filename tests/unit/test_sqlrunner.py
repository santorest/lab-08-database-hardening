from __future__ import annotations

from pathlib import Path

import pytest

from dbhardening.sqlrunner import ScriptError, apply_scripts, batches, list_scripts, script_database, substitute

from .fakes import FakeServer


def test_substitute_doubles_quotes():
    assert substitute("PASSWORD = N'$(APP_PASSWORD)'", {"APP_PASSWORD": "it's"}) == "PASSWORD = N'it''s'"


def test_substitute_missing_variable():
    with pytest.raises(ScriptError, match="APP_PASSWORD is not set"):
        substitute("'$(APP_PASSWORD)'", {})


def test_substitute_leaves_dollar_quoting_alone():
    sql = "DO $$ BEGIN PERFORM 1; END $$;"
    assert substitute(sql, {}) == sql


def test_script_database_directive():
    assert script_database("-- database: clinic\nSELECT 1") == "clinic"
    assert script_database("SELECT 1\n-- database: clinic") is None


def test_batches_split_on_go_for_mssql_only():
    sql = "SELECT 1;\nGO\n  go  \nSELECT 2;\nGO\n"
    assert batches(sql, "mssql") == ["SELECT 1;", "SELECT 2;"]
    assert batches("SELECT 1;\nGO\n", "postgres") == ["SELECT 1;\nGO"]


def test_list_scripts_order_and_naming(tmp_path: Path):
    for name in ("10-b.sql", "02-a.sql", "notes.txt"):
        (tmp_path / name).write_text("SELECT 1", encoding="utf-8")
    assert [p.name for p in list_scripts(tmp_path)] == ["02-a.sql", "10-b.sql"]
    (tmp_path / "bad.sql").write_text("SELECT 1", encoding="utf-8")
    with pytest.raises(ScriptError, match="bad.sql"):
        list_scripts(tmp_path)


def test_list_scripts_empty_directory(tmp_path: Path):
    with pytest.raises(ScriptError, match="no NN-name.sql scripts"):
        list_scripts(tmp_path)


def test_apply_scripts_reuses_one_connection_per_database(tmp_path: Path):
    (tmp_path / "01-a.sql").write_text("SELECT 1;\nGO\nSELECT '$(X)';\n", encoding="utf-8")
    (tmp_path / "02-b.sql").write_text("-- database: clinic\nSELECT 3;\n", encoding="utf-8")
    (tmp_path / "03-c.sql").write_text("SELECT 4;\n", encoding="utf-8")
    server = FakeServer({})
    applied = apply_scripts("mssql", tmp_path, lambda db: server(db, True), {"X": "y"})
    assert applied == ["01-a.sql", "02-b.sql", "03-c.sql"]
    assert server.opened == [(None, True), ("clinic", True)]
    assert [sql for _, sql, _ in server.log] == [
        "SELECT 1;",
        "SELECT 'y';",
        "-- database: clinic\nSELECT 3;",
        "SELECT 4;",
    ]


def test_missing_variable_runs_nothing(tmp_path: Path):
    (tmp_path / "01-a.sql").write_text("SELECT 1;\nGO\nSELECT '$(MISSING)';\n", encoding="utf-8")
    server = FakeServer({})
    with pytest.raises(ScriptError, match="01-a.sql: environment variable MISSING is not set"):
        apply_scripts("mssql", tmp_path, lambda db: server(db, True), {})
    assert server.log == []


def test_driver_error_names_the_script(tmp_path: Path):
    (tmp_path / "01-a.sql").write_text("SELECT boom;\n", encoding="utf-8")
    server = FakeServer({"boom": RuntimeError("Invalid column name 'boom'.")})
    with pytest.raises(ScriptError, match="01-a.sql: RuntimeError: Invalid column name"):
        apply_scripts("postgres", tmp_path, lambda db: server(db, True), {})


def test_repository_scripts_are_well_formed():
    root = Path(__file__).resolve().parents[2]
    for directory in ("seed/mssql", "seed/postgres", "harden/mssql", "harden/postgres"):
        for path in list_scripts(root / directory):
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if "$(" in line:
                    assert "'$(" in line, f"{path.name}: $(VAR) outside a quoted literal"

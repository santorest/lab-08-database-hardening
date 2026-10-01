from __future__ import annotations

import re
from typing import Any

import pytest

from dbhardening import collect_mssql, collect_pg
from dbhardening.collect_mssql import collect_mssql as run_mssql
from dbhardening.collect_pg import collect_postgres as run_pg

from .fakes import FakeServer
from .helpers import SETTINGS

FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|ALTER|CREATE|DROP|GRANT|REVOKE|EXEC|EXECUTE|TRUNCATE|DENY|BACKUP|RESTORE|"
    r"COPY|VACUUM|REINDEX|CLUSTER|SET)\b",
    re.IGNORECASE,
)


def queries(module):
    return {name: value for name, value in vars(module).items() if name.startswith("Q_")}


@pytest.mark.parametrize("module", [collect_mssql, collect_pg])
def test_every_collector_query_is_read_only(module):
    found = queries(module)
    assert found, "collector defines no Q_ constants"
    for name, sql in found.items():
        assert sql.lstrip().upper().startswith(("SELECT", "WITH", "SHOW")), name
        assert not FORBIDDEN.search(re.sub(r"'[^']*'", "''", sql)), name


MSSQL_BASE = {
    "SERVERPROPERTY": (["version", "edition"], [("17.0.4000.1", "Developer Edition (64-bit)")]),
    "sys.server_principals AS p": (
        ["name", "sid", "type_desc", "is_disabled", "is_policy_checked", "is_expiration_checked"],
        [("sa", "0x01", "SQL_LOGIN", False, True, False)],
    ),
    "sys.databases AS d": (
        ["name", "is_trustworthy_on", "is_db_chaining_on", "encryption_state"],
        [("clinic", True, False, None), ("hr", False, False, 3)],
    ),
    "has_dbaccess": None,  # unused key kept out of matching
}


def mssql_server(**overrides):
    responses = {k: v for k, v in {**MSSQL_BASE, **overrides}.items() if v is not None}
    per_db: dict[str, dict[str, Any]] = {
        "clinic": {
            "u.name = 'guest'": (["guest_connect"], [(True,)]),
            "WHERE name = ?": (["name"], [("clinic_app",)]),
        },
        "hr": {"u.name = 'guest'": (["guest_connect"], [(False,)])},
    }
    return FakeServer(responses, per_db)


def test_mssql_collects_all_datasets_and_only_runs_known_queries():
    server = mssql_server()
    snapshot = run_mssql(server, SETTINGS["mssql"])
    assert snapshot["engine"] == "mssql"
    assert snapshot["server_version"] == "17.0.4000.1 Developer Edition (64-bit)"
    expected = {
        "logins",
        "configurations",
        "sysadmins",
        "sessions",
        "databases",
        "server_audits",
        "server_audit_actions",
        "connection_probe",
        "guest",
        "db_audit_actions",
        "app_roles",
        "app_grants",
    }
    assert set(snapshot["datasets"]) == expected
    assert all(d["status"] == "ok" for d in snapshot["datasets"].values())
    assert snapshot["datasets"]["guest"]["items"] == [
        {"database": "clinic", "guest_connect": True},
        {"database": "hr", "guest_connect": False},
    ]
    known = set(queries(collect_mssql).values())
    assert {sql for _, sql, _ in server.log} <= known


def test_mssql_probe_uses_an_unencrypted_connection():
    server = mssql_server()
    run_mssql(server, SETTINGS["mssql"])
    assert (None, False) in server.opened


def test_mssql_failing_query_marks_only_that_dataset():
    server = mssql_server(**{"sys.server_role_members": RuntimeError("permission denied\nsecond line")})
    datasets = run_mssql(server, SETTINGS["mssql"])["datasets"]
    assert datasets["sysadmins"] == {"status": "unavailable", "error": "RuntimeError: permission denied", "items": []}
    assert datasets["logins"]["status"] == "ok"


def test_mssql_missing_app_user_makes_app_datasets_unavailable():
    server = mssql_server()
    server.per_database["clinic"]["WHERE name = ?"] = (["name"], [])
    datasets = run_mssql(server, SETTINGS["mssql"])["datasets"]
    assert datasets["app_roles"]["status"] == "unavailable"
    assert "clinic_app not found" in datasets["app_roles"]["error"]


def test_mssql_guest_unavailable_when_database_list_fails():
    server = mssql_server(**{"sys.databases AS d": RuntimeError("boom")})
    datasets = run_mssql(server, SETTINGS["mssql"])["datasets"]
    assert datasets["guest"]["error"] == "database list unavailable"


PG_BASE = {
    "SHOW server_version": (["server_version"], [("18.6 (Debian 18.6-1.pgdg13+1)",)]),
    "FROM pg_database": (["datname"], [("clinic",), ("postgres",)]),
    "SELECT oid FROM pg_roles WHERE rolname": (["oid"], [(16384,)]),
    "has_schema_privilege": (["database", "public_create"], [("x", False)]),
}


def test_postgres_collects_all_datasets_and_only_runs_known_queries():
    server = FakeServer(PG_BASE)
    snapshot = run_pg(server, SETTINGS["postgres"])
    expected = {
        "hba",
        "settings",
        "roles",
        "password_hashes",
        "secdef_functions",
        "languages",
        "sensitive_columns",
        "app_owned",
        "app_grants",
        "public_schema",
    }
    assert set(snapshot["datasets"]) == expected
    assert snapshot["server_version"].startswith("18.6")
    assert [db for db, _ in server.opened] == ["clinic", "clinic", "postgres"]
    known = set(queries(collect_pg).values())
    assert {sql for _, sql, _ in server.log} <= known


def test_postgres_sensitive_columns_are_passed_as_a_parameter():
    server = FakeServer(PG_BASE)
    run_pg(server, SETTINGS["postgres"])
    [params] = [p for _, sql, p in server.log if sql == collect_pg.Q_SENSITIVE]
    assert params == (["public.patients.national_id"],)


def test_postgres_missing_app_role():
    server = FakeServer({**PG_BASE, "SELECT oid FROM pg_roles WHERE rolname": (["oid"], [])})
    datasets = run_pg(server, SETTINGS["postgres"])["datasets"]
    assert datasets["app_owned"]["status"] == "unavailable"
    assert "role clinic_app not found" in datasets["app_grants"]["error"]

from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import closing
from typing import Any

import pytest

from dbhardening.connect import mssql_connect
from dbhardening.dbapi import rows
from dbhardening.findings import assess
from dbhardening.settings import load_settings
from dbhardening.snapshot import stable_view
from demo_app import fixed, vulnerable

pytestmark = pytest.mark.mssql
SETTINGS = load_settings()
NAMES = {"Ana Example", "Bruno Example", "Carla Example"}
OR_PAYLOAD = "x' OR '1'='1"
UNION_PAYLOAD = "x' UNION SELECT 0, full_name, NULL, NULL FROM dbo.patients --"
STACKED_PAYLOAD = "x'; DROP TABLE dbo.appointments; --"
AUDIT_QUERY = """SELECT action_id, server_principal_name, object_name, statement
FROM sys.fn_get_audit_file(N'/var/opt/mssql/audit/*.sqlaudit', DEFAULT, DEFAULT)"""


def app() -> Any:
    return mssql_connect("clinic", user="clinic_app", password=os.environ["APP_PASSWORD"])


def test_before_has_high_findings(results):
    highs = [f for f in assess(results["before"], SETTINGS) if f.status == "Finding" and f.severity == "High"]
    assert highs, "a default + seeded server should have High findings"


def test_after_has_no_high_and_nothing_unevaluated(results):
    findings = assess(results["after"], SETTINGS)
    assert [f.to_dict() for f in findings if f.severity == "High" or f.status == "NotEvaluated"] == []


def test_hardening_is_idempotent(results):
    assert stable_view(results["after"]) == stable_view(results["after-again"])


def test_audit_records_failed_login_role_change_and_select(out_dir):
    probe = "audit_probe_" + secrets.token_hex(4)
    with pytest.raises(Exception):  # noqa: B017 - the driver's own error type; the audit row is what matters
        mssql_connect("clinic", user="clinic_app", password="wrong-" + secrets.token_hex(8)).close()
    with closing(mssql_connect()) as conn:
        cur = conn.cursor()
        cur.execute(f"CREATE LOGIN [{probe}] WITH PASSWORD = N'Lab1-{secrets.token_hex(16)}'")
        cur.execute(f"ALTER SERVER ROLE securityadmin ADD MEMBER [{probe}]")
        cur.execute(f"ALTER SERVER ROLE securityadmin DROP MEMBER [{probe}]")
        cur.execute(f"DROP LOGIN [{probe}]")
        cur.close()
    with closing(app()) as conn:
        rows(conn, "SELECT COUNT(*) AS n FROM dbo.patients")

    found: dict[str, dict[str, Any] | None] = {"failed login": None, "role change": None, "select": None}
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not all(found.values()):
        with closing(mssql_connect()) as conn:
            events = rows(conn, AUDIT_QUERY)
        for e in events:
            action, who = str(e["action_id"]).strip(), str(e["server_principal_name"])
            if action == "LGIF" and who == "clinic_app":
                found["failed login"] = e
            elif action == "APRL" and probe in str(e["statement"]):
                found["role change"] = e
            elif action == "SL" and who == "clinic_app" and str(e["object_name"]) == "patients":
                found["select"] = e
        time.sleep(2)
    (out_dir / "audit-proof.json").write_text(json.dumps(found, indent=2, default=str) + "\n", encoding="utf-8")
    seen = sorted({str(e["action_id"]).strip() for e in events})
    assert all(found.values()), f"missing audit events: {[k for k, v in found.items() if not v]}; actions seen: {seen}"


def test_vulnerable_lookup_leaks_other_patients():
    with closing(app()) as conn:
        assert len(vulnerable.find_appointments_mssql(conn, "Ana Example")) == 1
        assert len(vulnerable.find_appointments_mssql(conn, OR_PAYLOAD)) == 3
        assert {r[1] for r in vulnerable.find_appointments_mssql(conn, UNION_PAYLOAD)} == NAMES


def test_fixed_lookup_treats_payloads_as_data():
    with closing(app()) as conn:
        assert [r[1] for r in fixed.find_appointments_mssql(conn, "Ana Example")] == ["Ana Example"]
        for payload in (OR_PAYLOAD, UNION_PAYLOAD, STACKED_PAYLOAD):
            assert fixed.find_appointments_mssql(conn, payload) == []


def test_least_privilege_contains_a_stacked_drop():
    with closing(app()) as conn:
        try:
            vulnerable.find_appointments_mssql(conn, STACKED_PAYLOAD)
        except Exception:  # noqa: BLE001, S110 - the DROP is refused; the table check below is the assertion
            pass
    with closing(mssql_connect("clinic")) as conn:
        assert rows(conn, "SELECT OBJECT_ID(N'dbo.appointments') AS id")[0]["id"] is not None


def test_app_login_cannot_change_what_it_was_not_granted():
    with closing(app()) as conn:
        cur = conn.cursor()
        with pytest.raises(Exception, match="(?i)permission"):  # noqa: B017
            cur.execute("DELETE FROM dbo.patients")

from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import closing
from typing import Any

import pytest

from dbhardening.connect import pg_connect
from dbhardening.dbapi import rows
from dbhardening.findings import assess
from dbhardening.settings import load_settings
from dbhardening.snapshot import stable_view
from demo_app import fixed, vulnerable

pytestmark = pytest.mark.postgres
SETTINGS = load_settings()
NAMES = {"Ana Example", "Bruno Example", "Carla Example"}
OR_PAYLOAD = "x' OR '1'='1"
UNION_PAYLOAD = "x' UNION SELECT 0, full_name, NULL, NULL FROM patients --"
STACKED_PAYLOAD = "x'; DROP TABLE appointments; --"
LOG_FILES = "SELECT name FROM pg_ls_logdir() WHERE name LIKE '%.csv' ORDER BY modification"


def app() -> Any:
    return pg_connect("clinic", user="clinic_app", password=os.environ["APP_PASSWORD"])


def server_log(conn: Any) -> list[str]:
    lines: list[str] = []
    for f in rows(conn, LOG_FILES):
        lines += str(rows(conn, "SELECT pg_read_file(%s) AS text", ("log/" + f["name"],))[0]["text"]).splitlines()
    return lines


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
    with pytest.raises(Exception):  # noqa: B017
        pg_connect("clinic", user="clinic_app", password="wrong-" + secrets.token_hex(8)).close()
    with closing(pg_connect("clinic")) as conn:
        cur = conn.cursor()
        cur.execute(f"CREATE ROLE {probe} NOLOGIN")
        cur.execute(f"GRANT auditor TO {probe}")
        cur.execute(f"DROP ROLE {probe}")
        cur.close()
    with closing(app()) as conn:
        rows(conn, "SELECT count(*) AS n FROM patients")

    found: dict[str, str | None] = {"failed login": None, "role change": None, "select": None}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not all(found.values()):
        with closing(pg_connect("clinic")) as conn:
            for line in server_log(conn):
                # csvlog doubles the quotes inside a field: for user ""clinic_app""
                if 'password authentication failed for user ""clinic_app""' in line:
                    found["failed login"] = line
                elif "AUDIT: SESSION" in line and "GRANT" in line and probe in line:
                    found["role change"] = line
                elif "AUDIT: OBJECT" in line and "public.patients" in line and "clinic_app" in line:
                    found["select"] = line
        time.sleep(2)
    (out_dir / "audit-proof.json").write_text(json.dumps(found, indent=2) + "\n", encoding="utf-8")
    assert all(found.values()), f"missing log lines: {[k for k, v in found.items() if not v]}"


def test_vulnerable_lookup_leaks_other_patients():
    with closing(app()) as conn:
        assert len(vulnerable.find_appointments_pg(conn, "Ana Example")) == 1
        assert len(vulnerable.find_appointments_pg(conn, OR_PAYLOAD)) == 3
        assert {r[1] for r in vulnerable.find_appointments_pg(conn, UNION_PAYLOAD)} == NAMES


def test_fixed_lookup_treats_payloads_as_data():
    with closing(app()) as conn:
        assert [r[1] for r in fixed.find_appointments_pg(conn, "Ana Example")] == ["Ana Example"]
        for payload in (OR_PAYLOAD, UNION_PAYLOAD, STACKED_PAYLOAD):
            assert fixed.find_appointments_pg(conn, payload) == []


def test_least_privilege_contains_a_stacked_drop():
    with closing(app()) as conn:
        with pytest.raises(Exception, match="must be owner"):  # noqa: B017
            vulnerable.find_appointments_pg(conn, STACKED_PAYLOAD)
    with closing(pg_connect("clinic")) as conn:
        assert rows(conn, "SELECT to_regclass('public.appointments') IS NOT NULL AS present")[0]["present"]


def test_app_role_cannot_change_what_it_was_not_granted():
    with closing(app()) as conn:
        cur = conn.cursor()
        with pytest.raises(Exception, match="permission denied"):  # noqa: B017
            cur.execute("DELETE FROM patients")


def test_app_password_never_reaches_the_server_log():
    # Hardening re-runs as a normal operation; with pgAudit loaded, a logged ALTER ROLE ... PASSWORD would leak it.
    with closing(pg_connect("clinic")) as conn:
        leaked = [line[:80] for line in server_log(conn) if os.environ["APP_PASSWORD"] in line]
    assert leaked == []

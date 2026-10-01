from __future__ import annotations

from .helpers import run, settings_with

SAFE_CONFIG = {
    "xp_cmdshell": 0,
    "clr enabled": 0,
    "clr strict security": 1,
    "Ole Automation Procedures": 0,
    "Ad Hoc Distributed Queries": 0,
    "remote access": 0,
    "cross db ownership chaining": 0,
}
GROUPS = [
    "FAILED_LOGIN_GROUP",
    "SERVER_ROLE_MEMBER_CHANGE_GROUP",
    "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
    "SERVER_PERMISSION_CHANGE_GROUP",
    "DATABASE_PERMISSION_CHANGE_GROUP",
]


def login(name, sid="0x0A", type_desc="SQL_LOGIN", disabled=False, policy=True, expiration=True):
    return {
        "name": name,
        "sid": sid,
        "type_desc": type_desc,
        "is_disabled": disabled,
        "is_policy_checked": policy,
        "is_expiration_checked": expiration,
    }


def config(**overrides):
    values = {**SAFE_CONFIG, **{k.replace("_", " ") if k != "xp_cmdshell" else k: v for k, v in overrides.items()}}
    return [{"name": k, "value": v} for k, v in values.items()]


def config_without(name):
    return [{"name": k, "value": v} for k, v in SAFE_CONFIG.items() if k != name]


def database(name="clinic", trustworthy=False, chaining=False, state=3):
    return {"name": name, "is_trustworthy_on": trustworthy, "is_db_chaining_on": chaining, "encryption_state": state}


# MS-01
def test_ms01_enabled_sa_with_its_name_gives_two_findings():
    details = [f.detail for f in run("mssql", "MS-01", logins=[login("sa", sid="0x01")])]
    assert details == ["The built-in sa login is enabled.", "The built-in sa login keeps its well-known name."]


def test_ms01_disabled_and_renamed_passes():
    assert run("mssql", "MS-01", logins=[login("lab_sa_disabled", sid="0x01", disabled=True)]) == []


def test_ms01_disabled_but_still_named_sa():
    [f] = run("mssql", "MS-01", logins=[login("SA", sid="0x01", disabled=True)])
    assert "well-known name" in f.detail


# MS-02
def test_ms02_policy_off_on_any_enabled_sql_login():
    [f] = run("mssql", "MS-02", logins=[login("clinic_app", policy=False, expiration=False)], sysadmins=[])
    assert (f.object, f.detail) == ("clinic_app", "CHECK_POLICY off.")


def test_ms02_expiration_off_only_matters_for_sysadmins():
    logins = [login("lab_admin", expiration=False), login("clinic_app", expiration=False)]
    [f] = run("mssql", "MS-02", logins=logins, sysadmins=[{"name": "LAB_ADMIN", "sid": "0x0B"}])
    assert (f.object, f.detail) == ("lab_admin", "CHECK_EXPIRATION off on a sysadmin login.")


def test_ms02_ignores_disabled_and_windows_logins():
    logins = [login("old", disabled=True, policy=False), login("CORP\\ops", type_desc="WINDOWS_LOGIN", policy=None)]
    assert run("mssql", "MS-02", logins=logins, sysadmins=[]) == []


# MS-03
def test_ms03_xp_cmdshell_on():
    [f] = run("mssql", "MS-03", configurations=config(xp_cmdshell=1))
    assert f.object == "xp_cmdshell"


def test_ms03_off_passes():
    assert run("mssql", "MS-03", configurations=config()) == []


def test_ms03_setting_not_reported_cannot_be_confirmed():
    [f] = run("mssql", "MS-03", configurations=config_without("xp_cmdshell"))
    assert "cannot confirm" in f.detail


# MS-04
def test_ms04_clr_without_strict_security_and_remote_access():
    rows = [
        {"name": k, "value": v}
        for k, v in {**SAFE_CONFIG, "clr enabled": 1, "clr strict security": 0, "remote access": 1}.items()
    ]
    assert sorted(f.object for f in run("mssql", "MS-04", configurations=rows)) == ["clr enabled", "remote access"]


def test_ms04_clr_with_strict_security_passes():
    rows = [{"name": k, "value": v} for k, v in {**SAFE_CONFIG, "clr enabled": 1}.items()]
    assert run("mssql", "MS-04", configurations=rows) == []


def test_ms04_missing_option_cannot_be_confirmed():
    [f] = run("mssql", "MS-04", configurations=config_without("remote access"))
    assert (f.object, "cannot confirm" in f.detail) == ("remote access", True)


# MS-05
def test_ms05_unencrypted_probe_reports_session_counts():
    sessions = [
        {"session_id": 51, "encrypt_option": "FALSE", "auth_scheme": "SQL"},
        {"session_id": 52, "encrypt_option": "TRUE", "auth_scheme": "SQL"},
        {"session_id": 53, "encrypt_option": "FALSE", "auth_scheme": "SQL"},
    ]
    [f] = run("mssql", "MS-05", connection_probe=[{"encrypt_option": "FALSE"}], sessions=sessions)
    assert "2 of 3 sessions" in f.detail


def test_ms05_forced_encryption_passes():
    assert run("mssql", "MS-05", connection_probe=[{"encrypt_option": "TRUE"}], sessions=[]) == []


def test_ms05_empty_probe_cannot_be_confirmed():
    [f] = run("mssql", "MS-05", connection_probe=[], sessions=[])
    assert "cannot confirm" in f.detail


# MS-06
def test_ms06_tde_states():
    rows = [database("clinic", state=None), database("hr", state=2), database("done", state=3)]
    found = {f.object: f.detail for f in run("mssql", "MS-06", databases=rows)}
    assert found == {
        "clinic": "TDE is not enabled.",
        "hr": "TDE is not complete (encryption_state 2; 3 means encrypted).",
    }


# MS-07
def full_audit():
    return {
        "server_audits": [{"name": "lab_audit", "status_desc": "STARTED"}],
        "server_audit_actions": [
            {"spec_name": "s", "is_state_enabled": True, "audit_name": "lab_audit", "audit_action_name": g}
            for g in GROUPS
        ],
        "db_audit_actions": [
            {
                "spec_name": "d",
                "is_state_enabled": True,
                "audit_name": "lab_audit",
                "audit_action_name": "SELECT",
                "object_name": "dbo.patients",
            }
        ],
    }


def test_ms07_complete_audit_passes():
    assert run("mssql", "MS-07", **full_audit()) == []


def test_ms07_no_running_audit():
    data = full_audit()
    data["server_audits"] = [{"name": "lab_audit", "status_desc": "STOPPED"}]
    [f] = run("mssql", "MS-07", **data)
    assert f.detail == "No server audit is running."


def test_ms07_missing_group_and_unaudited_table():
    data = full_audit()
    data["server_audit_actions"] = data["server_audit_actions"][1:]
    data["db_audit_actions"] = []
    details = sorted(f.detail for f in run("mssql", "MS-07", **data))
    assert details == [
        "No enabled server audit specification captures FAILED_LOGIN_GROUP.",
        "SELECT on this table is not audited.",
    ]


def test_ms07_disabled_specification_does_not_count():
    data = full_audit()
    for row in data["server_audit_actions"]:
        row["is_state_enabled"] = False
    assert len(run("mssql", "MS-07", **data)) == len(GROUPS)


def test_ms07_table_names_compare_case_insensitively():
    settings = settings_with("mssql", audited_tables=["DBO.PATIENTS"])
    assert run("mssql", "MS-07", settings, **full_audit()) == []


# MS-08
def test_ms08_unexpected_sysadmin():
    rows = [{"name": "sa", "sid": "0x01"}, {"name": "lab_admin", "sid": "0x0B"}, {"name": "intruder", "sid": "0x0C"}]
    settings = settings_with("mssql", allowed_sysadmins=["LAB_ADMIN"])
    assert [f.object for f in run("mssql", "MS-08", settings, sysadmins=rows)] == ["intruder"]


# MS-09
def test_ms09_guest_connect():
    rows = [{"database": "clinic", "guest_connect": True}, {"database": "hr", "guest_connect": False}]
    assert [f.object for f in run("mssql", "MS-09", guest=rows)] == ["clinic"]


# MS-10
def grant(permission, cls="OBJECT_OR_COLUMN", obj="dbo.patients", state="GRANT", grantee="clinic_app_role"):
    return {
        "grantee": grantee,
        "permission_name": permission,
        "state_desc": state,
        "class_desc": cls,
        "object_name": obj if cls == "OBJECT_OR_COLUMN" else None,
    }


def test_ms10_fixed_role_membership():
    [f] = run("mssql", "MS-10", app_roles=[{"name": "db_owner"}], app_grants=[])
    assert f.detail == "Member of fixed database role db_owner."


def test_ms10_least_privilege_passes():
    grants = [
        grant("CONNECT", cls="DATABASE", grantee="clinic_app"),
        grant("SELECT"),
        grant("INSERT", obj="dbo.appointments"),
        grant("SELECT", obj="DBO.Appointments"),
        grant("DELETE", obj="dbo.billing", state="DENY"),
    ]
    assert run("mssql", "MS-10", app_roles=[{"name": "clinic_app_role"}], app_grants=grants) == []


def test_ms10_grants_outside_the_app_tables():
    grants = [
        grant("SELECT", obj="dbo.billing"),
        grant("ALTER", cls="DATABASE"),
        grant("SELECT", state="GRANT_WITH_GRANT_OPTION"),
    ]
    details = sorted(f.detail for f in run("mssql", "MS-10", app_roles=[], app_grants=grants))
    assert details == [
        "ALTER on DATABASE (via clinic_app_role) is outside the app's tables.",
        "SELECT on dbo.billing (via clinic_app_role) is outside the app's tables.",
        "SELECT on dbo.patients granted WITH GRANT OPTION (via clinic_app_role).",
    ]


# MS-11, MS-12
def test_ms11_trustworthy():
    rows = [database("clinic", trustworthy=True), database("hr")]
    assert [f.object for f in run("mssql", "MS-11", databases=rows)] == ["clinic"]


def test_ms12_server_and_database_chaining():
    rows = [{"name": k, "value": v} for k, v in {**SAFE_CONFIG, "cross db ownership chaining": 1}.items()]
    found = [f.object for f in run("mssql", "MS-12", configurations=rows, databases=[database(chaining=True)])]
    assert found == ["server", "clinic"]


def test_ms12_off_passes():
    assert run("mssql", "MS-12", configurations=config(), databases=[database()]) == []

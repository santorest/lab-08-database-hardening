"""SQL Server checks: pure functions over a snapshot's datasets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dbhardening.findings import Items, check

SA_SID = "0x01"
FIXED_DB_ROLES = frozenset(
    {
        "db_owner",
        "db_securityadmin",
        "db_accessadmin",
        "db_backupoperator",
        "db_ddladmin",
        "db_datawriter",
        "db_datareader",
    }
)
REQUIRED_SERVER_GROUPS = (
    "FAILED_LOGIN_GROUP",
    "SERVER_ROLE_MEMBER_CHANGE_GROUP",
    "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
    "SERVER_PERMISSION_CHANGE_GROUP",
    "DATABASE_PERMISSION_CHANGE_GROUP",
)
RISKY_OPTIONS = (
    ("Ole Automation Procedures", "OLE Automation procedures are enabled."),
    ("Ad Hoc Distributed Queries", "Ad hoc distributed queries (OPENROWSET/OPENDATASOURCE) are enabled."),
    ("remote access", "Remote access (procedure calls from other servers) is enabled."),
)
Result = list[tuple[str, str]]
Data = Mapping[str, Items]
Settings = Mapping[str, Any]


def _cf(value: object) -> str:
    return str(value).casefold()


def _config(data: Data, name: str) -> int | None:
    for row in data["configurations"]:
        if _cf(row["name"]) == _cf(name):
            return int(row["value"])
    return None


def _unreported(name: str) -> tuple[str, str]:
    return (name, f"Setting '{name}' was not reported by sys.configurations; cannot confirm it is safe.")


def _sysadmin_names(data: Data) -> set[str]:
    return {_cf(r["name"]) for r in data["sysadmins"]}


@check(
    "MS-01",
    engine="mssql",
    title="sa login enabled or not renamed",
    severity="High",
    needs=["logins"],
    remediation="Create a named administrator login, then disable the sa login and rename it.",
    area="Authentication and logins",
)
def sa_login(data: Data, settings: Settings) -> Result:
    out: Result = []
    for row in data["logins"]:
        if _cf(row["sid"]) != SA_SID:
            continue
        if not row["is_disabled"]:
            out.append((str(row["name"]), "The built-in sa login is enabled."))
        if _cf(row["name"]) == "sa":
            out.append((str(row["name"]), "The built-in sa login keeps its well-known name."))
    return out


@check(
    "MS-02",
    engine="mssql",
    title="SQL logins without password policy",
    severity="Medium",
    needs=["logins", "sysadmins"],
    remediation="ALTER LOGIN ... WITH CHECK_POLICY = ON; for sysadmin logins also CHECK_EXPIRATION = ON.",
    area="Authentication and logins",
)
def login_policy(data: Data, settings: Settings) -> Result:
    admins = _sysadmin_names(data)
    out: Result = []
    for row in data["logins"]:
        if row["type_desc"] != "SQL_LOGIN" or row["is_disabled"]:
            continue
        if not row["is_policy_checked"]:
            out.append((str(row["name"]), "CHECK_POLICY off."))
        elif not row["is_expiration_checked"] and _cf(row["name"]) in admins:
            out.append((str(row["name"]), "CHECK_EXPIRATION off on a sysadmin login."))
    return out


@check(
    "MS-03",
    engine="mssql",
    title="xp_cmdshell enabled",
    severity="High",
    needs=["configurations"],
    remediation="EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;",
    area="Surface area reduction",
)
def xp_cmdshell(data: Data, settings: Settings) -> Result:
    value = _config(data, "xp_cmdshell")
    if value is None:
        return [_unreported("xp_cmdshell")]
    return (
        [("xp_cmdshell", "xp_cmdshell is enabled: any sysadmin session can run operating-system commands.")]
        if value == 1
        else []
    )


@check(
    "MS-04",
    engine="mssql",
    title="Risky surface options enabled",
    severity="Medium",
    needs=["configurations"],
    remediation="Turn the options off with sp_configure; keep 'clr strict security' on if CLR is needed.",
    area="Surface area reduction",
)
def surface(data: Data, settings: Settings) -> Result:
    out: Result = []
    clr, strict = _config(data, "clr enabled"), _config(data, "clr strict security")
    if clr is None or strict is None:
        out.append(_unreported("clr enabled" if clr is None else "clr strict security"))
    elif clr == 1 and strict == 0:
        out.append(("clr enabled", "CLR is enabled without 'clr strict security'."))
    for name, detail in RISKY_OPTIONS:
        value = _config(data, name)
        if value is None:
            out.append(_unreported(name))
        elif value == 1:
            out.append((name, detail))
    return out


@check(
    "MS-05",
    engine="mssql",
    title="Encrypted connections not forced",
    severity="High",
    needs=["connection_probe", "sessions"],
    remediation="Install a trusted certificate and set network.forceencryption = 1 in mssql.conf; restart.",
    area="Encryption in transit",
)
def encryption(data: Data, settings: Settings) -> Result:
    probe = data["connection_probe"]
    if not probe:
        return [("server", "The connection probe returned no row; cannot confirm encryption is forced.")]
    if _cf(probe[0]["encrypt_option"]) == "true":
        return []
    sessions = data["sessions"]
    plain = [s for s in sessions if _cf(s["encrypt_option"]) != "true"]
    return [
        (
            "server",
            "Encryption is not forced: a connection made with Encrypt=no was not encrypted; "
            f"{len(plain)} of {len(sessions)} sessions open at collection were unencrypted.",
        )
    ]


@check(
    "MS-06",
    engine="mssql",
    title="User database without TDE",
    severity="Medium",
    needs=["databases"],
    remediation="Create a database encryption key protected by a server certificate, back the certificate up "
    "offline, then ALTER DATABASE ... SET ENCRYPTION ON.",
    area="Encryption at rest",
)
def tde(data: Data, settings: Settings) -> Result:
    out: Result = []
    for row in data["databases"]:
        state = row["encryption_state"]
        if state is None:
            out.append((str(row["name"]), "TDE is not enabled."))
        elif int(state) != 3:
            out.append((str(row["name"]), f"TDE is not complete (encryption_state {state}; 3 means encrypted)."))
    return out


@check(
    "MS-07",
    engine="mssql",
    title="Audit does not cover key events",
    severity="High",
    needs=["server_audits", "server_audit_actions", "db_audit_actions"],
    remediation="Create a server audit (file target), a server audit specification for failed logins and "
    "role/permission changes, and a database audit specification for SELECT on sensitive tables.",
    area="Auditing and logging",
)
def audit(data: Data, settings: Settings) -> Result:
    started = {_cf(r["name"]) for r in data["server_audits"] if r["status_desc"] == "STARTED"}
    if not started:
        return [("server", "No server audit is running.")]
    covered = {
        r["audit_action_name"]
        for r in data["server_audit_actions"]
        if r["is_state_enabled"] and _cf(r["audit_name"]) in started
    }
    out: Result = [
        ("server", f"No enabled server audit specification captures {group}.")
        for group in REQUIRED_SERVER_GROUPS
        if group not in covered
    ]
    audited = {
        _cf(r["object_name"])
        for r in data["db_audit_actions"]
        if r["is_state_enabled"]
        and r["audit_action_name"] == "SELECT"
        and r["object_name"]
        and _cf(r["audit_name"]) in started
    }
    out += [(t, "SELECT on this table is not audited.") for t in settings["audited_tables"] if _cf(t) not in audited]
    return out


@check(
    "MS-08",
    engine="mssql",
    title="Unexpected sysadmin members",
    severity="High",
    needs=["sysadmins"],
    remediation="Remove the login from sysadmin and grant only what it needs.",
    area="Authorization",
)
def sysadmins(data: Data, settings: Settings) -> Result:
    allowed = {_cf(n) for n in settings["allowed_sysadmins"]}
    return [
        (str(r["name"]), "Member of sysadmin but not in the allowed list.")
        for r in data["sysadmins"]
        if _cf(r["sid"]) != SA_SID and _cf(r["name"]) not in allowed
    ]


@check(
    "MS-09",
    engine="mssql",
    title="guest user can connect",
    severity="Medium",
    needs=["guest"],
    remediation="In each user database: REVOKE CONNECT FROM guest;",
    area="Authorization",
)
def guest(data: Data, settings: Settings) -> Result:
    return [(str(r["database"]), "The guest user has CONNECT.") for r in data["guest"] if r["guest_connect"]]


@check(
    "MS-10",
    engine="mssql",
    title="Application login over-privileged",
    severity="Medium",
    needs=["app_roles", "app_grants"],
    remediation="Remove the app user from fixed roles; grant only the statements it needs on its own tables "
    "through a dedicated role.",
    area="Authorization",
)
def app_privileges(data: Data, settings: Settings) -> Result:
    login = str(settings["app_login"])
    tables = {_cf(t) for t in settings["app_tables"]}
    out: Result = [
        (login, f"Member of fixed database role {r['name']}.")
        for r in data["app_roles"]
        if _cf(r["name"]) in FIXED_DB_ROLES
    ]
    for g in data["app_grants"]:
        if g["state_desc"] not in ("GRANT", "GRANT_WITH_GRANT_OPTION"):
            continue
        perm, cls, obj = str(g["permission_name"]), str(g["class_desc"]), g["object_name"]
        if cls == "DATABASE" and perm == "CONNECT":
            continue
        target = str(obj) if obj else cls
        if g["state_desc"] == "GRANT_WITH_GRANT_OPTION":
            out.append((login, f"{perm} on {target} granted WITH GRANT OPTION (via {g['grantee']})."))
        elif cls != "OBJECT_OR_COLUMN" or not obj or _cf(obj) not in tables:
            out.append((login, f"{perm} on {target} (via {g['grantee']}) is outside the app's tables."))
    return out


@check(
    "MS-11",
    engine="mssql",
    title="TRUSTWORTHY database",
    severity="High",
    needs=["databases"],
    remediation="ALTER DATABASE ... SET TRUSTWORTHY OFF;",
    area="Authorization",
)
def trustworthy(data: Data, settings: Settings) -> Result:
    return [(str(r["name"]), "TRUSTWORTHY is on.") for r in data["databases"] if r["is_trustworthy_on"]]


@check(
    "MS-12",
    engine="mssql",
    title="Cross-database ownership chaining",
    severity="Low",
    needs=["configurations", "databases"],
    remediation="EXEC sp_configure 'cross db ownership chaining', 0; and ALTER DATABASE ... SET DB_CHAINING OFF;",
    area="Authorization",
)
def chaining(data: Data, settings: Settings) -> Result:
    value = _config(data, "cross db ownership chaining")
    out: Result = []
    if value is None:
        out.append(_unreported("cross db ownership chaining"))
    elif value == 1:
        out.append(("server", "Cross-database ownership chaining is on for the whole instance."))
    out += [
        (str(r["name"]), "Cross-database ownership chaining is on for this database.")
        for r in data["databases"]
        if r["is_db_chaining_on"]
    ]
    return out

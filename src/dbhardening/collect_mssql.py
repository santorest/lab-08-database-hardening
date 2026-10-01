"""Read-only SQL Server collector. Every statement it runs is one of the Q_ constants below."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from functools import partial
from typing import Any

from dbhardening.dbapi import describe_error, rows, run_dataset
from dbhardening.snapshot import dataset_unavailable, new_snapshot

MssqlConnect = Callable[[str | None, bool], Any]

Q_VERSION = """SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS version,
       CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition"""
Q_LOGINS = """SELECT p.name, CONVERT(varchar(200), p.sid, 1) AS sid, p.type_desc, p.is_disabled,
       s.is_policy_checked, s.is_expiration_checked
FROM sys.server_principals AS p
LEFT JOIN sys.sql_logins AS s ON s.principal_id = p.principal_id
WHERE p.type IN ('S', 'U', 'G') AND p.name NOT LIKE '##%'"""
Q_CONFIGURATIONS = """SELECT name, CAST(value_in_use AS int) AS value
FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'clr enabled', 'clr strict security', 'Ole Automation Procedures',
               'Ad Hoc Distributed Queries', 'remote access', 'cross db ownership chaining')"""
Q_SYSADMINS = """SELECT m.name, CONVERT(varchar(200), m.sid, 1) AS sid
FROM sys.server_role_members AS rm
JOIN sys.server_principals AS r ON r.principal_id = rm.role_principal_id
JOIN sys.server_principals AS m ON m.principal_id = rm.member_principal_id
WHERE r.name = 'sysadmin'"""
Q_SESSIONS = """SELECT session_id, CAST(encrypt_option AS varchar(10)) AS encrypt_option, auth_scheme
FROM sys.dm_exec_connections"""
Q_PROBE = """SELECT CAST(encrypt_option AS varchar(10)) AS encrypt_option
FROM sys.dm_exec_connections WHERE session_id = @@SPID"""
Q_DATABASES = """SELECT d.name, d.is_trustworthy_on, d.is_db_chaining_on, k.encryption_state
FROM sys.databases AS d
LEFT JOIN sys.dm_database_encryption_keys AS k ON k.database_id = d.database_id
WHERE d.database_id > 4 AND d.state_desc = 'ONLINE'
ORDER BY d.name"""
Q_SERVER_AUDITS = """SELECT a.name, s.status_desc
FROM sys.server_audits AS a
LEFT JOIN sys.dm_server_audit_status AS s ON s.audit_id = a.audit_id"""
Q_SERVER_AUDIT_ACTIONS = """SELECT sp.name AS spec_name, sp.is_state_enabled, a.name AS audit_name, d.audit_action_name
FROM sys.server_audit_specifications AS sp
JOIN sys.server_audits AS a ON a.audit_guid = sp.audit_guid
JOIN sys.server_audit_specification_details AS d ON d.server_specification_id = sp.server_specification_id"""
Q_DB_AUDIT_ACTIONS = """SELECT sp.name AS spec_name, sp.is_state_enabled, a.name AS audit_name, d.audit_action_name,
       OBJECT_SCHEMA_NAME(d.major_id) + '.' + OBJECT_NAME(d.major_id) AS object_name
FROM sys.database_audit_specifications AS sp
JOIN sys.server_audits AS a ON a.audit_guid = sp.audit_guid
JOIN sys.database_audit_specification_details AS d ON d.database_specification_id = sp.database_specification_id
WHERE d.class_desc = 'OBJECT_OR_COLUMN'"""
Q_GUEST = """SELECT CAST(CASE WHEN EXISTS (
    SELECT 1 FROM sys.database_permissions AS p
    JOIN sys.database_principals AS u ON u.principal_id = p.grantee_principal_id
    WHERE u.name = 'guest' AND p.permission_name = 'CONNECT' AND p.state IN ('G', 'W'))
  THEN 1 ELSE 0 END AS bit) AS guest_connect"""
Q_APP_USER = "SELECT name FROM sys.database_principals WHERE name = ?"
Q_APP_ROLES = """WITH member_of AS (
    SELECT rm.role_principal_id FROM sys.database_role_members AS rm
    JOIN sys.database_principals AS u ON u.principal_id = rm.member_principal_id
    WHERE u.name = ?
    UNION ALL
    SELECT rm.role_principal_id FROM sys.database_role_members AS rm
    JOIN member_of AS m ON rm.member_principal_id = m.role_principal_id)
SELECT DISTINCT r.name FROM member_of AS m
JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id"""
Q_APP_GRANTS = """WITH principals AS (
    SELECT u.principal_id, u.name FROM sys.database_principals AS u WHERE u.name = ?
    UNION ALL
    SELECT r.principal_id, r.name FROM sys.database_role_members AS rm
    JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id
    JOIN principals AS p ON p.principal_id = rm.member_principal_id)
SELECT DISTINCT p.name AS grantee, dp.permission_name, dp.state_desc, dp.class_desc,
       CASE WHEN dp.class = 1 THEN OBJECT_SCHEMA_NAME(dp.major_id) + '.' + OBJECT_NAME(dp.major_id) END AS object_name
FROM principals AS p
JOIN sys.database_permissions AS dp ON dp.grantee_principal_id = p.principal_id"""

SERVER_DATASETS = (
    ("logins", Q_LOGINS),
    ("configurations", Q_CONFIGURATIONS),
    ("sysadmins", Q_SYSADMINS),
    ("sessions", Q_SESSIONS),
    ("databases", Q_DATABASES),
    ("server_audits", Q_SERVER_AUDITS),
    ("server_audit_actions", Q_SERVER_AUDIT_ACTIONS),
)


def _in_database(
    connect: MssqlConnect, database: str | None, sql: str, *, encrypt: bool = True
) -> list[dict[str, Any]]:
    with closing(connect(database, encrypt)) as conn:
        return rows(conn, sql)


def _guest(connect: MssqlConnect, databases: Mapping[str, Any]) -> dict[str, Any]:
    if databases["status"] != "ok":
        return dataset_unavailable("database list unavailable")

    def collect() -> list[dict[str, Any]]:
        out = []
        for db in databases["items"]:
            [row] = _in_database(connect, str(db["name"]), Q_GUEST)
            out.append({"database": db["name"], "guest_connect": bool(row["guest_connect"])})
        return out

    return run_dataset(collect)


def _app(connect: MssqlConnect, database: str, login: str) -> dict[str, Any]:
    try:
        with closing(connect(database, True)) as conn:
            if not rows(conn, Q_APP_USER, (login,)):
                missing = dataset_unavailable(f"user {login} not found in database {database}")
                return {"app_roles": missing, "app_grants": missing}
            return {
                "app_roles": run_dataset(lambda: rows(conn, Q_APP_ROLES, (login,))),
                "app_grants": run_dataset(lambda: rows(conn, Q_APP_GRANTS, (login,))),
            }
    except Exception as exc:  # noqa: BLE001 - e.g. the app database does not exist
        failed = dataset_unavailable(describe_error(exc))
        return {"app_roles": failed, "app_grants": failed}


def collect_mssql(connect: MssqlConnect, settings: Mapping[str, Any]) -> dict[str, Any]:
    datasets: dict[str, Any] = {}
    with closing(connect(None, True)) as conn:
        [info] = rows(conn, Q_VERSION)
        version = f"{info['version']} {info['edition']}"
        for name, sql in SERVER_DATASETS:
            datasets[name] = run_dataset(partial(rows, conn, sql))
    # A connection that does not ask for encryption shows whether the server forces it (MS-05).
    datasets["connection_probe"] = run_dataset(lambda: _in_database(connect, None, Q_PROBE, encrypt=False))
    datasets["guest"] = _guest(connect, datasets["databases"])
    app_db = str(settings["app_database"])
    datasets["db_audit_actions"] = run_dataset(lambda: _in_database(connect, app_db, Q_DB_AUDIT_ACTIONS))
    datasets.update(_app(connect, app_db, str(settings["app_login"])))
    return new_snapshot("mssql", version, datasets)

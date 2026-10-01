"""Read-only PostgreSQL collector (needs a superuser for pg_authid and pg_hba_file_rules).
Every statement it runs is one of the Q_ constants below."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from functools import partial
from typing import Any

from dbhardening.dbapi import describe_error, rows, run_dataset
from dbhardening.snapshot import dataset_unavailable, new_snapshot

PgConnect = Callable[[str | None], Any]

Q_VERSION = "SHOW server_version"
Q_HBA = """SELECT line_number, type, database, user_name, address, netmask, auth_method, error
FROM pg_hba_file_rules ORDER BY line_number"""
Q_SETTINGS = """SELECT name, setting FROM pg_settings
WHERE name IN ('ssl', 'password_encryption', 'shared_preload_libraries', 'pgaudit.log',
               'log_connections', 'log_disconnections', 'log_line_prefix')"""
Q_ROLES = "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles WHERE rolname !~ '^pg_'"
# Only the kind of hash leaves the server, never the hash itself (S105 is a false positive on the name).
Q_PASSWORD_HASHES = """SELECT rolname,
       CASE WHEN rolpassword IS NULL THEN 'none'
            WHEN rolpassword LIKE 'md5%' THEN 'md5'
            WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram'
            ELSE 'other' END AS kind
FROM pg_authid WHERE rolname !~ '^pg_'"""  # noqa: S105
Q_SECDEF = """SELECT n.nspname || '.' || p.proname AS function, p.proconfig
FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')"""
Q_LANGUAGES = "SELECT lanname, lanpltrusted FROM pg_language"
Q_SENSITIVE = """SELECT table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema || '.' || table_name || '.' || column_name = ANY(%s)"""
Q_DATABASES = "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname"
Q_PUBLIC_SCHEMA = """SELECT current_database() AS database,
       has_schema_privilege('public', n.oid, 'CREATE') AS public_create
FROM pg_namespace AS n WHERE n.nspname = 'public'"""
Q_APP_ROLE = "SELECT oid FROM pg_roles WHERE rolname = %s"
# The app role plus every role it is a member of, directly or through other roles.
APP_ROLES_CTE = """WITH RECURSIVE app AS (
    SELECT oid FROM pg_roles WHERE rolname = %s
    UNION
    SELECT m.roleid FROM pg_auth_members AS m JOIN app ON m.member = app.oid)
"""
Q_APP_OWNED = (
    APP_ROLES_CTE  # noqa: S608 - two constants joined; no input reaches the SQL text
    + """SELECT n.nspname || '.' || c.relname AS object, c.relkind::text AS kind, pg_get_userbyid(c.relowner) AS owner
FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relowner IN (SELECT oid FROM app)
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
UNION ALL
SELECT n.nspname || '.' || p.proname AS object, 'function' AS kind, pg_get_userbyid(p.proowner) AS owner
FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
WHERE p.proowner IN (SELECT oid FROM app)
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')"""
)
Q_APP_GRANTS = (
    APP_ROLES_CTE  # noqa: S608 - two constants joined; no input reaches the SQL text
    + """SELECT n.nspname || '.' || c.relname AS object, a.privilege_type AS privilege,
       pg_get_userbyid(a.grantee) AS grantee
FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(c.relacl) AS a
WHERE a.grantee IN (SELECT oid FROM app) AND a.grantee <> c.relowner
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
UNION ALL
SELECT 'schema ' || n.nspname AS object, a.privilege_type AS privilege, pg_get_userbyid(a.grantee) AS grantee
FROM pg_namespace AS n CROSS JOIN LATERAL aclexplode(n.nspacl) AS a
WHERE a.grantee IN (SELECT oid FROM app) AND a.grantee <> n.nspowner"""
)
Q_APP_MEMBERSHIPS = (
    APP_ROLES_CTE  # noqa: S608 - two constants joined; no input reaches the SQL text
    + """SELECT r.rolname AS role, r.rolsuper
FROM app JOIN pg_roles AS r ON r.oid = app.oid
WHERE r.rolname <> %s
ORDER BY r.rolname"""
)

APP_DB_DATASETS = (
    ("hba", Q_HBA),
    ("settings", Q_SETTINGS),
    ("roles", Q_ROLES),
    ("password_hashes", Q_PASSWORD_HASHES),
    ("secdef_functions", Q_SECDEF),
    ("languages", Q_LANGUAGES),
)


def _public_schema(connect: PgConnect, databases: Mapping[str, Any]) -> dict[str, Any]:
    if databases["status"] != "ok":
        return dataset_unavailable("database list unavailable")

    def collect() -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for db in databases["items"]:
            with closing(connect(str(db["datname"]))) as conn:
                out += rows(conn, Q_PUBLIC_SCHEMA)
        return out

    return run_dataset(collect)


def _app(conn: Any, role: str) -> dict[str, Any]:
    try:
        exists = rows(conn, Q_APP_ROLE, (role,))
    except Exception as exc:  # noqa: BLE001
        failed = dataset_unavailable(describe_error(exc))
        return {"app_owned": failed, "app_grants": failed, "app_memberships": failed}
    if not exists:
        missing = dataset_unavailable(f"role {role} not found")
        return {"app_owned": missing, "app_grants": missing, "app_memberships": missing}
    return {
        "app_owned": run_dataset(lambda: rows(conn, Q_APP_OWNED, (role,))),
        "app_grants": run_dataset(lambda: rows(conn, Q_APP_GRANTS, (role,))),
        "app_memberships": run_dataset(lambda: rows(conn, Q_APP_MEMBERSHIPS, (role, role))),
    }


def collect_postgres(connect: PgConnect, settings: Mapping[str, Any]) -> dict[str, Any]:
    datasets: dict[str, Any] = {}
    with closing(connect(str(settings["app_database"]))) as conn:
        [info] = rows(conn, Q_VERSION)
        version = str(info["server_version"])
        for name, sql in APP_DB_DATASETS:
            datasets[name] = run_dataset(partial(rows, conn, sql))
        columns = list(settings["sensitive_columns"])
        datasets["sensitive_columns"] = run_dataset(lambda: rows(conn, Q_SENSITIVE, (columns,)))
        datasets.update(_app(conn, str(settings["app_role"])))
        databases = run_dataset(lambda: rows(conn, Q_DATABASES))
    datasets["public_schema"] = _public_schema(connect, databases)
    return new_snapshot("postgres", version, datasets)

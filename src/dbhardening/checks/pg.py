"""PostgreSQL checks: pure functions over a snapshot's datasets. Role names compare case-sensitively."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dbhardening.findings import Items, check

WEAK_METHODS = frozenset({"trust", "password", "md5"})
LOOPBACK = frozenset({"127.0.0.1", "::1"})
UNTRUSTED_LANGUAGES = frozenset({"plpython3u", "plpythonu", "plpython2u", "plperlu", "pltclu"})
APP_TABLE_PRIVILEGES = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})
OFF_VALUES = frozenset({"", "off", "false", "0", "no"})
Result = list[tuple[str, str]]
Data = Mapping[str, Items]
Settings = Mapping[str, Any]


def _setting(data: Data, name: str) -> str | None:
    for row in data["settings"]:
        if row["name"] == name:
            return str(row["setting"]) if row["setting"] is not None else ""
    return None


def _unreported(name: str) -> tuple[str, str]:
    return (name, f"Setting '{name}' was not reported by pg_settings; cannot confirm it is safe.")


def _label(rule: Mapping[str, Any]) -> str:
    return f"pg_hba line {rule['line_number']}"


def _text(rule: Mapping[str, Any]) -> str:
    parts = [str(rule["type"]), ",".join(rule["database"] or []), ",".join(rule["user_name"] or [])]
    if rule["address"]:
        parts.append(str(rule["address"]))
    return " ".join(parts)


def _rules(data: Data) -> Items:
    return [r for r in data["hba"] if not r.get("error")]


@check(
    "PG-01",
    engine="postgres",
    title="Weak pg_hba authentication",
    severity="High",
    needs=["hba"],
    remediation="Use scram-sha-256 (or cert) in every pg_hba.conf rule; never trust, password or md5.",
    area="Authentication",
)
def hba_methods(data: Data, settings: Settings) -> Result:
    out: Result = []
    for rule in data["hba"]:
        if rule.get("error"):
            out.append((_label(rule), f"Rule could not be parsed: {rule['error']}"))
        elif rule["auth_method"] in WEAK_METHODS:
            out.append((_label(rule), f"{_text(rule)} uses {rule['auth_method']}."))
    return out


@check(
    "PG-02",
    engine="postgres",
    title="MD5 password hashing",
    severity="Medium",
    needs=["settings", "password_hashes"],
    remediation="Set password_encryption = 'scram-sha-256' and reset every password still stored as MD5.",
    area="Authentication",
)
def password_hashing(data: Data, settings: Settings) -> Result:
    out: Result = []
    value = _setting(data, "password_encryption")
    if value is None:
        out.append(_unreported("password_encryption"))
    elif value != "scram-sha-256":
        out.append(("password_encryption", f"New passwords are hashed with {value}."))
    out += [
        (str(r["rolname"]), "Password stored as an MD5 hash.") for r in data["password_hashes"] if r["kind"] == "md5"
    ]
    return out


@check(
    "PG-03",
    engine="postgres",
    title="TLS not enforced",
    severity="High",
    needs=["settings", "hba"],
    remediation="Configure a certificate, set ssl = on and use hostssl for every remote rule.",
    area="Encryption in transit",
)
def tls(data: Data, settings: Settings) -> Result:
    out: Result = []
    value = _setting(data, "ssl")
    if value is None:
        out.append(_unreported("ssl"))
    elif value != "on":
        out.append(("ssl", "SSL is off; connections cannot be encrypted."))
    for rule in _rules(data):
        if rule["type"] in ("host", "hostnossl") and rule["address"] not in LOOPBACK:
            out.append((_label(rule), f"{_text(rule)} allows connections without TLS."))
    return out


@check(
    "PG-04",
    engine="postgres",
    title="Unexpected superusers or privileged app role",
    severity="High",
    needs=["roles"],
    remediation="ALTER ROLE ... NOSUPERUSER NOCREATEROLE NOCREATEDB for anything not expected.",
    area="Authorization",
)
def superusers(data: Data, settings: Settings) -> Result:
    allowed = set(settings["allowed_superusers"])
    app = settings["app_role"]
    out: Result = []
    for r in data["roles"]:
        if r["rolsuper"] and r["rolname"] not in allowed:
            out.append((str(r["rolname"]), "Superuser not in the allowed list."))
        elif r["rolname"] == app:
            extras = [label for label, key in (("CREATEROLE", "rolcreaterole"), ("CREATEDB", "rolcreatedb")) if r[key]]
            if extras:
                out.append((str(app), "App role has " + ", ".join(extras) + "."))
    return out


@check(
    "PG-05",
    engine="postgres",
    title="pg_hba open to any address",
    severity="Medium",
    needs=["hba"],
    remediation="Limit each remote rule to the networks the clients really use.",
    area="Network access",
)
def open_rules(data: Data, settings: Settings) -> Result:
    def open_to_all(rule: Mapping[str, Any]) -> bool:
        # pg_hba addresses being compared, not a socket being bound (S104 is a false positive here).
        any_address = ("0.0.0.0", "::")  # noqa: S104
        return rule["address"] == "all" or (rule["address"] in any_address and rule["netmask"] in any_address)

    return [
        (_label(r), f"{_text(r)} accepts clients from any address.")
        for r in _rules(data)
        if r["type"] != "local" and open_to_all(r)
    ]


@check(
    "PG-06",
    engine="postgres",
    title="pgAudit not configured",
    severity="High",
    needs=["settings"],
    remediation="shared_preload_libraries = 'pgaudit', CREATE EXTENSION pgaudit, pgaudit.log with at least "
    "role and ddl, and object audit through pgaudit.role.",
    area="Auditing and logging",
)
def pgaudit(data: Data, settings: Settings) -> Result:
    libs = {x.strip().casefold() for x in (_setting(data, "shared_preload_libraries") or "").split(",")}
    if "pgaudit" not in libs:
        return [("shared_preload_libraries", "pgaudit is not preloaded, so no audit records are written.")]
    current = _setting(data, "pgaudit.log") or ""
    classes = {c.strip().casefold() for c in current.split(",") if c.strip()}
    if "all" in classes:
        return []
    missing = [c for c in settings["pgaudit_required_classes"] if c not in classes]
    return (
        [("pgaudit.log", f"Audit classes missing: {', '.join(missing)} (current: {current or 'none'}).")]
        if missing
        else []
    )


@check(
    "PG-07",
    engine="postgres",
    title="Connection logging incomplete",
    severity="Medium",
    needs=["settings"],
    remediation="log_connections and log_disconnections on; log_line_prefix with %u, %d and %h (or %r).",
    area="Auditing and logging",
)
def connection_logging(data: Data, settings: Settings) -> Result:
    out: Result = []
    connections = _setting(data, "log_connections")  # PostgreSQL 18: a list of aspects; '' means off
    if connections is None:
        out.append(_unreported("log_connections"))
    elif connections.strip().casefold() in OFF_VALUES:
        out.append(("log_connections", "Connections are not logged."))
    disconnections = _setting(data, "log_disconnections")
    if disconnections is None:
        out.append(_unreported("log_disconnections"))
    elif disconnections != "on":
        out.append(("log_disconnections", "Disconnections are not logged."))
    prefix = _setting(data, "log_line_prefix")
    if prefix is None:
        out.append(_unreported("log_line_prefix"))
    else:
        lacking = [
            name
            for name, codes in (("user", ("%u",)), ("database", ("%d",)), ("client", ("%h", "%r")))
            if not any(code in prefix for code in codes)
        ]
        if lacking:
            out.append(("log_line_prefix", f"log_line_prefix lacks {', '.join(lacking)}."))
    return out


@check(
    "PG-08",
    engine="postgres",
    title="PUBLIC can create in schema public",
    severity="Medium",
    needs=["public_schema"],
    remediation="REVOKE CREATE ON SCHEMA public FROM PUBLIC; in every database.",
    area="Authorization",
)
def public_create(data: Data, settings: Settings) -> Result:
    return [
        (str(r["database"]), "PUBLIC has CREATE on schema public.") for r in data["public_schema"] if r["public_create"]
    ]


@check(
    "PG-09",
    engine="postgres",
    title="Application role over-privileged",
    severity="Medium",
    needs=["app_owned", "app_grants"],
    remediation="Give the objects to a separate NOLOGIN owner role and grant the app only what it needs on its "
    "own tables.",
    area="Authorization",
)
def app_privileges(data: Data, settings: Settings) -> Result:
    tables = set(settings["app_tables"])
    out: Result = [
        (str(r["object"]), "Owned by the app role; an owner can alter or drop it.") for r in data["app_owned"]
    ]
    for g in data["app_grants"]:
        obj, privilege = str(g["object"]), str(g["privilege"])
        if obj.startswith("schema "):
            if privilege != "USAGE":
                out.append((obj, f"App role holds {privilege} on {obj}."))
        elif obj not in tables or privilege not in APP_TABLE_PRIVILEGES:
            out.append((obj, f"App role holds {privilege} on {obj}."))
    return out


@check(
    "PG-10",
    engine="postgres",
    title="SECURITY DEFINER without fixed search_path",
    severity="High",
    needs=["secdef_functions"],
    remediation="ALTER FUNCTION ... SET search_path = <trusted schemas>, pg_temp;",
    area="Code and extensions",
)
def secdef(data: Data, settings: Settings) -> Result:
    return [
        (str(r["function"]), "SECURITY DEFINER function without a fixed search_path.")
        for r in data["secdef_functions"]
        if not any(str(c).startswith("search_path=") for c in (r["proconfig"] or []))
    ]


@check(
    "PG-11",
    engine="postgres",
    title="Untrusted language marked trusted",
    severity="High",
    needs=["languages"],
    remediation="UPDATE pg_language SET lanpltrusted = false for untrusted languages, or drop them.",
    area="Code and extensions",
)
def languages(data: Data, settings: Settings) -> Result:
    return [
        (str(r["lanname"]), "Untrusted language is marked trusted, so non-superusers can create functions in it.")
        for r in data["languages"]
        if r["lanname"] in UNTRUSTED_LANGUAGES and r["lanpltrusted"]
    ]


@check(
    "PG-12",
    engine="postgres",
    title="Sensitive column in plaintext",
    severity="Medium",
    needs=["sensitive_columns"],
    remediation="Store the column as bytea encrypted with pgcrypto (pgp_sym_encrypt) and keep the key outside "
    "the database; use volume encryption for data at rest.",
    area="Encryption at rest",
)
def sensitive(data: Data, settings: Settings) -> Result:
    found = {
        f"{r['table_schema']}.{r['table_name']}.{r['column_name']}": str(r["data_type"])
        for r in data["sensitive_columns"]
    }
    out: Result = []
    for column in settings["sensitive_columns"]:
        if column not in found:
            out.append((column, "Column listed as sensitive was not found; cannot confirm it is protected."))
        elif found[column] != "bytea":
            out.append((column, f"Stored as {found[column]} (plaintext); expected pgcrypto-encrypted bytea."))
    return out

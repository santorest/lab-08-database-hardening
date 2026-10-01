from __future__ import annotations

from .helpers import run, settings_with

SAFE = {
    "ssl": "on",
    "password_encryption": "scram-sha-256",
    "shared_preload_libraries": "pgaudit",
    "pgaudit.log": "role, ddl",
    "log_connections": "receipt,authentication,authorization",
    "log_disconnections": "on",
    "log_line_prefix": "%m [%p] user=%u db=%d client=%h ",
}


def pg_settings(**changes):
    """changes use '__' for '.', e.g. pgaudit__log; None removes the row."""
    values = dict(SAFE)
    for key, value in changes.items():
        name = key.replace("__", ".")
        if value is None:
            values.pop(name, None)
        else:
            values[name] = value
    return [{"name": k, "setting": v} for k, v in values.items()]


def hba(line, type_="hostssl", address="172.16.0.0", netmask="255.240.0.0", method="scram-sha-256", error=None):
    return {
        "line_number": line,
        "type": type_,
        "database": ["all"],
        "user_name": ["all"],
        "address": address,
        "netmask": netmask,
        "auth_method": method,
        "error": error,
    }


def role(name, superuser=False, createrole=False, createdb=False):
    return {
        "rolname": name,
        "rolsuper": superuser,
        "rolcreaterole": createrole,
        "rolcreatedb": createdb,
        "rolcanlogin": True,
    }


# PG-01
def test_pg01_weak_methods_and_parse_errors():
    rules = [
        hba(1, "local", None, None, "trust"),
        hba(2, "host", "127.0.0.1", "255.255.255.255", "md5"),
        hba(3),
        hba(4, error='invalid authentication method "foo"'),
    ]
    found = {f.object: f.detail for f in run("postgres", "PG-01", hba=rules)}
    assert set(found) == {"pg_hba line 1", "pg_hba line 2", "pg_hba line 4"}
    assert found["pg_hba line 1"].endswith("uses trust.")
    assert found["pg_hba line 4"].startswith("Rule could not be parsed")


def test_pg01_scram_only_passes():
    assert run("postgres", "PG-01", hba=[hba(1, "local", None, None), hba(2)]) == []


# PG-02
def test_pg02_md5_setting_and_hashes():
    found = [
        f.object
        for f in run(
            "postgres",
            "PG-02",
            settings=pg_settings(password_encryption="md5"),
            password_hashes=[{"rolname": "clinic_app", "kind": "md5"}, {"rolname": "postgres", "kind": "scram"}],
        )
    ]
    assert found == ["password_encryption", "clinic_app"]


def test_pg02_scram_passes():
    assert run("postgres", "PG-02", settings=pg_settings(), password_hashes=[{"rolname": "a", "kind": "scram"}]) == []


def test_pg02_unreported_setting_cannot_be_confirmed():
    [f] = run("postgres", "PG-02", settings=pg_settings(password_encryption=None), password_hashes=[])
    assert "cannot confirm" in f.detail


# PG-03
def test_pg03_ssl_off_and_non_tls_remote_rule():
    rules = [
        hba(1, "host", "0.0.0.0", "0.0.0.0"),
        hba(2, "host", "127.0.0.1", "255.255.255.255"),
        hba(3, "local", None, None),
        hba(4),
    ]
    found = [f.object for f in run("postgres", "PG-03", settings=pg_settings(ssl="off"), hba=rules)]
    assert found == ["ssl", "pg_hba line 1"]


def test_pg03_hostnossl_is_flagged():
    [f] = run("postgres", "PG-03", settings=pg_settings(), hba=[hba(1, "hostnossl")])
    assert "without TLS" in f.detail


# PG-04
def test_pg04_superusers_are_case_sensitive_and_app_attributes():
    roles = [role("postgres", superuser=True), role("Postgres", superuser=True), role("clinic_app", createdb=True)]
    found = {f.object: f.detail for f in run("postgres", "PG-04", roles=roles)}
    assert found == {"Postgres": "Superuser not in the allowed list.", "clinic_app": "App role has CREATEDB."}


def test_pg04_plain_app_role_passes():
    assert run("postgres", "PG-04", roles=[role("postgres", superuser=True), role("clinic_app")]) == []


# PG-05
def test_pg05_open_to_any_address():
    rules = [
        hba(1, "host", "all", None),
        hba(2, "hostssl", "0.0.0.0", "0.0.0.0"),
        hba(3, "hostssl", "::", "::"),
        hba(4),
        hba(5, "local", None, None),
    ]
    assert [f.object for f in run("postgres", "PG-05", hba=rules)] == [
        "pg_hba line 1",
        "pg_hba line 2",
        "pg_hba line 3",
    ]


# PG-06
def test_pg06_not_preloaded():
    [f] = run("postgres", "PG-06", settings=pg_settings(shared_preload_libraries="", pgaudit__log=None))
    assert f.object == "shared_preload_libraries"


def test_pg06_missing_class():
    [f] = run("postgres", "PG-06", settings=pg_settings(pgaudit__log="ddl"))
    assert f.detail == "Audit classes missing: role (current: ddl)."


def test_pg06_all_and_spacing_pass():
    s1 = pg_settings(shared_preload_libraries=" pg_stat_statements , PGAUDIT ", pgaudit__log="all")
    assert run("postgres", "PG-06", settings=s1) == []
    assert run("postgres", "PG-06", settings=pg_settings()) == []


# PG-07
def test_pg07_connections_disconnections_and_prefix():
    s = pg_settings(log_connections="", log_disconnections="off", log_line_prefix="%m ")
    found = {f.object: f.detail for f in run("postgres", "PG-07", settings=s)}
    assert set(found) == {"log_connections", "log_disconnections", "log_line_prefix"}
    assert found["log_line_prefix"] == "log_line_prefix lacks user, database, client."


def test_pg07_remote_host_with_port_counts_as_client():
    s = pg_settings(log_connections="on", log_line_prefix="%u@%d from %r ")
    assert run("postgres", "PG-07", settings=s) == []


# PG-08
def test_pg08_public_create():
    rows = [{"database": "clinic", "public_create": True}, {"database": "postgres", "public_create": False}]
    assert [f.object for f in run("postgres", "PG-08", public_schema=rows)] == ["clinic"]


# PG-09
def test_pg09_owned_objects_and_excess_grants():
    owned = [{"object": "public.patients", "kind": "r"}]
    grants = [
        {"object": "public.patients", "privilege": "SELECT"},
        {"object": "public.patients", "privilege": "TRUNCATE"},
        {"object": "public.billing", "privilege": "SELECT"},
        {"object": "schema public", "privilege": "USAGE"},
        {"object": "schema public", "privilege": "CREATE"},
    ]
    details = [f.detail for f in run("postgres", "PG-09", app_owned=owned, app_grants=grants)]
    assert details == [
        "Owned by the app role; an owner can alter or drop it.",
        "App role holds TRUNCATE on public.patients.",
        "App role holds SELECT on public.billing.",
        "App role holds CREATE on schema public.",
    ]


def test_pg09_least_privilege_passes():
    grants = [
        {"object": "public.patients", "privilege": "SELECT"},
        {"object": "public.appointments", "privilege": "INSERT"},
    ]
    assert run("postgres", "PG-09", app_owned=[], app_grants=grants) == []


# PG-10
def test_pg10_search_path():
    rows = [
        {"function": "public.a", "proconfig": None},
        {"function": "public.b", "proconfig": ["work_mem=1MB"]},
        {"function": "public.c", "proconfig": ["search_path=public, pg_temp"]},
    ]
    assert [f.object for f in run("postgres", "PG-10", secdef_functions=rows)] == ["public.a", "public.b"]


# PG-11
def test_pg11_untrusted_language_marked_trusted():
    rows = [
        {"lanname": "plpython3u", "lanpltrusted": True},
        {"lanname": "plperlu", "lanpltrusted": False},
        {"lanname": "plpgsql", "lanpltrusted": True},
    ]
    assert [f.object for f in run("postgres", "PG-11", languages=rows)] == ["plpython3u"]


# PG-12
def test_pg12_plaintext_bytea_and_missing():
    settings = settings_with(
        "postgres", sensitive_columns=["public.patients.national_id", "public.patients.phone", "public.billing.card"]
    )
    rows = [
        {"table_schema": "public", "table_name": "patients", "column_name": "national_id", "data_type": "text"},
        {"table_schema": "public", "table_name": "patients", "column_name": "phone", "data_type": "bytea"},
    ]
    found = {f.object: f.detail for f in run("postgres", "PG-12", settings, sensitive_columns=rows)}
    assert found == {
        "public.patients.national_id": "Stored as text (plaintext); expected pgcrypto-encrypted bytea.",
        "public.billing.card": "Column listed as sensitive was not found; cannot confirm it is protected.",
    }

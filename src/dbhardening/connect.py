"""Connections from environment variables. Drivers are imported lazily so unit tests need neither."""

from __future__ import annotations

import os
from typing import Any


class ConfigError(ValueError):
    """A required environment variable is missing."""


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"environment variable {name} is not set")
    return value


def _odbc(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def mssql_connect(
    database: str | None = None, encrypt: bool = True, *, user: str | None = None, password: str | None = None
) -> Any:
    import pyodbc

    trust = (not encrypt) or os.environ.get("MSSQL_TRUST_SERVER_CERT", "no") == "yes"
    parts = [
        "DRIVER={ODBC Driver 18 for SQL Server}",
        f"SERVER={os.environ.get('MSSQL_HOST', 'localhost')},{os.environ.get('MSSQL_PORT', '1433')}",
        f"UID={_odbc(user or _env('MSSQL_USER'))}",
        f"PWD={_odbc(password or _env('MSSQL_PASSWORD'))}",
        f"Encrypt={'yes' if encrypt else 'no'}",
        f"TrustServerCertificate={'yes' if trust else 'no'}",
    ]
    if database:
        parts.append(f"DATABASE={_odbc(database)}")
    return pyodbc.connect(";".join(parts), autocommit=True, timeout=15)


def pg_connect(database: str | None = None, *, user: str | None = None, password: str | None = None) -> Any:
    import psycopg

    kwargs: dict[str, Any] = {"autocommit": True, "connect_timeout": 15}
    if database:
        kwargs["dbname"] = database
    if user:
        kwargs["user"] = user
    if password:
        kwargs["password"] = password
    return psycopg.connect(**kwargs)

"""Applies numbered SQL scripts (seed or hardening) in order, with sqlcmd-style $(VAR) values from the environment."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import ExitStack, closing
from pathlib import Path
from typing import Any

from dbhardening.dbapi import describe_error

VARIABLE = re.compile(r"\$\((?P<name>[A-Z][A-Z0-9_]*)\)")
DIRECTIVE = re.compile(r"\A--\s*database:\s*(?P<name>[A-Za-z0-9_]+)\s*$", re.MULTILINE)
GO_LINE = re.compile(r"^\s*GO\s*$", re.IGNORECASE | re.MULTILINE)
SCRIPT_NAME = re.compile(r"^\d{2}-[a-z0-9-]+\.sql$")


class ScriptError(ValueError):
    """A script could not be prepared or failed on the server."""


def substitute(sql: str, env: Mapping[str, str]) -> str:
    """Replaces $(NAME); the value is meant for a '...' literal, so single quotes are doubled."""

    def value(match: re.Match[str]) -> str:
        name = match.group("name")
        if not env.get(name):
            raise ScriptError(f"environment variable {name} is not set")
        return env[name].replace("'", "''")

    return VARIABLE.sub(value, sql)


def script_database(sql: str) -> str | None:
    match = DIRECTIVE.match(sql)
    return match.group("name") if match else None


def batches(sql: str, engine: str) -> list[str]:
    parts = GO_LINE.split(sql) if engine == "mssql" else [sql]
    return [p.strip() for p in parts if p.strip()]


def list_scripts(directory: Path) -> list[Path]:
    scripts = sorted(p for p in directory.glob("*.sql"))
    bad = [p.name for p in scripts if not SCRIPT_NAME.match(p.name)]
    if bad:
        raise ScriptError(f"script names must look like NN-name.sql: {', '.join(bad)}")
    if not scripts:
        raise ScriptError(f"no NN-name.sql scripts in {directory}")
    return scripts


def _drain(cursor: Any) -> None:
    # pyodbc reports an error in a later statement of a batch only when its result set is reached.
    nextset = getattr(cursor, "nextset", None)
    while nextset is not None and nextset():
        pass


def apply_scripts(
    engine: str, directory: Path, connect: Callable[[str | None], Any], env: Mapping[str, str]
) -> list[str]:
    applied: list[str] = []
    with ExitStack() as stack:
        connections: dict[str | None, Any] = {}
        for path in list_scripts(directory):
            raw = path.read_text(encoding="utf-8")
            try:
                sql = substitute(raw, env)
            except ScriptError as exc:
                raise ScriptError(f"{path.name}: {exc}") from exc
            database = script_database(raw)
            try:
                if database not in connections:
                    connections[database] = stack.enter_context(closing(connect(database)))
                conn = connections[database]
                for batch in batches(sql, engine):
                    cursor = conn.cursor()
                    try:
                        cursor.execute(batch)
                        _drain(cursor)
                    finally:
                        cursor.close()
            except ScriptError:
                raise
            except Exception as exc:  # noqa: BLE001 - driver errors become one readable message
                raise ScriptError(f"{path.name}: {describe_error(exc)}") from exc
            applied.append(path.name)
    return applied

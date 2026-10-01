"""Runs one query and returns plain tuples (pyodbc and psycopg)."""

from __future__ import annotations

from typing import Any


def fetch(conn: Any, sql: str, params: tuple[Any, ...] | None = None) -> list[tuple[Any, ...]]:
    cur = conn.cursor()
    try:
        if params is None:
            cur.execute(sql)
        else:
            cur.execute(sql, params)
        return [tuple(row) for row in cur.fetchall()] if cur.description else []
    finally:
        cur.close()

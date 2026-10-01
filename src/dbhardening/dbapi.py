"""Small helpers over any DB-API connection (pyodbc and psycopg)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from dbhardening.snapshot import dataset_ok, dataset_unavailable


def rows(conn: Any, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    cur = conn.cursor()
    try:
        if params:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        if cur.description is None:
            return []
        columns = [d[0] for d in cur.description]
        return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]
    finally:
        cur.close()


def describe_error(exc: BaseException) -> str:
    first = (str(exc).splitlines() or [""])[0]
    return f"{type(exc).__name__}: {first}"[:300]


def run_dataset(fn: Callable[[], list[dict[str, Any]]]) -> dict[str, Any]:
    """Any driver error (permission, missing feature) makes the dataset unavailable instead of failing the run."""
    try:
        return dataset_ok(fn())
    except Exception as exc:  # noqa: BLE001 - every driver has its own exception tree
        return dataset_unavailable(describe_error(exc))

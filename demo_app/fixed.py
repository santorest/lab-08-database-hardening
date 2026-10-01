"""The fix: the patient name travels as a parameter, never as SQL text."""

from __future__ import annotations

from typing import Any

from demo_app import vulnerable
from demo_app.db import fetch

PG_SQL = (
    "SELECT a.id, p.full_name, a.starts_at, a.reason FROM appointments AS a "
    "JOIN patients AS p ON p.id = a.patient_id WHERE p.full_name = %s ORDER BY a.id"
)
MSSQL_SQL = (
    "SELECT a.id, p.full_name, a.starts_at, a.reason FROM dbo.appointments AS a "
    "JOIN dbo.patients AS p ON p.id = a.patient_id WHERE p.full_name = ? ORDER BY a.id"
)


def find_appointments_pg(conn: Any, patient_name: str) -> list[tuple[Any, ...]]:
    return fetch(conn, vulnerable.PG_SQL.format(name=patient_name))


def find_appointments_mssql(conn: Any, patient_name: str) -> list[tuple[Any, ...]]:
    return fetch(conn, vulnerable.MSSQL_SQL.format(name=patient_name))

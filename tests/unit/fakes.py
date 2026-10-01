"""A tiny DB-API stand-in: responses are matched by a substring of the SQL text."""

from __future__ import annotations

from typing import Any


class FakeCursor:
    def __init__(self, conn: FakeConnection) -> None:
        self.conn = conn
        self.description: list[tuple[str]] | None = None
        self._rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        self.conn.log.append((self.conn.database, sql, params))
        for key, result in self.conn.responses.items():
            if key in sql:
                if isinstance(result, Exception):
                    raise result
                columns, rows = result
                self.description = [(c,) for c in columns]
                self._rows = [tuple(r) for r in rows]
                return self
        self.description = [("unused",)]
        self._rows = []
        return self

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def nextset(self) -> bool:
        return False

    def close(self) -> None:
        pass


class FakeConnection:
    def __init__(self, responses: dict[str, Any], log: list[Any], database: str | None, encrypt: bool = True) -> None:
        self.responses, self.log, self.database, self.encrypt = responses, log, database, encrypt

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def close(self) -> None:
        pass


class FakeServer:
    """connect(database, encrypt) factory; per-database responses override the shared ones."""

    def __init__(self, responses: dict[str, Any], per_database: dict[str, dict[str, Any]] | None = None) -> None:
        self.responses = responses
        self.per_database = per_database or {}
        self.log: list[Any] = []
        self.opened: list[tuple[str | None, bool]] = []

    def __call__(self, database: str | None = None, encrypt: bool = True) -> FakeConnection:
        self.opened.append((database, encrypt))
        merged = {**self.responses, **self.per_database.get(database or "", {})}
        return FakeConnection(merged, self.log, database, encrypt)

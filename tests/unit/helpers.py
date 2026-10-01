"""Builders shared by the unit tests."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

from dbhardening.findings import Finding, assess
from dbhardening.settings import load_settings
from dbhardening.snapshot import dataset_ok, new_snapshot

SETTINGS = load_settings()
COLLECTED_AT = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


def settings_with(engine: str, **values: Any) -> dict[str, dict[str, Any]]:
    """A deep copy of the defaults with some keys of one engine replaced."""
    result = copy.deepcopy(SETTINGS)
    result[engine].update(values)
    return result


def snap(engine: str, **datasets: Any) -> dict[str, Any]:
    """A snapshot; a list becomes an ok dataset, a dict is used as the dataset object itself."""
    built = {name: value if isinstance(value, dict) else dataset_ok(value) for name, value in datasets.items()}
    return new_snapshot(engine, "test", built, collected_at=COLLECTED_AT)


def run(engine: str, check_id: str, settings: dict[str, Any] | None = None, **datasets: Any) -> list[Finding]:
    """Findings of one check (other checks see no data and are not evaluated, which is ignored here)."""
    return [f for f in assess(snap(engine, **datasets), settings or SETTINGS) if f.check_id == check_id]

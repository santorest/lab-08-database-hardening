"""Integration tests against the lab containers, after scripts/run-lab.sh. LAB_ENGINE selects the engine."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from dbhardening.snapshot import load_snapshot

OUT = Path(os.environ.get("LAB_OUT", "out"))
ENGINES = ("mssql", "postgres")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    engine = os.environ.get("LAB_ENGINE")
    if engine not in ENGINES:
        raise pytest.UsageError("set LAB_ENGINE=mssql or LAB_ENGINE=postgres (integration tests need a lab container)")
    for item in items:
        for marker in ENGINES:
            if marker in item.keywords and marker != engine:
                item.add_marker(pytest.mark.skip(reason=f"needs LAB_ENGINE={marker}"))


@pytest.fixture(scope="session")
def results() -> dict[str, Any]:
    folder = OUT / os.environ["LAB_ENGINE"]
    return {name: load_snapshot(folder / f"{name}.json") for name in ("before", "after", "after-again")}


@pytest.fixture(scope="session")
def out_dir() -> Path:
    return OUT / os.environ["LAB_ENGINE"]

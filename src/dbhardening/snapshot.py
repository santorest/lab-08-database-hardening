"""Snapshot format: one engine, when it was collected, and named datasets {status, error, items}."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORMAT = 1
VOLATILE_DATASETS = frozenset({"sessions"})  # differs on every collection, ignored when comparing snapshots


class SnapshotError(ValueError):
    """The file is not a usable snapshot."""


def dataset_ok(items: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    return {"status": "ok", "error": None, "items": [dict(item) for item in items]}


def dataset_unavailable(error: str) -> dict[str, Any]:
    return {"status": "unavailable", "error": error, "items": []}


def new_snapshot(
    engine: str, server_version: str, datasets: Mapping[str, Any], collected_at: datetime | None = None
) -> dict[str, Any]:
    when = (collected_at or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "format": FORMAT,
        "engine": engine,
        "collected_at": when,
        "server_version": server_version,
        "datasets": dict(datasets),
    }


def save_snapshot(snapshot: Mapping[str, Any], path: Path) -> None:
    # default=str turns driver values (datetime, Decimal, UUID) into text; collectors cast binary values in SQL.
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def load_snapshot(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read snapshot {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise SnapshotError(f"{path} is not a format-{FORMAT} snapshot")
    return data


def stable_view(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """The parts of a snapshot that must not change when nothing on the server changed."""
    view = copy.deepcopy(dict(snapshot))
    view.pop("collected_at", None)
    view["datasets"] = {k: v for k, v in view.get("datasets", {}).items() if k not in VOLATILE_DATASETS}
    return view

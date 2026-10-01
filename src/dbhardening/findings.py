"""Findings, the check catalog and the audit engine."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from dbhardening.snapshot import SnapshotError

SEVERITIES = ("High", "Medium", "Low")
ENGINES = ("mssql", "postgres")

Items = list[dict[str, Any]]
CheckFunc = Callable[[Mapping[str, Items], Mapping[str, Any]], list[tuple[str, str]]]


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: str
    status: str  # "Finding" or "NotEvaluated"
    object: str
    detail: str
    remediation: str
    area: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    engine: str
    title: str
    severity: str
    needs: tuple[str, ...]
    remediation: str
    area: str
    func: CheckFunc


CATALOG: dict[str, CheckSpec] = {}


def check(
    check_id: str,
    *,
    engine: str,
    title: str,
    severity: str,
    needs: Sequence[str],
    remediation: str,
    area: str,
) -> Callable[[CheckFunc], CheckFunc]:
    """Registers a pure check: func(data, engine_settings) -> [(object, detail), ...]."""
    if engine not in ENGINES:
        raise ValueError(f"unknown engine {engine!r}")
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")

    def register(func: CheckFunc) -> CheckFunc:
        if check_id in CATALOG:
            raise ValueError(f"duplicate check id {check_id}")
        CATALOG[check_id] = CheckSpec(check_id, engine, title, severity, tuple(needs), remediation, area, func)
        return func

    return register


def load_checks() -> None:
    """Importing the check modules registers their checks."""
    from dbhardening.checks import mssql, pg  # noqa: F401


def catalog_for(engine: str) -> list[CheckSpec]:
    load_checks()
    return sorted((s for s in CATALOG.values() if s.engine == engine), key=lambda s: s.check_id)


def _finding(spec: CheckSpec, status: str, obj: str, detail: str) -> Finding:
    return Finding(spec.check_id, spec.title, spec.severity, status, obj, detail, spec.remediation, spec.area)


def _missing(datasets: Mapping[str, Any], needs: Sequence[str]) -> list[str]:
    missing = []
    for name in needs:
        dataset = datasets.get(name)
        if not isinstance(dataset, Mapping):
            missing.append(f"{name} (not collected)")
        elif dataset.get("status") != "ok":
            missing.append(f"{name} ({dataset.get('error') or 'unavailable'})")
        elif not isinstance(dataset.get("items"), list):
            missing.append(f"{name} (malformed dataset)")
    return missing


def assess(snapshot: Mapping[str, Any], settings: Mapping[str, Any]) -> list[Finding]:
    """Runs every check of the snapshot's engine; a check without its data is NotEvaluated, never a pass."""
    engine = snapshot.get("engine")
    if engine not in ENGINES:
        raise SnapshotError(f"snapshot engine {engine!r} is not one of {', '.join(ENGINES)}")
    datasets = snapshot.get("datasets") or {}
    findings: list[Finding] = []
    for spec in catalog_for(str(engine)):
        missing = _missing(datasets, spec.needs)
        if missing:
            findings.append(_finding(spec, "NotEvaluated", "-", "Not evaluated: " + "; ".join(missing)))
            continue
        data = {name: list(datasets[name]["items"]) for name in spec.needs}
        for obj, detail in spec.func(data, settings[str(engine)]):
            findings.append(_finding(spec, "Finding", obj, detail))
    return findings

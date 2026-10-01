"""Settings: packaged defaults plus an optional TOML override with the same sections and keys."""

from __future__ import annotations

import tomllib
from importlib import resources
from pathlib import Path
from typing import Any


def load_settings(override: Path | None = None) -> dict[str, dict[str, Any]]:
    text = resources.files("dbhardening").joinpath("defaults.toml").read_text(encoding="utf-8")
    settings: dict[str, dict[str, Any]] = tomllib.loads(text)
    if override is None:
        return settings
    extra = tomllib.loads(override.read_text(encoding="utf-8"))
    for section, values in extra.items():
        if section not in settings or not isinstance(values, dict):
            raise ValueError(f"unknown settings section [{section}]")
        for key, value in values.items():
            if key not in settings[section]:
                raise ValueError(f"unknown setting {section}.{key}")
            expected = type(settings[section][key])
            if type(value) is not expected:
                raise ValueError(f"setting {section}.{key} must be {expected.__name__}")
            settings[section][key] = value
    return settings

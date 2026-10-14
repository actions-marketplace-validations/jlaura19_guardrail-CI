from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)"
)
# Poetry treats a bare version ("2.0.1") as an exact pin.
_BARE_VERSION = re.compile(r"^[0-9][A-Za-z0-9._+!-]*$")


def parse_requirements(path: Path) -> dict[str, str]:
    """Extract `name==version` pins from a requirements*.txt file."""
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _REQ_LINE.match(raw.split("#", 1)[0])
        if m and not m.group(2).endswith("."):
            pins[m.group(1)] = m.group(2)
    return pins


def _pin_from_pep508(spec: str) -> tuple[str, str] | None:
    try:
        req = Requirement(spec)
    except InvalidRequirement:
        return None
    specs = list(req.specifier)
    if len(specs) != 1 or specs[0].operator not in ("==", "==="):
        return None
    version = specs[0].version
    if "*" in version:
        return None
    return req.name, version


def _pin_from_poetry(constraint: Any) -> str | None:
    if isinstance(constraint, dict):
        constraint = constraint.get("version")
    if not isinstance(constraint, str):
        return None
    text = constraint.strip()
    if text.startswith("=="):
        text = text[2:].strip()
    if "*" in text or "," in text or not _BARE_VERSION.match(text):
        return None
    return text


def parse_pyproject(path: Path) -> dict[str, str]:
    """Extract exact pins from PEP 621 and Poetry dependency tables.

    Raises ValueError (tomllib.TOMLDecodeError) on invalid TOML.
    """
    with path.open("rb") as fh:
        data = tomllib.load(fh)

    pins: dict[str, str] = {}

    project_deps = (data.get("project") or {}).get("dependencies") or []
    for spec in project_deps:
        if isinstance(spec, str) and (pin := _pin_from_pep508(spec)):
            pins[pin[0]] = pin[1]

    poetry_deps = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, constraint in poetry_deps.items():
        if name.lower() == "python":
            continue
        if (version := _pin_from_poetry(constraint)) is not None:
            pins[name] = version

    return pins


def extract_dependencies(path: Path) -> dict[str, str]:
    """Dispatch on file type; unsupported file names yield no dependencies."""
    if path.name == "pyproject.toml":
        return parse_pyproject(path)
    if path.suffix == ".txt":
        return parse_requirements(path)
    return {}

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
BREAKING_WARNING = "(Warning: Major breaking upgrade)"


@dataclass(frozen=True, slots=True)
class FixSuggestion:
    version: str
    breaking: bool = False


@dataclass(frozen=True, slots=True)
class Vulnerability:
    package: str
    version: str
    vuln_id: str
    summary: str
    fixed_version: str | None
    breaking: bool = False

    @property
    def fix_label(self) -> str | None:
        """Fixed version, annotated when the upgrade crosses a major boundary."""
        if self.fixed_version is None:
            return None
        if self.breaking:
            return f"{self.fixed_version} {BREAKING_WARNING}"
        return self.fixed_version


def suggest_fix(current: str, fixed_versions: Iterable[str]) -> FixSuggestion | None:
    """Pick the minimal safe upgrade from the versions that fix a vulnerability.

    Preference: lowest fix in the same major.minor, then lowest in the same
    major, then lowest overall (flagged as a breaking upgrade). Unparseable
    version strings never raise; they are only used as a last resort.
    """
    parsed: list[tuple[Version, str]] = []
    unparsed: list[str] = []
    for raw in fixed_versions:
        try:
            parsed.append((Version(raw), raw))
        except InvalidVersion:
            unparsed.append(raw)
    parsed.sort(key=lambda p: p[0])

    try:
        cur: Version | None = Version(current)
    except InvalidVersion:
        cur = None

    if cur is None:
        # Cannot tell what is "newer" or "breaking", so offer the lowest fix.
        if parsed:
            return FixSuggestion(parsed[0][1])
        return FixSuggestion(unparsed[0]) if unparsed else None

    candidates = [p for p in parsed if p[0] > cur]
    if not cur.is_prerelease:
        candidates = [p for p in candidates if not p[0].is_prerelease] or candidates
    if not candidates:
        return FixSuggestion(unparsed[0]) if unparsed else None

    same_minor = [p for p in candidates if p[0].major == cur.major and p[0].minor == cur.minor]
    if same_minor:
        return FixSuggestion(same_minor[0][1])
    same_major = [p for p in candidates if p[0].major == cur.major]
    if same_major:
        return FixSuggestion(same_major[0][1])
    return FixSuggestion(candidates[0][1], breaking=True)


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    found: list[str] = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or pkg.get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    found.append(str(event["fixed"]))
    return found


def _cve_id(vuln: dict[str, Any]) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return str(vuln.get("id", "UNKNOWN"))


def query_osv(packages: dict[str, str], *, timeout: float = 30.0) -> list[Vulnerability]:
    """Look up {name: version} in OSV; logs a warning and returns [] on failure."""
    if not packages:
        return []
    items = list(packages.items())
    queries = [
        {"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in items
    ]
    try:
        resp = httpx.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OSV batch query failed; skipping dependency scan: %s", exc)
        return []

    # querybatch returns only IDs, so fetch details once per unique ID.
    details: dict[str, dict[str, Any]] = {}
    out: list[Vulnerability] = []
    for (name, version), result in zip(items, results):
        for stub in (result or {}).get("vulns", []):
            vid = stub["id"]
            if vid not in details:
                try:
                    r = httpx.get(OSV_VULN_URL.format(id=vid), timeout=timeout)
                    r.raise_for_status()
                    details[vid] = r.json()
                except (httpx.HTTPError, ValueError) as exc:
                    logger.warning("OSV detail lookup failed for %s: %s", vid, exc)
                    details[vid] = {"id": vid}
            vuln = details[vid]
            fix = suggest_fix(version, _fixed_versions(vuln, name))
            out.append(
                Vulnerability(
                    package=name,
                    version=version,
                    vuln_id=_cve_id(vuln),
                    summary=vuln.get("summary") or "No summary available.",
                    fixed_version=fix.version if fix else None,
                    breaking=fix.breaking if fix else False,
                )
            )
    return out

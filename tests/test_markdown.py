from __future__ import annotations

from guardrail.models import Finding, Severity
from guardrail.reporter.markdown import to_markdown


def _finding(**overrides) -> Finding:
    base = dict(
        severity=Severity.HIGH,
        category="Vulnerable Dependency",
        file="pyproject.toml",
        line=1,
        description="django==2.0: CVE-1 - bad | pipe",
        remediation="Upgrade django to >= 5.2.16 (Warning: Major breaking upgrade).",
    )
    return Finding(**{**base, **overrides})


def test_remediation_column_shows_breaking_annotation():
    md = to_markdown([_finding()])
    row = next(line for line in md.splitlines() if "Vulnerable Dependency" in line)
    assert row.endswith("| Upgrade django to >= 5.2.16 (Warning: Major breaking upgrade). |")


def test_pipes_are_escaped_and_rows_sorted_by_severity():
    md = to_markdown(
        [_finding(severity=Severity.LOW, category="Parse Error"), _finding(severity=Severity.CRITICAL)]
    )
    assert "bad \\| pipe" in md
    assert md.index("CRITICAL") < md.index("LOW")


def test_empty_report():
    assert "No issues found" in to_markdown([])

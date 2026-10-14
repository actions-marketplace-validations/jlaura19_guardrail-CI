from __future__ import annotations

from collections.abc import Sequence

from guardrail.models import Finding, Severity

_ORDER = {s: i for i, s in enumerate(Severity)}
_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "⚪",
}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def to_markdown(findings: Sequence[Finding]) -> str:
    lines = ["## 🛡️ GuardRail-CI Security Report", ""]
    if not findings:
        lines.append("✅ No issues found.")
        return "\n".join(lines) + "\n"
    lines += [
        f"**{len(findings)} issue(s) found.**",
        "",
        "| Severity | Category | Location | Description | Remediation |",
        "|---|---|---|---|---|",
    ]
    for f in sorted(findings, key=lambda f: (_ORDER[f.severity], f.file, f.line)):
        loc = f"`{_cell(f.file)}:{f.line}`"
        lines.append(
            f"| {_ICON[f.severity]} {f.severity.value} | {_cell(f.category)} | {loc} "
            f"| {_cell(f.description)} | {_cell(f.remediation)} |"
        )
    return "\n".join(lines) + "\n"

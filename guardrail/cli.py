from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from enum import Enum
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from guardrail import github
from guardrail.models import Finding, Severity
from guardrail.reporter.markdown import to_markdown
from guardrail.scanner.ast_visitor import scan_source
from guardrail.scanner.dependencies import extract_dependencies
from guardrail.scanner.osv_client import query_osv

app = typer.Typer(help="GuardRail-CI: developer-first SAST scanner.", no_args_is_help=True)

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "site-packages"}
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


class OutputFormat(str, Enum):
    text = "text"
    markdown = "markdown"


def _iter_files(root: Path, pattern: str) -> Iterator[Path]:
    for path in root.rglob(pattern):
        if path.is_file() and not SKIP_DIRS.intersection(path.relative_to(root).parts):
            yield path


def scan_directory(root: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []

    for path in _iter_files(root, "*.py"):
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"Skipped {rel}: {exc}")
            continue
        findings.extend(scan_source(source, rel))

    for dep_file in (*_iter_files(root, "requirements*.txt"), *_iter_files(root, "pyproject.toml")):
        rel = dep_file.relative_to(root).as_posix()
        try:
            vulns = query_osv(extract_dependencies(dep_file))
        except (OSError, ValueError, httpx.HTTPError) as exc:
            warnings.append(f"Dependency check failed for {rel}: {exc}")
            continue
        for v in vulns:
            fix = (
                f"Upgrade {v.package} to >= {v.fix_label}."
                if v.fixed_version
                else f"No fixed version published; consider replacing {v.package}."
            )
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="Vulnerable Dependency",
                    file=rel,
                    line=1,
                    description=f"{v.package}=={v.version}: {v.vuln_id} - {v.summary}",
                    remediation=fix,
                )
            )
    return findings, warnings


def _publish_to_github(findings: list[Finding], *, explicit: bool, err: Console) -> None:
    # Implicit (env-based) mode must not fail or warn on non-PR events like push.
    if not explicit and not github.is_pull_request_event():
        return
    try:
        # With no findings, only refresh a stale comment; never create a new one.
        github.post_or_update_comment(
            to_markdown(findings), create_if_missing=bool(findings)
        )
    except github.GitHubError as exc:
        err.print(f"[yellow]warning:[/yellow] Could not post PR comment: {exc}")


@app.callback()
def main() -> None:
    """GuardRail-CI command line interface."""


@app.command()
def scan(
    target_directory: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    format: OutputFormat = typer.Option(OutputFormat.text, "--format", "-f"),
    github_pr: bool = typer.Option(
        False, "--github-pr", help="Post findings as a PR comment (auto-on in GitHub Actions)."
    ),
) -> None:
    """Scan TARGET_DIRECTORY for insecure routes, vulnerable deps and secrets."""
    findings, warnings = scan_directory(target_directory.resolve())
    err = Console(stderr=True)
    for w in warnings:
        err.print(f"[yellow]warning:[/yellow] {w}")

    if github_pr or os.environ.get("GITHUB_ACTIONS") == "true":
        _publish_to_github(findings, explicit=github_pr, err=err)

    if format is OutputFormat.markdown:
        sys.stdout.reconfigure(encoding="utf-8")  # emoji-safe on Windows consoles
        typer.echo(to_markdown(findings))
    else:
        console = Console()
        if not findings:
            console.print("[green]No issues found.[/green]")
        else:
            table = Table(show_lines=True)
            for col in ("Severity", "Category", "Location", "Description", "Remediation"):
                table.add_column(col, overflow="fold")
            for f in findings:
                table.add_row(
                    f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
                    f.category,
                    f"{f.file}:{f.line}",
                    f.description,
                    f.remediation,
                )
            console.print(table)

    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

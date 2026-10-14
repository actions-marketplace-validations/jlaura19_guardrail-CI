# 🛡️ GuardRail-CI

[![CI](https://github.com/OWNER/guardrail-ci/actions/workflows/guardrail-ci.yml/badge.svg)](https://github.com/OWNER/guardrail-ci/actions/workflows/guardrail-ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

**Catch unauthenticated FastAPI routes, vulnerable dependencies and leaked secrets before they merge.**
GuardRail-CI reads your code (it never runs it), then posts one tidy, self-updating comment on the pull request with exactly what to fix.

> Replace `OWNER` in the badges and snippets below with your GitHub user or organisation.

## What it finds

| Check | How | Severity |
| --- | --- | --- |
| Unauthenticated state-changing routes (`@app.post/put/patch/delete`, `@router.*` with no `Depends(...)` / `Security(...)`) | AST inspection | 🟠 HIGH |
| Hardcoded GitHub tokens (`ghp_…`) and AWS access keys (`AKIA…`) in string literals | AST + regex | 🔴 CRITICAL |
| Known-vulnerable pinned dependencies (`requirements*.txt`, `pyproject.toml` PEP 621 and Poetry) | [OSV](https://osv.dev) API | 🟠 HIGH |
| Files that fail to parse | AST | ⚪ LOW |

Dependency findings come with a **minimal safe upgrade**: the lowest fixed version in your current `major.minor`, else the lowest in your major, else the lowest overall flagged `(Warning: Major breaking upgrade)`.

## How it works

```
  Pull Request (opened / synchronize / reopened)
         │
         ▼
 ┌──────────────────────── GuardRail-CI ────────────────────────┐
 │                                                              │
 │  *.py files ──► AST engine ──► insecure routes, secrets      │
 │                                                              │
 │  requirements*.txt ┐                                         │
 │  pyproject.toml    ┴─► pinned deps ──► OSV API ─► CVEs +     │
 │                                        minimal safe upgrade  │
 └───────────────────────────────┬──────────────────────────────┘
                                 ▼
                     Markdown report (severity table)
                                 │
                                 ▼
        PR comment  <!-- guardrail-ci-report -->
        (created once, then updated in place on every push)
                                 │
                                 ▼
        exit code 1 on HIGH/CRITICAL  ──►  failing check blocks merge
```

## Quickstart

```bash
pip install guardrail-ci          # or: pip install git+https://github.com/OWNER/guardrail-ci
guardrail scan .                  # rich table in the terminal
guardrail scan . --format markdown
```

Exit code is `1` when any HIGH or CRITICAL finding exists, otherwise `0`, so it works as a gate in any CI.
Running inside GitHub Actions (or with `--github-pr`) also posts the report to the pull request; set `GITHUB_TOKEN`, `GITHUB_REPOSITORY` and `GITHUB_EVENT_PATH` yourself when running it outside the provided action.

## GitHub Actions

Drop this into `.github/workflows/guardrail-ci.yml`:

```yaml
name: GuardRail-CI

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  guardrail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: OWNER/guardrail-ci@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          target-dir: "."
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

Mark the `guardrail` job as a required status check in your branch protection to block merges on findings.
Pull requests from forks get a read-only token, so the check still fails correctly but the comment is skipped; the workflow in this repo documents the safe options in detail. Want to verify your setup end to end? See [docs/LIVE_VALIDATION.md](docs/LIVE_VALIDATION.md).

## What the bot comment looks like

---

## 🛡️ GuardRail-CI Security Report

**3 issue(s) found.**

| Severity | Category | Location | Description | Remediation |
|---|---|---|---|---|
| 🔴 CRITICAL | Hardcoded Secret | `app/settings.py:12` | Possible AWS access key hardcoded in source. | Revoke the credential, remove it from history, and load it from environment/secret manager. |
| 🟠 HIGH | Unauthenticated State-Changing Route | `app/routes/items.py:18` | POST route 'create_item' has no authentication dependency (Depends/Security). | Add an auth dependency, e.g. `user = Depends(get_current_user)`, or `dependencies=[Depends(...)]` on the route. |
| 🟠 HIGH | Vulnerable Dependency | `requirements.txt:1` | django==2.0: CVE-2018-7537 - Django Denial-of-service possibility in truncatechars_html and truncatewords_html template filters | Upgrade django to >= 2.0.3. |

---

Push a fix and the same comment flips to **✅ No issues found.**; no comment spam.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## Limitations

- Only exact pins (`==`) are checked for vulnerabilities; ranges such as `>=` or `^` are skipped.
- Route detection matches decorators on objects literally named `app` or `router`.
- Secret detection covers GitHub `ghp_` tokens and AWS access key IDs only.

## License

[MIT](LICENSE)

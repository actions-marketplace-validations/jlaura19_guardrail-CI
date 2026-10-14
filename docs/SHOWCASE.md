# GuardRail-CI showcase assets

All figures below were measured on the live validation run
(`jlaura19/guardrail-CI`, PR #1): first comment posted 13 s after the workflow
started, whole job 16-22 s, 126 automated tests.

## 1. Copy-paste output (terminal and PR comment)

### Terminal

```text
$ guardrail scan . --format markdown ; echo "exit code: $?"
exit code: 1
```

### Bot comment on the pull request

> ## 🛡️ GuardRail-CI Security Report
>
> **3 issue(s) found.**
>
> | Severity | Category | Location | Description | Remediation |
> |---|---|---|---|---|
> | 🔴 CRITICAL | Hardcoded Secret | `samples/bad.py:6` | Possible GitHub token hardcoded in source. | Revoke the credential, remove it from history, and load it from environment/secret manager. |
> | 🟠 HIGH | Unauthenticated State-Changing Route | `samples/bad.py:10` | POST route 'delete_user' has no authentication dependency (Depends/Security). | Add an auth dependency, e.g. `user = Depends(get_current_user)`, or `dependencies=[Depends(...)]` on the route. |
> | 🟠 HIGH | Vulnerable Dependency | `samples/requirements-test.txt:1` | requests==2.20.0: CVE-2023-32681 - Unintended leak of Proxy-Authorization header in requests | Upgrade requests to >= 2.31.0. |

After the fix commit, the **same** comment is edited in place:

> ## 🛡️ GuardRail-CI Security Report
>
> ✅ No issues found.

### One-paragraph project description

GuardRail-CI is a developer-first SAST GitHub Action for FastAPI services. It
parses Python with the `ast` module (never executing the code) to flag
unauthenticated state-changing routes and hardcoded GitHub/AWS credentials,
checks pinned dependencies from `requirements*.txt`, PEP 621 and Poetry files
against the OSV database, and recommends the minimal safe upgrade. Results land
in a single PR comment that updates in place, and the job fails the check on
HIGH/CRITICAL findings.

## 2. Resume bullets

- **CI/CD latency:** Built a GitHub Action that scans a PR and posts a
  remediation report in ~13 s (16-22 s end to end) by using pure AST analysis
  (no code execution, no builds) and one batched OSV request for all
  dependencies, so security gating adds seconds, not minutes, to the pipeline.
- **Security coverage:** Implemented `ast.NodeVisitor`-based detection of
  unauthenticated POST/PUT/PATCH/DELETE FastAPI routes (OWASP API Security Top
  10 2023: API2 Broken Authentication, API5 Broken Function Level
  Authorization), hardcoded GitHub/AWS secrets, and known-vulnerable pinned
  dependencies via OSV; validated by 126 pytest cases, including HTTP mocking
  and failure injection.
- **Automated remediation:** Generated SemVer-aware "minimal safe upgrade"
  advice (same minor, then same major, then a flagged breaking upgrade) and a
  single idempotent PR comment, located by a hidden marker and PATCHed in place
  on each push, with least-privilege token permissions and a documented
  fork-safe design.

## 3. 60-second demo script (video or GIF)

Setup: a repo with the action installed, a clean `main`, two windows (editor
and the PR page), font size large, dark theme.

| Time | Screen | Narration / action |
|---|---|---|
| 0:00-0:07 | Title card, then the GitHub repo | "GuardRail-CI: a security reviewer that comments on every pull request." |
| 0:07-0:17 | Editor: add a route `@app.post("/users/delete")` with no auth, plus `requests==2.20.0` in `requirements.txt` | "Here's a typical risky change: an unauthenticated delete endpoint and an old, vulnerable dependency." |
| 0:17-0:25 | Terminal: `git push`, then click **Compare and pull request** and **Create** | "Push and open the PR." |
| 0:25-0:38 | PR page, **Checks** tab spinning; comment appears at about 13 s. Zoom on the table | "Within seconds the bot comments: a HIGH unauthenticated route and the CVE, with the exact fix." Point at the red failing check. |
| 0:38-0:48 | Editor: add `user=Depends(get_current_user)`, bump `requests>=2.31.0` pin, commit, push | "Fix it by adding auth and upgrading the dependency." |
| 0:48-0:56 | PR page: comment flips to "✅ No issues found.", check turns green; hover over **edited** | "The same comment updates in place, with no spam, and the check goes green." |
| 0:56-1:00 | End card: repo URL | "GuardRail-CI: shift-left security in one YAML file." |

Recording tips: trim waiting time instead of speeding it up, so the ~13 s
latency is honest (show a small on-screen timer); for a GIF, keep only the
0:25-0:56 segment at 1.5x.

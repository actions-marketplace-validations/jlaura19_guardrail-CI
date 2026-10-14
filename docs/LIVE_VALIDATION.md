# Live validation checklist

End-to-end check that GuardRail-CI comments on a real PR, updates that comment
in place, and gates the build with the right exit codes.

Prerequisites: a GitHub account, `git`, and (optional but handy) the
[GitHub CLI](https://cli.github.com/) (`gh auth login`).

## 0. Pre-flight (local)

```bash
pip install -e ".[dev]"
python -m pytest -q                 # all green
guardrail scan .                    # "No issues found." and exit code 0
```

`main` must scan clean, otherwise step 5c cannot show a passing run.

## 1. Push the repository to GitHub

> The project folder may sit inside a larger git repository (for example your
> home directory). Run `git init` **inside the project folder** so that you
> only publish GuardRail-CI.

```bash
cd "<path to guardrail ci>"
git init -b main
git add .
git commit -m "feat: GuardRail-CI MVP"
gh repo create guardrail-ci --public --source . --push
# or create the repo in the UI, then: git remote add origin <url> && git push -u origin main
```

## 2. Repository settings

1. **Settings -> Actions -> General -> Workflow permissions**: keep
   *Read repository contents permissions*; the workflow requests
   `pull-requests: write` itself.
2. **Settings -> Actions -> General -> Fork pull request workflows**: leave the
   default (fork PRs get a read-only token; see the comments in
   `.github/workflows/guardrail-ci.yml`).
3. The workflow only runs on pull requests, so open any throwaway PR once (or
   continue to step 4): a status check can only be selected for branch
   protection after it has run.

## 3. Branch protection (so a failing scan blocks merges)

**Settings -> Branches -> Add branch ruleset / protection rule** for `main`:

- [x] Require a pull request before merging
- [x] Require status checks to pass -> add **`guardrail`** (the job name)
- [x] Require branches to be up to date before merging (optional)

## 4. Create the failing test branch

```bash
git switch -c test/guardrail-demo
mkdir samples
```

Create `samples/bad.py` with an unauthenticated state-changing route:

```python
from fastapi import FastAPI

app = FastAPI()


@app.post("/items")
async def create_item(item: dict):
    return item
```

Optionally add a dependency finding (a real, known-vulnerable pin):

```bash
echo "django==2.0" > samples/requirements.txt
```

Commit, push and open the PR:

```bash
git add samples
git commit -m "test: add intentionally insecure sample"
git push -u origin test/guardrail-demo
gh pr create --base main --head test/guardrail-demo --title "GuardRail demo" --body "Live validation"
```

## 5. Verify

### a) Initial comment with findings

- [ ] The **GuardRail-CI** run starts on the PR (Checks tab or `gh pr checks`).
- [ ] The job **fails** (red X).
- [ ] The PR has **one** comment from `github-actions[bot]` titled
      *GuardRail-CI Security Report* with a row like
      `HIGH | Unauthenticated State-Changing Route | samples/bad.py:6`
      (plus `Vulnerable Dependency` rows if you added the django pin, with a
      suggestion such as `Upgrade django to >= 2.0.3`).
- [ ] The comment body starts with the hidden marker
      `<!-- guardrail-ci-report -->`:

```bash
gh api repos/{owner}/{repo}/issues/<PR_NUMBER>/comments --jq '.[] | {id, user: .user.login, starts: (.body | .[0:30])}'
```

### b) Fix commit updates the same comment (idempotency)

Note the comment `id` from the command above, then fix `samples/bad.py`:

```python
from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user() -> str:
    return "demo"


@app.post("/items")
async def create_item(item: dict, user: str = Depends(get_current_user)):
    return item
```

Also delete `samples/requirements.txt` if you added it.

```bash
git add -A
git commit -m "fix: require authentication on /items"
git push
```

- [ ] A new run starts on the `synchronize` event.
- [ ] The **same comment id** is edited (the UI shows *edited*) and now reads
      **No issues found.** There is still exactly **one** GuardRail comment:

```bash
gh api repos/{owner}/{repo}/issues/<PR_NUMBER>/comments --jq '[.[] | select(.body | contains("guardrail-ci-report"))] | length'   # -> 1
```

### c) Exit codes

- [ ] Failing run: in the run log, step **GuardRail-CI scan** ends with
      `Process completed with exit code 1` and the check is red.
- [ ] Fixed run: the same step exits `0`, the check is green, and the merge
      button is unblocked.
- [ ] Optional local confirmation:

```bash
guardrail scan . ; echo $?       # PowerShell: guardrail scan . ; $LASTEXITCODE
```

## 6. Extra checks (recommended)

- [ ] **Re-run** the job from the Actions tab: still one comment.
- [ ] **Fork PR**: the check still goes red/green, the log shows
      `warning: Could not post PR comment`, and the exit code reflects only the
      findings.
- [ ] **Push to `main`** (not a PR): no comment attempt and no warning.

## 7. Clean up

```bash
gh pr close <PR_NUMBER> --delete-branch
```

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `Resource not accessible by integration` (403) in the log | Workflow `permissions:` lacks `pull-requests: write`, or a fork PR (expected) |
| No comment and no warning | Run was triggered by `push` / `workflow_dispatch`, not a PR event |
| Status check `guardrail` not selectable in branch protection | The workflow has not run yet on the repo |
| Duplicate comments | The hidden marker `<!-- guardrail-ci-report -->` was removed from the comment body |

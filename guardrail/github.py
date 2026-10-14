from __future__ import annotations

import json
import os
from typing import Any

import httpx

MARKER = "<!-- guardrail-ci-report -->"
API_URL = "https://api.github.com"


class GitHubError(RuntimeError):
    """Raised when the GitHub context is incomplete or the API call fails."""


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise GitHubError(f"Environment variable {name} is not set.")
    return value


def get_pr_number(event_path: str | None = None) -> int:
    path = event_path or _require_env("GITHUB_EVENT_PATH")
    try:
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
    except (OSError, ValueError) as exc:
        raise GitHubError(f"Cannot read event payload {path}: {exc}") from exc
    number = (event.get("pull_request") or {}).get("number") or event.get("number")
    if not isinstance(number, int):
        raise GitHubError("Event payload does not describe a pull request.")
    return number


def is_pull_request_event() -> bool:
    try:
        get_pr_number()
    except GitHubError:
        return False
    return True


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _find_existing_comment(
    client: httpx.Client, base: str, issue_number: int
) -> int | None:
    page = 1
    while True:
        resp = client.get(
            f"{base}/issues/{issue_number}/comments",
            params={"per_page": 100, "page": page},
        )
        resp.raise_for_status()
        comments: list[dict[str, Any]] = resp.json()
        for comment in comments:
            if MARKER in (comment.get("body") or ""):
                return int(comment["id"])
        if len(comments) < 100:
            return None
        page += 1


def post_or_update_comment(markdown_body: str, *, create_if_missing: bool = True) -> None:
    """Update the existing GuardRail comment on the PR, or create one."""
    token = _require_env("GITHUB_TOKEN")
    repo = _require_env("GITHUB_REPOSITORY")
    issue_number = get_pr_number()
    base = f"{os.environ.get('GITHUB_API_URL', API_URL)}/repos/{repo}"
    body = markdown_body if MARKER in markdown_body else f"{MARKER}\n{markdown_body}"

    try:
        with httpx.Client(headers=_headers(token), timeout=30.0) as client:
            comment_id = _find_existing_comment(client, base, issue_number)
            if comment_id is not None:
                resp = client.patch(
                    f"{base}/issues/comments/{comment_id}", json={"body": body}
                )
            elif create_if_missing:
                resp = client.post(
                    f"{base}/issues/{issue_number}/comments", json={"body": body}
                )
            else:
                return
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise GitHubError(f"GitHub API request failed: {exc}") from exc

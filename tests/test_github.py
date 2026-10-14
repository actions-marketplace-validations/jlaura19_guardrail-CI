from __future__ import annotations

import json

import httpx
import pytest
import respx

from guardrail.github import MARKER, GitHubError, get_pr_number, post_or_update_comment

API = "https://api.github.com/repos/octo/repo"


@pytest.fixture(autouse=True)
def gh_env(monkeypatch, tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 42}}))
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    return event


@pytest.fixture
def api():
    with respx.mock(assert_all_called=False) as router:
        yield router


def test_creates_comment_when_none_exists(api):
    api.get(f"{API}/issues/42/comments").respond(json=[{"id": 1, "body": "unrelated"}])
    post = api.post(f"{API}/issues/42/comments").respond(201, json={})
    post_or_update_comment("hello")
    body = json.loads(post.calls.last.request.content)["body"]
    assert body.startswith(MARKER) and "hello" in body
    assert post.calls.last.request.headers["Authorization"] == "Bearer tok"


def test_updates_existing_comment(api):
    api.get(f"{API}/issues/42/comments").respond(
        json=[{"id": 1, "body": "x"}, {"id": 9, "body": f"{MARKER}\nold"}]
    )
    patch = api.patch(f"{API}/issues/comments/9").respond(json={})
    post = api.post(f"{API}/issues/42/comments").respond(201, json={})
    post_or_update_comment("new")
    assert "new" in json.loads(patch.calls.last.request.content)["body"]
    assert not post.called


def test_marker_not_duplicated(api):
    api.get(f"{API}/issues/42/comments").respond(json=[])
    post = api.post(f"{API}/issues/42/comments").respond(201, json={})
    post_or_update_comment(f"{MARKER}\nbody")
    assert json.loads(post.calls.last.request.content)["body"].count(MARKER) == 1


def test_finds_comment_on_second_page(api):
    page1 = [{"id": i, "body": "x"} for i in range(100)]
    api.get(f"{API}/issues/42/comments", params={"page": "1"}).respond(json=page1)
    api.get(f"{API}/issues/42/comments", params={"page": "2"}).respond(
        json=[{"id": 777, "body": MARKER}]
    )
    patch = api.patch(f"{API}/issues/comments/777").respond(json={})
    post_or_update_comment("x")
    assert patch.called


def test_create_if_missing_false_skips_creation(api):
    api.get(f"{API}/issues/42/comments").respond(json=[])
    post = api.post(f"{API}/issues/42/comments").respond(201, json={})
    post_or_update_comment("x", create_if_missing=False)
    assert not post.called


def test_http_error_wrapped(api):
    api.get(f"{API}/issues/42/comments").respond(500)
    with pytest.raises(GitHubError):
        post_or_update_comment("x")


def test_network_error_wrapped(api):
    api.get(f"{API}/issues/42/comments").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(GitHubError):
        post_or_update_comment("x")


@pytest.mark.parametrize("var", ["GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH"])
def test_missing_env_raises(monkeypatch, var):
    monkeypatch.delenv(var)
    with pytest.raises(GitHubError, match=var):
        post_or_update_comment("x")


def test_pr_number_from_top_level_number(gh_env):
    gh_env.write_text(json.dumps({"number": 3}))
    assert get_pr_number() == 3


@pytest.mark.parametrize("content", ["{}", "not json"])
def test_invalid_event_payload(gh_env, content):
    gh_env.write_text(content)
    with pytest.raises(GitHubError):
        get_pr_number()

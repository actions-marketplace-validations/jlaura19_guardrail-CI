from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from guardrail.cli import app
from guardrail.github import MARKER
from guardrail.scanner.osv_client import OSV_BATCH_URL

runner = CliRunner()

GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"
API = "https://api.github.com/repos/octo/repo"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("GITHUB_ACTIONS", "GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def project(tmp_path: Path):
    def _make(**files: str) -> Path:
        for name, content in files.items():
            (tmp_path / name).write_text(content, encoding="utf-8")
        return tmp_path

    return _make


@pytest.fixture
def clean_project(project):
    return project(**{"ok.py": '@app.post("/x")\ndef h(u=Depends(a)): ...\n'})


@pytest.fixture
def high_project(project):
    return project(**{"bad.py": '@app.post("/x")\ndef h(): ...\n'})


def test_clean_code_exits_zero(clean_project):
    result = runner.invoke(app, ["scan", str(clean_project)])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_high_finding_exits_one(high_project):
    result = runner.invoke(app, ["scan", str(high_project)])
    assert result.exit_code == 1
    assert "Unauthenticated" in result.output
    assert "HIGH" in result.output


def test_critical_finding_exits_one(project):
    root = project(**{"s.py": f'T = "{GH_TOKEN}"\n'})
    assert runner.invoke(app, ["scan", str(root)]).exit_code == 1


def test_low_only_exits_zero(project):
    root = project(**{"bad.py": "def broken(:\n"})
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 0
    assert "Parse Error" in result.output


def test_markdown_format(high_project):
    result = runner.invoke(app, ["scan", str(high_project), "--format", "markdown"])
    assert result.exit_code == 1
    assert "| Severity | Category | Location | Description | Remediation |" in result.output
    assert "`bad.py:2`" in result.output
    assert "GuardRail-CI Security Report" in result.output


def test_text_format_is_not_markdown(high_project):
    result = runner.invoke(app, ["scan", str(high_project)])
    assert "|---|" not in result.output
    assert "GuardRail-CI Security Report" not in result.output


def test_markdown_clean(clean_project):
    result = runner.invoke(app, ["scan", str(clean_project), "--format", "markdown"])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_invalid_format_rejected(clean_project):
    assert runner.invoke(app, ["scan", str(clean_project), "--format", "xml"]).exit_code == 2


def test_missing_directory_rejected(tmp_path):
    assert runner.invoke(app, ["scan", str(tmp_path / "nope")]).exit_code == 2


def test_skips_virtualenv_directories(project, tmp_path):
    root = project()
    (root / ".venv").mkdir()
    (root / ".venv" / "bad.py").write_text('@app.post("/x")\ndef h(): ...\n')
    assert runner.invoke(app, ["scan", str(root)]).exit_code == 0


@respx.mock
def test_vulnerable_requirement_reported(project):
    respx.post(OSV_BATCH_URL).respond(json={"results": [{"vulns": [{"id": "GHSA-1"}]}]})
    respx.get("https://api.osv.dev/v1/vulns/GHSA-1").respond(
        json={
            "id": "GHSA-1",
            "aliases": ["CVE-2020-0001"],
            "summary": "Bad",
            "affected": [
                {
                    "package": {"name": "django", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"fixed": "2.2"}]}],
                }
            ],
        }
    )
    root = project(**{"requirements.txt": "django==2.0  # pinned\n"})
    result = runner.invoke(app, ["scan", str(root), "--format", "markdown"])
    assert result.exit_code == 1
    assert "CVE-2020-0001" in result.output
    assert "Upgrade django to >= 2.2" in result.output


@respx.mock
def test_pyproject_pin_with_breaking_upgrade_is_annotated(project):
    respx.post(OSV_BATCH_URL).respond(json={"results": [{"vulns": [{"id": "GHSA-2"}]}]})
    respx.get("https://api.osv.dev/v1/vulns/GHSA-2").respond(
        json={
            "id": "GHSA-2",
            "aliases": ["CVE-2026-0002"],
            "summary": "Old bug",
            "affected": [
                {
                    "package": {"name": "django", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"fixed": "5.2.16"}, {"fixed": "4.2.20"}]}],
                }
            ],
        }
    )
    root = project(**{"pyproject.toml": '[project]\ndependencies = ["django==2.0"]\n'})
    result = runner.invoke(app, ["scan", str(root), "--format", "markdown"])
    assert result.exit_code == 1
    assert "`pyproject.toml:1`" in result.output
    assert "Upgrade django to >= 4.2.20 (Warning: Major breaking upgrade)." in result.output


def test_invalid_pyproject_warns_but_does_not_crash(project):
    root = project(**{"pyproject.toml": "[project\n"})
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 0
    assert "Dependency check failed for pyproject.toml" in result.output


@respx.mock
def test_osv_outage_does_not_fail_scan(project):
    respx.post(OSV_BATCH_URL).mock(side_effect=httpx.ConnectError("down"))
    root = project(**{"requirements.txt": "django==2.0\n"})
    assert runner.invoke(app, ["scan", str(root)]).exit_code == 0


class TestGithubIntegration:
    @pytest.fixture
    def gh_env(self, monkeypatch, tmp_path):
        event = tmp_path / "event.json"
        event.write_text(json.dumps({"pull_request": {"number": 7}}))
        monkeypatch.setenv("GITHUB_TOKEN", "tok")
        monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
        return event

    @respx.mock
    def test_flag_posts_comment_when_findings(self, gh_env, high_project):
        respx.get(f"{API}/issues/7/comments").respond(json=[])
        post = respx.post(f"{API}/issues/7/comments").respond(201, json={})
        result = runner.invoke(app, ["scan", str(high_project), "--github-pr"])
        assert result.exit_code == 1
        assert post.called
        assert MARKER in json.loads(post.calls.last.request.content)["body"]

    @respx.mock
    def test_flag_clean_without_existing_comment_posts_nothing(self, gh_env, clean_project):
        respx.get(f"{API}/issues/7/comments").respond(json=[])
        post = respx.post(f"{API}/issues/7/comments").respond(201, json={})
        result = runner.invoke(app, ["scan", str(clean_project), "--github-pr"])
        assert result.exit_code == 0
        assert not post.called

    @respx.mock
    def test_clean_scan_refreshes_stale_comment(self, gh_env, clean_project):
        respx.get(f"{API}/issues/7/comments").respond(json=[{"id": 5, "body": MARKER}])
        patch = respx.patch(f"{API}/issues/comments/5").respond(json={})
        runner.invoke(app, ["scan", str(clean_project), "--github-pr"])
        assert "No issues found" in json.loads(patch.calls.last.request.content)["body"]

    @respx.mock
    def test_github_actions_env_enables_posting(self, gh_env, high_project, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        respx.get(f"{API}/issues/7/comments").respond(json=[])
        post = respx.post(f"{API}/issues/7/comments").respond(201, json={})
        runner.invoke(app, ["scan", str(high_project)])
        assert post.called

    @respx.mock
    def test_github_actions_env_on_non_pr_event_is_silent(
        self, gh_env, high_project, monkeypatch
    ):
        gh_env.write_text(json.dumps({"ref": "refs/heads/main"}))
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        result = runner.invoke(app, ["scan", str(high_project)])
        assert result.exit_code == 1
        assert "Could not post" not in result.output

    @respx.mock
    def test_api_failure_warns_but_keeps_exit_code(self, gh_env, high_project):
        respx.get(f"{API}/issues/7/comments").respond(403)
        result = runner.invoke(app, ["scan", str(high_project), "--github-pr"])
        assert result.exit_code == 1
        assert "Could not post PR comment" in result.output

    def test_no_posting_without_flag_or_env(self, high_project):
        with respx.mock(assert_all_called=False) as router:
            result = runner.invoke(app, ["scan", str(high_project)])
            assert not router.calls
        assert result.exit_code == 1

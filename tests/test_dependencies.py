from __future__ import annotations

from pathlib import Path

import pytest

from guardrail.scanner.dependencies import (
    extract_dependencies,
    parse_pyproject,
    parse_requirements,
)


@pytest.fixture
def write(tmp_path: Path):
    def _write(name: str, content: str) -> Path:
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        return path

    return _write


class TestPyprojectPep621:
    def test_extracts_exact_pins(self, write):
        path = write(
            "pyproject.toml",
            '[project]\nname = "x"\ndependencies = ["django==2.0", "httpx == 0.27.0"]\n',
        )
        assert parse_pyproject(path) == {"django": "2.0", "httpx": "0.27.0"}

    def test_handles_extras_and_markers(self, write):
        path = write(
            "pyproject.toml",
            '[project]\ndependencies = ["uvicorn[standard]==0.30.1 ; python_version >= \'3.11\'"]\n',
        )
        assert parse_pyproject(path) == {"uvicorn": "0.30.1"}

    @pytest.mark.parametrize(
        "spec",
        ["django>=2.0", "django~=2.0", "django<3", "django==2.*", "django>=2,<3", "django", "not a req!!"],
    )
    def test_ignores_non_exact_specs(self, write, spec):
        path = write("pyproject.toml", f'[project]\ndependencies = ["{spec}"]\n')
        assert parse_pyproject(path) == {}


class TestPyprojectPoetry:
    def test_extracts_pins_in_all_forms(self, write):
        path = write(
            "pyproject.toml",
            """
            [tool.poetry.dependencies]
            python = "3.11"
            django = "==2.0"
            flask = "2.3.1"
            requests = { version = "==2.31.0", extras = ["socks"] }
            """,
        )
        assert parse_pyproject(path) == {"django": "2.0", "flask": "2.3.1", "requests": "2.31.0"}

    @pytest.mark.parametrize("constraint", ['"^2.0"', '"~2.0"', '">=2.0"', '"*"', '"2.*"', '"==1.0,<2"'])
    def test_ignores_ranges(self, write, constraint):
        path = write("pyproject.toml", f"[tool.poetry.dependencies]\ndjango = {constraint}\n")
        assert parse_pyproject(path) == {}

    def test_ignores_git_and_path_dependencies(self, write):
        path = write(
            "pyproject.toml",
            '[tool.poetry.dependencies]\nlib = { git = "https://example.com/lib.git" }\n'
            'multi = [{ version = "1.0" }]\n',
        )
        assert parse_pyproject(path) == {}


def test_pep621_and_poetry_are_merged(write):
    path = write(
        "pyproject.toml",
        '[project]\ndependencies = ["a==1.0"]\n[tool.poetry.dependencies]\nb = "2.0"\n',
    )
    assert parse_pyproject(path) == {"a": "1.0", "b": "2.0"}


def test_pyproject_without_dependencies(write):
    assert parse_pyproject(write("pyproject.toml", '[tool.black]\nline-length = 88\n')) == {}


def test_invalid_toml_raises_value_error(write):
    with pytest.raises(ValueError):
        parse_pyproject(write("pyproject.toml", "[project\n"))


class TestRequirementsTxt:
    def test_parses_pins_and_skips_noise(self, write):
        path = write(
            "requirements.txt",
            "# comment\ndjango==2.0  # inline\nrequests[socks]==2.31.0\nflask>=2\n-r other.txt\n\n",
        )
        assert parse_requirements(path) == {"django": "2.0", "requests": "2.31.0"}


def test_extract_dispatches_on_file_name(write):
    req = write("requirements-dev.txt", "a==1\n")
    pyp = write("pyproject.toml", '[project]\ndependencies = ["b==2"]\n')
    other = write("setup.cfg", "")
    assert extract_dependencies(req) == {"a": "1"}
    assert extract_dependencies(pyp) == {"b": "2"}
    assert extract_dependencies(other) == {}

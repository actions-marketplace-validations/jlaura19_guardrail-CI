from __future__ import annotations

import textwrap

import pytest

from guardrail.models import Finding, Severity
from guardrail.scanner.ast_visitor import scan_source

GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"  # 4 + 36 chars
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


@pytest.fixture
def scan():
    def _scan(src: str) -> list[Finding]:
        return scan_source(textwrap.dedent(src), "sample.py")

    return _scan


def categories(findings: list[Finding]) -> list[str]:
    return [f.category for f in findings]


def test_token_fixtures_match_expected_shape():
    assert len(GH_TOKEN) == 40 and len(AWS_KEY) == 20


class TestUnauthenticatedRoutes:
    @pytest.mark.parametrize(
        "decorator, method",
        [
            ('@app.post("/x")', "POST"),
            ('@app.put("/x")', "PUT"),
            ('@app.patch("/x")', "PATCH"),
            ('@router.delete("/x")', "DELETE"),
            ('@router.post("/x", status_code=201)', "POST"),
        ],
    )
    def test_flags_state_changing_routes(self, scan, decorator, method):
        findings = scan(f"{decorator}\ndef handler(item: dict):\n    return item\n")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity is Severity.HIGH
        assert f.category == "Unauthenticated State-Changing Route"
        assert method in f.description
        assert f.file == "sample.py"
        assert f.line == 2  # reported on the def line

    def test_flags_async_route(self, scan):
        findings = scan('@app.post("/x")\nasync def h():\n    ...\n')
        assert categories(findings) == ["Unauthenticated State-Changing Route"]

    def test_flags_each_route_separately(self, scan):
        findings = scan(
            """
            @app.post("/a")
            def a(): ...

            @router.delete("/b")
            def b(): ...
            """
        )
        assert len(findings) == 2

    @pytest.mark.parametrize("decorator", ['@app.get("/x")', '@router.get("/x")', '@app.head("/x")'])
    def test_ignores_read_only_routes(self, scan, decorator):
        assert scan(f"{decorator}\ndef h(): ...\n") == []

    def test_ignores_unrelated_decorators(self, scan):
        assert scan('@other.post("/x")\ndef h(): ...\n') == []
        assert scan("@cache\ndef h(): ...\n") == []


class TestFalsePositivePrevention:
    @pytest.mark.parametrize(
        "source",
        [
            pytest.param(
                '@app.post("/x")\ndef h(user=Depends(get_user)): ...\n', id="depends-default"
            ),
            pytest.param(
                '@router.delete("/x")\ndef h(user=Security(get_user, scopes=["a"])): ...\n',
                id="security-default",
            ),
            pytest.param(
                '@app.put("/x")\ndef h(user: Annotated[User, Depends(get_user)]): ...\n',
                id="annotated-depends",
            ),
            pytest.param(
                '@app.patch("/x", dependencies=[Depends(verify)])\ndef h(): ...\n',
                id="decorator-dependencies",
            ),
            pytest.param(
                '@app.post("/x")\ndef h(*, user=Depends(get_user)): ...\n', id="kwonly-default"
            ),
            pytest.param(
                '@app.post("/x")\ndef h(user=fastapi.Depends(get_user)): ...\n',
                id="attribute-depends",
            ),
            pytest.param(
                '@app.post("/x")\nasync def h(user=Depends(get_user)): ...\n', id="async"
            ),
        ],
    )
    def test_authenticated_routes_not_flagged(self, scan, source):
        assert scan(source) == []

    def test_non_auth_default_still_flagged(self, scan):
        findings = scan('@app.post("/x")\ndef h(q: int = Query(1)): ...\n')
        assert len(findings) == 1

    def test_empty_decorator_dependencies_still_flagged(self, scan):
        findings = scan('@app.post("/x", dependencies=[])\ndef h(): ...\n')
        assert len(findings) == 1


class TestSecrets:
    def test_github_token_in_variable(self, scan):
        findings = scan(f'TOKEN = "{GH_TOKEN}"\n')
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].category == "Hardcoded Secret"
        assert "GitHub" in findings[0].description
        assert findings[0].line == 1

    def test_aws_key_in_variable(self, scan):
        findings = scan(f'KEY = "{AWS_KEY}"\n')
        assert len(findings) == 1
        assert "AWS" in findings[0].description

    def test_secret_in_dict_value(self, scan):
        findings = scan(f'CONFIG = {{\n    "aws": "{AWS_KEY}",\n    "gh": "{GH_TOKEN}",\n}}\n')
        assert sorted(f.line for f in findings) == [2, 3]

    def test_secret_in_call_argument_and_fstring_prefix(self, scan):
        findings = scan(f'client("{GH_TOKEN}")\nurl = f"https://x/{{a}}?k={AWS_KEY}"\n')
        assert len(findings) == 2

    def test_secret_embedded_in_longer_string(self, scan):
        assert len(scan(f'h = "Authorization: token {GH_TOKEN}"\n')) == 1

    @pytest.mark.parametrize(
        "value",
        [
            "ghp_tooshort",
            "AKIA123",
            "akiaabcdefghijklmnop",  # wrong case
            "AKIA" + "a" * 16,  # lowercase body
            "hello world",
        ],
    )
    def test_non_secrets_not_flagged(self, scan, value):
        assert scan(f'x = "{value}"\n') == []

    def test_bytes_literal_ignored(self, scan):
        assert scan(f'x = b"{AWS_KEY}"\n') == []

    def test_secret_in_comment_ignored(self, scan):
        assert scan(f"# {AWS_KEY}\n") == []


class TestSyntaxErrors:
    @pytest.mark.parametrize(
        "source",
        ["def broken(:\n", "x = (\n", "class\n", "print 'py2'\n", "if True:\npass\n"],
    )
    def test_malformed_source_yields_parse_error(self, source):
        findings = scan_source(source, "bad.py")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity is Severity.LOW
        assert f.category == "Parse Error"
        assert f.file == "bad.py"
        assert f.line >= 1

    def test_null_bytes_do_not_raise(self):
        findings = scan_source("x = 1\x00\n", "nul.py")
        assert [f.category for f in findings] == ["Parse Error"]

    def test_empty_source_is_clean(self):
        assert scan_source("", "empty.py") == []

    def test_deeply_nested_source_does_not_raise(self):
        findings = scan_source("x = " + "(" * 5000 + "1" + ")" * 5000, "deep.py")
        assert all(f.category == "Parse Error" for f in findings)

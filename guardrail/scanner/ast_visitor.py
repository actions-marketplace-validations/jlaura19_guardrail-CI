from __future__ import annotations

import ast
import re

from guardrail.models import Finding, Severity

STATE_CHANGING_METHODS = {"post", "put", "delete", "patch"}
ROUTE_OBJECTS = {"app", "router"}
AUTH_CALLS = {"Depends", "Security"}

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "GitHub token": re.compile(r"ghp_[A-Za-z0-9_]{36}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
}


class SecurityVisitor(ast.NodeVisitor):
    """Collects insecure-route and hardcoded-secret findings for one file."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[Finding] = []

    # -- routes -----------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_route(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_route(node)
        self.generic_visit(node)

    def _check_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            method = self._route_method(dec)
            if method is None:
                continue
            if not (self._decorator_has_auth(dec) or self._args_have_auth(node.args)):
                self.findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Unauthenticated State-Changing Route",
                        file=self.filename,
                        line=node.lineno,
                        description=(
                            f"{method.upper()} route '{node.name}' has no "
                            "authentication dependency (Depends/Security)."
                        ),
                        remediation=(
                            "Add an auth dependency, e.g. "
                            "`user = Depends(get_current_user)`, or "
                            "`dependencies=[Depends(...)]` on the route."
                        ),
                    )
                )
            return

    @staticmethod
    def _route_method(dec: ast.expr) -> str | None:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if (
            isinstance(target, ast.Attribute)
            and target.attr in STATE_CHANGING_METHODS
            and isinstance(target.value, ast.Name)
            and target.value.id in ROUTE_OBJECTS
        ):
            return target.attr
        return None

    @staticmethod
    def _contains_auth_call(node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if name in AUTH_CALLS:
                    return True
        return False

    def _decorator_has_auth(self, dec: ast.expr) -> bool:
        if not isinstance(dec, ast.Call):
            return False
        return any(
            kw.arg == "dependencies" and self._contains_auth_call(kw.value)
            for kw in dec.keywords
        )

    def _args_have_auth(self, args: ast.arguments) -> bool:
        defaults = [d for d in (*args.defaults, *args.kw_defaults) if d is not None]
        annotations = [
            a.annotation
            for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
            if a.annotation is not None
        ]
        return any(self._contains_auth_call(n) for n in (*defaults, *annotations))

    # -- secrets ----------------------------------------------------------
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(node.value):
                    self.findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Hardcoded Secret",
                            file=self.filename,
                            line=node.lineno,
                            description=f"Possible {name} hardcoded in source.",
                            remediation=(
                                "Revoke the credential, remove it from history, "
                                "and load it from environment/secret manager."
                            ),
                        )
                    )
        self.generic_visit(node)


def scan_source(source: str, filename: str = "<string>") -> list[Finding]:
    """Scan Python source; syntax errors yield a LOW finding instead of raising."""
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        line = getattr(exc, "lineno", None) or 1
        return [
            Finding(
                severity=Severity.LOW,
                category="Parse Error",
                file=filename,
                line=line,
                description=f"Could not parse file: {exc}",
                remediation="Fix the syntax error so the file can be analyzed.",
            )
        ]
    visitor = SecurityVisitor(filename)
    visitor.visit(tree)
    return visitor.findings

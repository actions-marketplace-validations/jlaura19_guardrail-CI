from __future__ import annotations

import logging

import httpx
import pytest
import respx

from guardrail.scanner.osv_client import (
    BREAKING_WARNING,
    OSV_BATCH_URL,
    FixSuggestion,
    query_osv,
    suggest_fix,
)

VULN_URL = "https://api.osv.dev/v1/vulns/{id}"


def vuln_detail(vid, *, aliases=(), summary="A summary", package="django", fixed=None):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "id": vid,
        "aliases": list(aliases),
        "summary": summary,
        "affected": [
            {
                "package": {"name": package, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }


@pytest.fixture
def mock_osv():
    with respx.mock(assert_all_called=False) as router:
        yield router


def test_empty_input_makes_no_requests(mock_osv):
    assert query_osv({}) == []
    assert not mock_osv.calls


def test_parses_cve_summary_and_fixed_version(mock_osv):
    batch = mock_osv.post(OSV_BATCH_URL).respond(
        json={"results": [{"vulns": [{"id": "GHSA-aaaa"}]}, {}]}
    )
    mock_osv.get(VULN_URL.format(id="GHSA-aaaa")).respond(
        json=vuln_detail(
            "GHSA-aaaa", aliases=["GHSA-x", "CVE-2018-7537"], summary="DoS in filters", fixed="2.0.3"
        )
    )

    vulns = query_osv({"django": "2.0", "httpx": "0.27.0"})

    assert len(vulns) == 1
    v = vulns[0]
    assert (v.package, v.version) == ("django", "2.0")
    assert v.vuln_id == "CVE-2018-7537"
    assert v.summary == "DoS in filters"
    assert v.fixed_version == "2.0.3"

    import json

    payload = json.loads(batch.calls.last.request.content)
    assert payload["queries"] == [
        {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "2.0"},
        {"package": {"name": "httpx", "ecosystem": "PyPI"}, "version": "0.27.0"},
    ]


def test_falls_back_to_osv_id_and_no_fix(mock_osv):
    mock_osv.post(OSV_BATCH_URL).respond(json={"results": [{"vulns": [{"id": "PYSEC-1"}]}]})
    mock_osv.get(VULN_URL.format(id="PYSEC-1")).respond(
        json={"id": "PYSEC-1", "affected": []}
    )
    (v,) = query_osv({"pkg": "1.0"})
    assert v.vuln_id == "PYSEC-1"
    assert v.fixed_version is None
    assert v.summary


def test_fixed_version_ignores_other_packages(mock_osv):
    mock_osv.post(OSV_BATCH_URL).respond(json={"results": [{"vulns": [{"id": "X-1"}]}]})
    mock_osv.get(VULN_URL.format(id="X-1")).respond(
        json=vuln_detail("X-1", package="other", fixed="9.9")
    )
    (v,) = query_osv({"django": "2.0"})
    assert v.fixed_version is None


def test_detail_fetched_once_per_unique_id(mock_osv):
    mock_osv.post(OSV_BATCH_URL).respond(
        json={"results": [{"vulns": [{"id": "SHARED"}]}, {"vulns": [{"id": "SHARED"}]}]}
    )
    detail = mock_osv.get(VULN_URL.format(id="SHARED")).respond(
        json=vuln_detail("SHARED", package="a", fixed="1")
    )
    vulns = query_osv({"a": "0.1", "b": "0.2"})
    assert [v.package for v in vulns] == ["a", "b"]
    assert detail.call_count == 1


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(lambda route: route.respond(500), id="http-500"),
        pytest.param(lambda route: route.mock(side_effect=httpx.ConnectError("down")), id="connect-error"),
        pytest.param(lambda route: route.mock(side_effect=httpx.ReadTimeout("slow")), id="timeout"),
        pytest.param(lambda route: route.respond(200, content=b"not json"), id="invalid-json"),
    ],
)
def test_batch_failure_logs_warning_and_returns_empty(mock_osv, caplog, failure):
    failure(mock_osv.post(OSV_BATCH_URL))
    with caplog.at_level(logging.WARNING, logger="guardrail.scanner.osv_client"):
        assert query_osv({"django": "2.0"}) == []
    assert any(r.levelno == logging.WARNING for r in caplog.records)


class TestSuggestFix:
    @pytest.mark.parametrize(
        "current, fixed, expected",
        [
            # (b) lowest patch in the same major.minor wins over lower-numbered older branches
            ("2.0", ["1.11.18", "2.0.10", "2.0.3", "2.1.5", "5.2.16"], FixSuggestion("2.0.3")),
            ("2.0.5", ["2.0.3", "2.0.10", "2.1.0"], FixSuggestion("2.0.10")),
            # (c) no patch in the same minor -> lowest in the same major
            ("2.0", ["2.2.4", "2.1.5", "3.0.1", "5.2.16"], FixSuggestion("2.1.5")),
            ("1.4.0", ["1.11.18", "1.5.2"], FixSuggestion("1.5.2")),
            # (d) only major upgrades -> lowest, flagged breaking
            ("2.0", ["5.2.16", "4.2.20", "3.2.25"], FixSuggestion("3.2.25", breaking=True)),
            ("1.0", ["2.0"], FixSuggestion("2.0", breaking=True)),
            # (a) fixes at or below the current version are ignored
            ("2.0.4", ["2.0.3", "2.0.4"], None),
            ("2.0", [], None),
        ],
    )
    def test_selection_tiers(self, current, fixed, expected):
        assert suggest_fix(current, fixed) == expected

    def test_input_order_does_not_matter(self):
        assert suggest_fix("2.0", ["2.0.10", "2.0.3", "2.0.9"]) == FixSuggestion("2.0.3")

    def test_compares_numerically_not_lexically(self):
        assert suggest_fix("1.9", ["1.10.0", "1.9.2"]) == FixSuggestion("1.9.2")
        assert suggest_fix("1.8", ["1.10.0", "1.9.0"]) == FixSuggestion("1.9.0")

    def test_prefers_final_over_prerelease(self):
        assert suggest_fix("2.0", ["2.0.3rc1", "2.0.4"]) == FixSuggestion("2.0.4")
        assert suggest_fix("2.0", ["2.0.3rc1"]) == FixSuggestion("2.0.3rc1")

    def test_unparseable_fix_versions_are_skipped(self):
        assert suggest_fix("2.0", ["garbage", "2.0.3"]) == FixSuggestion("2.0.3")

    def test_only_unparseable_fixes_fall_back_to_raw_string(self):
        assert suggest_fix("2.0", ["not-a-version"]) == FixSuggestion("not-a-version")

    def test_unparseable_current_version_falls_back_to_lowest_fix(self):
        assert suggest_fix("weird", ["3.0", "2.1", "bad"]) == FixSuggestion("2.1")
        assert suggest_fix("weird", ["bad"]) == FixSuggestion("bad")
        assert suggest_fix("weird", []) is None


def test_query_osv_uses_minimal_safe_upgrade(mock_osv):
    mock_osv.post(OSV_BATCH_URL).respond(json={"results": [{"vulns": [{"id": "V1"}, {"id": "V2"}]}]})
    detail = vuln_detail("V1", aliases=["CVE-1"], fixed="5.2.16")
    detail["affected"][0]["ranges"].append(
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.0.10"}]}
    )
    detail["affected"][0]["ranges"].append(
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.1"}, {"fixed": "2.0.3"}]}
    )
    mock_osv.get(VULN_URL.format(id="V1")).respond(json=detail)
    mock_osv.get(VULN_URL.format(id="V2")).respond(
        json=vuln_detail("V2", aliases=["CVE-2"], fixed="5.2.16")
    )

    first, second = query_osv({"django": "2.0"})

    assert (first.fixed_version, first.breaking) == ("2.0.3", False)
    assert first.fix_label == "2.0.3"
    assert (second.fixed_version, second.breaking) == ("5.2.16", True)
    assert second.fix_label == f"5.2.16 {BREAKING_WARNING}"


def test_detail_failure_still_reports_vulnerability(mock_osv, caplog):
    mock_osv.post(OSV_BATCH_URL).respond(json={"results": [{"vulns": [{"id": "GHSA-bad"}]}]})
    mock_osv.get(VULN_URL.format(id="GHSA-bad")).respond(500)
    with caplog.at_level(logging.WARNING, logger="guardrail.scanner.osv_client"):
        (v,) = query_osv({"django": "2.0"})
    assert v.vuln_id == "GHSA-bad"
    assert v.fixed_version is None
    assert "GHSA-bad" in caplog.text

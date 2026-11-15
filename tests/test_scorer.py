"""Scoring engine, grading, remediation wiring and quality-gate tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.models import (
    AuditReport,
    Category,
    Finding,
    SectionResult,
    Severity,
    Status,
    TargetReport,
)
from core.scorer import (
    DEFAULT_CATEGORY_WEIGHTS,
    GENERIC_REMEDIATION,
    REMEDIATIONS,
    Scorer,
    score_to_grade,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def finding(
    check_id: str = "http.hsts.missing",
    *,
    status: Status = Status.FAIL,
    severity: Severity = Severity.HIGH,
    weight: float = 10.0,
    category: Category = Category.HTTP,
    remediation_key: str | None = "http.hsts",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        category=category,
        severity=severity,
        status=status,
        weight=weight,
        description="test",
        remediation_key=remediation_key,
    )


def target_with(*findings: Finding, category: Category = Category.HTTP) -> TargetReport:
    section = SectionResult(category=category)
    section.extend(findings)
    report = TargetReport(target="example.com", sections={category.value: section})
    return Scorer().apply(report)


class TestCategoryMath:
    def test_all_pass_is_100(self) -> None:
        score, earned, possible = Scorer.score_findings(
            [finding(status=Status.PASS, severity=Severity.PASS), finding(status=Status.PASS)]
        )
        assert score == 100.0
        assert earned == possible

    def test_all_fail_is_zero(self) -> None:
        assert Scorer.score_findings([finding(), finding()])[0] == 0.0

    def test_warning_credits_40_percent(self) -> None:
        score, _, _ = Scorer.score_findings([finding(status=Status.WARN)])
        assert score == 40.0

    def test_info_has_no_penalty(self) -> None:
        score, _, _ = Scorer.score_findings(
            [finding(status=Status.INFO, severity=Severity.INFO), finding(status=Status.PASS)]
        )
        assert score == 100.0

    def test_mixed_weights(self) -> None:
        score, _, possible = Scorer.score_findings(
            [
                finding(status=Status.PASS, weight=10),
                finding(status=Status.FAIL, weight=10),
                finding(status=Status.WARN, weight=5),
            ]
        )
        assert possible == 25
        assert score == pytest.approx(100 * (10 + 0 + 2) / 25, abs=0.01)

    def test_zero_weight_is_ignored(self) -> None:
        assert Scorer.score_findings([finding(weight=0)]) == (0.0, 0.0, 0.0)


class TestTargetScoring:
    def test_overall_uses_category_weights(self) -> None:
        report = TargetReport(
            target="example.com",
            sections={
                Category.HTTP.value: SectionResult(
                    category=Category.HTTP, findings=[finding(status=Status.PASS)]
                ),
                Category.TLS.value: SectionResult(
                    category=Category.TLS,
                    findings=[finding(check_id="tls.trust", category=Category.TLS)],
                ),
                Category.DNS.value: SectionResult(
                    category=Category.DNS,
                    findings=[finding(check_id="dns.spf", category=Category.DNS)],
                ),
            },
        )
        Scorer().score_target(report)
        assert report.scores[Category.HTTP.value] == 100.0
        assert report.scores[Category.TLS.value] == 0.0
        expected = 100 * DEFAULT_CATEGORY_WEIGHTS[Category.HTTP.value] / 100
        assert report.overall_score == pytest.approx(expected, abs=0.01)
        assert report.grade == score_to_grade(report.overall_score)

    def test_missing_category_is_renormalised(self) -> None:
        report = TargetReport(
            target="example.com",
            sections={
                Category.DNS.value: SectionResult(
                    category=Category.DNS,
                    findings=[finding(check_id="dns.spf", category=Category.DNS)],
                )
            },
        )
        Scorer().score_target(report)
        assert report.overall_score == 0.0
        # A 50 % DNS category must map to a 50 overall score, not 15.
        report.sections[Category.DNS.value].findings = [
            finding(check_id="dns.spf", category=Category.DNS, status=Status.WARN)
        ]
        Scorer().score_target(report)
        assert report.overall_score == 40.0

    def test_ignore_checks(self) -> None:
        report = TargetReport(
            target="example.com",
            sections={
                Category.HTTP.value: SectionResult(
                    category=Category.HTTP,
                    findings=[
                        finding(check_id="http.hsts.missing"),
                        finding(check_id="http.csp.missing", status=Status.PASS),
                    ],
                )
            },
        )
        Scorer(ignore_checks=["http.hsts"]).score_target(report)
        assert report.overall_score == 100.0

    def test_category_weight_validation(self) -> None:
        with pytest.raises(ValueError):
            Scorer(category_weights={"http_headers": 0, "tls": 0, "dns_email": 0})


class TestRemediation:
    def test_attached_to_problems_only(self) -> None:
        report = target_with(
            finding(status=Status.FAIL),
            finding(check_id="http.csp.present", status=Status.PASS, severity=Severity.PASS),
        )
        assert report.findings[0].remediation is not None
        assert report.findings[1].remediation is None

    def test_placeholders_are_rendered(self) -> None:
        report = target_with(
            finding(check_id="dns.spf", category=Category.DNS, remediation_key="dns.spf")
        )
        remediation = report.findings[0].remediation
        assert remediation is not None
        assert "example.com" in (remediation.dns or "")
        assert "{target}" not in (remediation.dns or "")

    def test_unknown_key_gets_generic_remediation(self) -> None:
        report = target_with(finding(remediation_key="does.not.exist"))
        remediation = report.findings[0].remediation
        assert remediation is not None
        assert remediation.summary == GENERIC_REMEDIATION.summary

    def test_every_template_has_a_snippet(self) -> None:
        for key, remediation in REMEDIATIONS.items():
            assert remediation.summary, key
            assert any(
                (remediation.nginx, remediation.apache, remediation.cloudflare, remediation.dns)
            ), f"{key} has no copy-pasteable snippet"

    def test_auditor_keys_exist(self) -> None:
        """Every remediation_key used in the auditor code must be registered."""
        used: set[str] = set()
        for path in [
            REPO_ROOT / "auditors" / "http_auditor.py",
            REPO_ROOT / "auditors" / "tls_auditor.py",
            REPO_ROOT / "auditors" / "dns_auditor.py",
        ]:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "remediation_key"
                            and isinstance(keyword.value, ast.Constant)
                            and isinstance(keyword.value.value, str)
                        ):
                            used.add(keyword.value.value)
        missing = used - set(REMEDIATIONS)
        assert not missing, f"unregistered remediation keys: {sorted(missing)}"
        assert len(used) >= 20


class TestGates:
    def base_report(self, score_findings: list[Finding]) -> AuditReport:
        section = SectionResult(category=Category.HTTP)
        section.extend(score_findings)
        target = TargetReport(target="example.com", sections={Category.HTTP.value: section})
        Scorer().apply(target)
        return AuditReport(targets=[target])

    def test_fail_under(self) -> None:
        report = self.base_report([finding(status=Status.PASS)])
        report.fail_under = 90
        assert report.passed is True
        assert report.gate_failures() == []

        report = self.base_report([finding()])
        report.fail_under = 90
        assert report.passed is False
        assert "below --fail-under 90" in report.gate_failures()[0]

    def test_fail_on_severity(self) -> None:
        report = self.base_report([finding(severity=Severity.HIGH)])
        report.fail_on_severity = "critical"
        assert report.passed is True

        report.fail_on_severity = "high"
        assert report.passed is False
        assert "at or above HIGH" in report.gate_failures()[0]

    def test_no_gate_always_passes(self) -> None:
        report = self.base_report([finding(severity=Severity.CRITICAL)])
        assert report.passed is True

    def test_worst_severity(self) -> None:
        report = self.base_report([finding(severity=Severity.CRITICAL)])
        assert report.worst_severity() is Severity.CRITICAL

    def test_counts(self) -> None:
        report = self.base_report(
            [
                finding(severity=Severity.CRITICAL),
                finding(status=Status.WARN, severity=Severity.MEDIUM),
                finding(status=Status.PASS, severity=Severity.PASS),
            ]
        )
        counts = report.counts()
        assert counts["CRITICAL"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["PASS"] == 1


class TestSeverityOrdering:
    def test_ordering_helpers(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
        assert Severity.PASS < Severity.INFO
        assert Severity.CRITICAL.rank == 5
        assert Status.FAIL.score_factor == 0.0
        assert Status.WARN.score_factor == 0.4

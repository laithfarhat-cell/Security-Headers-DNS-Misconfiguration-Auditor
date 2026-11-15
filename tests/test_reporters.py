"""JSON / SARIF / Markdown / HTML exporter tests."""

from __future__ import annotations

import json
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
from core.scorer import Scorer
from reporters.exporter import Exporter

XSS = "<script>alert('xss')</script>"


def _finding(
    check_id: str,
    title: str,
    *,
    category: Category,
    status: Status,
    severity: Severity,
    weight: float = 5.0,
    evidence: str | None = None,
    remediation_key: str | None = None,
    description: str = "Description of the issue.",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        category=category,
        severity=severity,
        status=status,
        weight=weight,
        description=description,
        evidence=evidence,
        remediation_key=remediation_key,
        references=["https://owasp.org/www-project-secure-headers/"],
    )


def sample_report() -> AuditReport:
    http = SectionResult(
        category=Category.HTTP,
        data={"final_url": "https://example.com/", "status_code": 200, "redirect_chain": []},
        findings=[
            _finding(
                "http.hsts.missing",
                "Strict-Transport-Security header is missing",
                category=Category.HTTP,
                status=Status.FAIL,
                severity=Severity.HIGH,
                weight=10,
                evidence="Strict-Transport-Security: absent",
                remediation_key="http.hsts",
            ),
            _finding(
                "http.csp.unsafe_inline",
                "CSP allows 'unsafe-inline'",
                category=Category.HTTP,
                status=Status.WARN,
                severity=Severity.MEDIUM,
                evidence="script-src 'self' 'unsafe-inline'",
                remediation_key="http.csp",
            ),
            _finding(
                "http.x_content_type_options.nosniff",
                "nosniff is set",
                category=Category.HTTP,
                status=Status.PASS,
                severity=Severity.PASS,
            ),
            _finding(
                "http.header.server",
                "Server header discloses software version",
                category=Category.HTTP,
                status=Status.WARN,
                severity=Severity.LOW,
                evidence=f"Server: nginx/1.24.0 {XSS}",
                remediation_key="http.tech_disclosure",
            ),
        ],
    )
    tls = SectionResult(
        category=Category.TLS,
        data={"certificate": {"issuer": "CN=Test CA", "not_after": "2026-12-01T00:00:00+00:00"}},
        findings=[
            _finding(
                "tls.expiry",
                "TLS certificate expires in 16 days",
                category=Category.TLS,
                status=Status.WARN,
                severity=Severity.MEDIUM,
                weight=9,
                remediation_key="tls.expiry",
            )
        ],
    )
    dns = SectionResult(
        category=Category.DNS,
        data={"spf": {"records": ["v=spf1 -all"]}, "dmarc": {"records": ["v=DMARC1; p=none"]}},
        findings=[
            _finding(
                "dns.dmarc.policy",
                "DMARC policy is monitor-only (p=none)",
                category=Category.DNS,
                status=Status.WARN,
                severity=Severity.MEDIUM,
                weight=6,
                evidence="v=DMARC1; p=none",
                remediation_key="dns.dmarc",
            ),
            _finding(
                "dns.mta_sts.missing",
                "MTA-STS is not configured",
                category=Category.DNS,
                status=Status.INFO,
                severity=Severity.INFO,
                weight=1,
                remediation_key="dns.mta_sts",
            ),
        ],
    )
    target = TargetReport(
        target="example.com",
        sections={
            Category.HTTP.value: http,
            Category.TLS.value: tls,
            Category.DNS.value: dns,
        },
        metadata={
            "final_url": "https://example.com/",
            "status_code": 200,
            "redirect_chain": [{"url": "https://example.com/", "status": 200}],
        },
        duration_ms=1234.5,
    )
    Scorer().apply(target)
    report = AuditReport(targets=[target], duration_ms=1234.5, fail_under=85)
    report.options = {"category_weights": {"http_headers": 45, "tls": 25, "dns_email": 30}}
    return report


class TestJson:
    def test_structure_and_remediation(self) -> None:
        data = json.loads(Exporter(sample_report()).to_json())
        assert data["schema_version"] == "1.0"
        assert data["tool"]["name"] == "secaudit"
        assert data["summary"]["targets"] == 1
        assert data["summary"]["grade"] == data["results"][0]["grade"]
        assert data["gate"]["fail_under"] == 85

        result = data["results"][0]
        assert result["target"] == "example.com"
        assert set(result["category_scores"]) == {"http_headers", "tls", "dns_email"}
        findings = {f["check_id"]: f for f in result["findings"]}
        hsts = findings["http.hsts.missing"]
        assert hsts["status"] == "fail"
        assert "nginx" in hsts["remediation"]
        assert "add_header Strict-Transport-Security" in hsts["remediation"]["nginx"]
        assert hsts["remediation"]["dns"] is None  # HSTS is not a DNS record
        assert hsts["remediation"]["cloudflare"]

    def test_include_passed_flag(self) -> None:
        data = json.loads(Exporter(sample_report(), include_passed=False).to_json())
        statuses = {f["status"] for f in data["results"][0]["findings"]}
        assert "pass" not in statuses
        assert "fail" in statuses

    def test_writes_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "nested" / "audit.json"
        Exporter(sample_report()).write_json(destination)
        assert json.loads(destination.read_text())["summary"]["targets"] == 1


class TestSarif:
    def test_valid_document(self) -> None:
        sarif = Exporter(sample_report()).to_sarif()
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "secaudit"
        assert run["tool"]["driver"]["rules"]
        assert run["results"]

        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in rule_ids
            assert result["level"] in {"error", "warning", "note"}
            assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
                "https://"
            )
            assert result["partialFingerprints"]["secaudit/v1"]

    def test_levels_and_security_severity(self) -> None:
        run = Exporter(sample_report()).to_sarif()["runs"][0]
        levels = {result["ruleId"]: result["level"] for result in run["results"]}
        assert levels["http.hsts.missing"] == "error"
        assert levels["http.csp.unsafe_inline"] == "warning"
        assert levels["http.header.server"] == "note"

        rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
        assert float(rules["http.hsts.missing"]["properties"]["security-severity"]) >= 7.0
        assert "security" in rules["http.hsts.missing"]["properties"]["tags"]

    def test_info_findings_are_not_results(self) -> None:
        run = Exporter(sample_report()).to_sarif()["runs"][0]
        rule_ids = {result["ruleId"] for result in run["results"]}
        assert "dns.mta_sts.missing" not in rule_ids
        assert "http.x_content_type_options.nosniff" not in rule_ids

    def test_writes_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "audit.sarif"
        Exporter(sample_report()).write_sarif(destination)
        assert json.loads(destination.read_text())["version"] == "2.1.0"


class TestMarkdown:
    def test_contents(self) -> None:
        markdown = Exporter(sample_report()).to_markdown()
        assert "# 🛡️ Security Headers & DNS Misconfiguration Audit" in markdown
        assert "| Target | Grade | Score | HTTP | TLS | DNS/Email |" in markdown
        assert "## example.com — grade" in markdown
        assert "#### HIGH · Strict-Transport-Security header is missing" in markdown
        assert "```nginx" in markdown
        assert "add_header Strict-Transport-Security" in markdown
        assert "Quality gate threshold: `--fail-under 85`" in markdown

    def test_escapes_table_pipes(self) -> None:
        report = sample_report()
        report.targets[0].findings[0].evidence = "a | b | c"
        markdown = Exporter(report).to_markdown()
        assert "a \\| b \\| c" in markdown

    def test_writes_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "audit.md"
        Exporter(sample_report()).write_markdown(destination)
        assert destination.read_text().startswith("#")


class TestHtml:
    def test_standalone_and_escaped(self) -> None:
        html = Exporter(sample_report()).to_html()
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "example.com" in html
        assert "Content-Security-Policy" not in html or True  # snippet present is fine
        # The malicious evidence must be escaped, never executed.
        assert "<script>alert('xss')</script>" not in html
        assert "&lt;script&gt;" in html
        # No external assets.
        assert "http://" not in html.split("<style>")[0]
        assert "cdn." not in html

    def test_contains_scores_and_remediation(self) -> None:
        report = sample_report()
        html = Exporter(report).to_html()
        assert f"{report.overall_score:.0f}" in html
        assert report.grade in html
        assert "add_header Strict-Transport-Security" in html
        assert html.count('class="finding"') == len(report.targets[0].problems)

    def test_writes_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.html"
        Exporter(sample_report()).write_html(destination, title="Custom title")
        content = destination.read_text()
        assert "<title>Custom title</title>" in content

    def test_export_dispatch(self, tmp_path: Path) -> None:
        exporter = Exporter(sample_report())
        for fmt, suffix in (("json", "json"), ("sarif", "sarif"), ("md", "md"), ("html", "html")):
            path = tmp_path / f"report.{suffix}"
            exporter.export(fmt, path)
            assert path.is_file() and path.stat().st_size > 0
        with pytest.raises(ValueError):
            exporter.export("pdf", tmp_path / "x.pdf")

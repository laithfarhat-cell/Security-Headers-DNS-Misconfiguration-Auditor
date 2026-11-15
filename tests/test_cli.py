"""CLI parsing, target collection, quality-gate exit codes and export wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import main as cli
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


def _report_with_finding(severity: Severity = Severity.HIGH) -> AuditReport:
    section = SectionResult(
        category=Category.DNS,
        findings=[
            Finding(
                check_id="dns.spf.missing",
                title="No SPF record is published",
                category=Category.DNS,
                severity=severity,
                status=Status.FAIL,
                weight=8.0,
                description="SPF is missing",
                remediation_key="dns.spf",
            )
        ],
    )
    target = TargetReport(target="example.com", sections={Category.DNS.value: section})
    Scorer().apply(target)
    return AuditReport(targets=[target])


class TestParser:
    def test_defaults(self) -> None:
        args = cli.build_parser().parse_args(["-d", "example.com"])
        assert args.domain == ["example.com"]
        assert args.targets == []
        assert args.nameserver == []
        assert args.fail_under is None
        assert args.json is None and args.sarif is None

    def test_all_flags(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "-d",
                "a.example",
                "-d",
                "b.example",
                "-iL",
                "targets.txt",
                "--nameserver",
                "1.1.1.1",
                "--nameserver",
                "8.8.8.8",
                "-c",
                "20",
                "--fail-under",
                "90",
                "-oJ",
                "out.json",
                "-oS",
                "out.sarif",
                "-oM",
                "out.md",
                "-oH",
                "out.html",
                "-v",
            ]
        )
        assert args.domain == ["a.example", "b.example"]
        assert args.input_list == "targets.txt"
        assert args.concurrency == 20
        assert args.fail_under == 90
        assert args.sarif == "out.sarif"
        assert args.verbose is True

    def test_version(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            cli.build_parser().parse_args(["--version"])
        assert excinfo.value.code == 0

    def test_invalid_fail_under_rejected(self) -> None:
        args = cli.build_parser().parse_args(["-d", "example.com", "--fail-under", "140"])
        settings = cli._settings_from_args(args)
        with pytest.raises(SystemExit):
            cli._resolve_gate(args, settings)


class TestTargetCollection:
    def test_positional_and_domain_flags(self) -> None:
        args = cli.build_parser().parse_args(["a.example", "-d", "b.example"])
        assert cli.read_targets(args) == ["a.example", "b.example"]

    def test_input_list_comments_and_dedupe(self, tmp_path: Path) -> None:
        listing = tmp_path / "domains.txt"
        listing.write_text(
            "# production\n"
            "example.com\n"
            "\n"
            "https://www.example.com/path\n"
            "example.com  # duplicate\n"
            "api.example.com,status.example.com\n"
        )
        args = cli.build_parser().parse_args(["-iL", str(listing)])
        targets = cli.read_targets(args)
        assert targets == ["example.com", "https://www.example.com/path", "api.example.com", "status.example.com"]

    def test_missing_input_list(self) -> None:
        args = cli.build_parser().parse_args(["-iL", "/nonexistent/file.txt"])
        with pytest.raises(SystemExit):
            cli.read_targets(args)

    def test_no_targets(self) -> None:
        args = cli.build_parser().parse_args([])
        assert cli.read_targets(args) == []


class TestSettings:
    def test_cli_overrides(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("scan:\n  concurrency: 3\n  timeout: 4\nscoring:\n  fail_under: 77\n")
        args = cli.build_parser().parse_args(
            ["-d", "example.com", "--config", str(config), "-c", "9", "--nameserver", "9.9.9.9"]
        )
        settings = cli._settings_from_args(args)
        assert settings["scan"]["concurrency"] == 9
        assert settings["scan"]["timeout"] == 4
        assert settings["scoring"]["fail_under"] == 77
        fail_under, fail_on = cli._resolve_gate(args, settings)
        assert fail_under == 77
        assert fail_on is None
        auditor = cli.Auditor(settings)
        assert auditor.nameservers == ["9.9.9.9"]

    def test_missing_config(self) -> None:
        args = cli.build_parser().parse_args(["-d", "example.com", "--config", "/nope.yaml"])
        with pytest.raises(SystemExit):
            cli._settings_from_args(args)


class TestExitCodes:
    def _patch_run(self, monkeypatch: pytest.MonkeyPatch, report: AuditReport) -> None:
        async def fake_run(self, targets, progress=None, task_id=None):  # type: ignore[no-untyped-def]
            return report

        monkeypatch.setattr(cli.Auditor, "run", fake_run)

    def test_gate_failure_returns_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_run(monkeypatch, _report_with_finding())
        assert cli.main(["-d", "example.com", "--fail-under", "80", "-q"]) == 1

    def test_gate_pass_returns_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_run(monkeypatch, _report_with_finding(Severity.LOW))
        assert cli.main(["-d", "example.com", "--fail-under", "0", "-q"]) == 0

    def test_fail_on_severity(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_run(monkeypatch, _report_with_finding(Severity.HIGH))
        assert cli.main(["-d", "example.com", "--fail-on-severity", "critical", "-q"]) == 0
        assert cli.main(["-d", "example.com", "--fail-on-severity", "high", "-q"]) == 1

    def test_no_targets_returns_2(self) -> None:
        assert cli.main(["-q"]) == 2

    def test_exports_written(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self._patch_run(monkeypatch, _report_with_finding())
        code = cli.main(
            [
                "-d",
                "example.com",
                "-q",
                "-oJ",
                str(tmp_path / "r.json"),
                "-oS",
                str(tmp_path / "r.sarif"),
                "-oM",
                str(tmp_path / "r.md"),
                "-oH",
                str(tmp_path / "r.html"),
            ]
        )
        assert code == 0
        assert json.loads((tmp_path / "r.json").read_text())["summary"]["targets"] == 1
        assert json.loads((tmp_path / "r.sarif").read_text())["version"] == "2.1.0"
        assert (tmp_path / "r.md").read_text().startswith("#")
        assert "<!DOCTYPE html>" in (tmp_path / "r.html").read_text()

    def test_renders_terminal_report(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        self._patch_run(monkeypatch, _report_with_finding())
        assert cli.main(["-d", "example.com"]) == 0
        output = capsys.readouterr().out
        assert "Overall posture" in output
        assert "example.com" in output
        assert "dns.spf.missing" in output
        assert "add_header" not in output  # LOW/MEDIUM remediation is hidden without -v

    def test_quiet_mode_keeps_stdout_clean(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, tmp_path: Path
    ) -> None:
        self._patch_run(monkeypatch, _report_with_finding())
        assert cli.main(["-d", "example.com", "-q", "-oJ", str(tmp_path / "r.json")]) == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == ""
        assert "Reports written" in captured.err

    def test_verbose_shows_remediation(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        self._patch_run(monkeypatch, _report_with_finding())
        assert cli.main(["-d", "example.com", "-v"]) == 0
        output = capsys.readouterr().out
        assert "v=spf1" in output

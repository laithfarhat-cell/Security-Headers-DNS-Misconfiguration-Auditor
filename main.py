#!/usr/bin/env python3
"""secaudit — asynchronous Security Headers & DNS Misconfiguration Auditor.

Examples
--------
Audit a single domain and print the terminal report::

    secaudit -d example.com

Audit a list of domains, fail the build below 80 and write every report format::

    secaudit -iL domains.txt --fail-under 80 \
        -oJ reports/audit.json -oS reports/audit.sarif \
        -oM reports/audit.md -oH reports/audit.html

Use a specific resolver with higher concurrency::

    secaudit -d example.com --nameserver 1.1.1.1 --nameserver 8.8.8.8 -c 25
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from auditors.dns_auditor import DnsAuditor, normalise_domain
from auditors.http_auditor import HttpAuditor
from auditors.tls_auditor import TlsAuditor
from core import __version__
from core.config import get as cfg
from core.config import load_config, normalise_nameservers, with_overrides
from core.models import (
    AuditReport,
    Category,
    Finding,
    SectionResult,
    Severity,
    Status,
    TargetReport,
)
from core.scorer import Scorer, category_summary, grade_to_colour
from reporters.exporter import Exporter

log = logging.getLogger("secaudit")

SEVERITY_STYLE = {
    Severity.CRITICAL.value: "bold white on red3",
    Severity.HIGH.value: "bold white on dark_orange3",
    Severity.MEDIUM.value: "bold black on yellow3",
    Severity.LOW.value: "bold black on green_yellow",
    Severity.INFO.value: "bold white on steel_blue1",
    Severity.PASS.value: "bold white on green4",
}

DEFAULT_USER_AGENT = (
    "secaudit/1.0 (+https://github.com/laithfarhat-cell/"
    "Security-Headers-DNS-Misconfiguration-Auditor)"
)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secaudit",
        description=(
            "Asynchronous Security Headers, TLS and DNS/E-mail misconfiguration auditor "
            "with weighted scoring, remediation guidance and CI/CD quality gates."
        ),
        epilog=(
            "Exit codes: 0 = audit passed, 1 = quality gate failed, 2 = usage/runtime error. "
            "Example: secaudit -iL domains.txt --fail-under 85 -oH report.html"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_group = parser.add_argument_group("targets")
    target_group.add_argument(
        "targets", nargs="*", metavar="DOMAIN", help="domains to audit (same as -d)"
    )
    target_group.add_argument(
        "-d",
        "--domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="domain to audit; repeat for multiple targets",
    )
    target_group.add_argument(
        "-iL",
        "--input-list",
        metavar="FILE",
        help="file with one domain per line ('-' reads stdin)",
    )

    scan_group = parser.add_argument_group("scanning")
    scan_group.add_argument(
        "--nameserver",
        action="append",
        default=[],
        metavar="IP[:PORT]",
        help="custom recursive DNS resolver (repeatable, comma separated allowed)",
    )
    scan_group.add_argument(
        "-c", "--concurrency", type=int, metavar="N", help="targets audited in parallel (default 10)"
    )
    scan_group.add_argument(
        "--timeout", type=float, metavar="SECONDS", help="per-request/query timeout (default 10)"
    )
    scan_group.add_argument(
        "--user-agent", metavar="STRING", help="User-Agent used for HTTP probes"
    )
    scan_group.add_argument(
        "-v", "--verbose", action="store_true", help="show every finding, evidence and remediation"
    )
    scan_group.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="CHECK_ID",
        help="exclude a check (or prefix) from the score, e.g. --ignore dns.mta_sts",
    )

    gate_group = parser.add_argument_group("quality gate")
    gate_group.add_argument(
        "--fail-under",
        type=float,
        metavar="SCORE",
        help="exit with status 1 when the overall or any target score is below SCORE (0-100)",
    )
    gate_group.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "none"],
        metavar="SEVERITY",
        help="exit with status 1 when a finding at or above this severity exists",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument("-oJ", "--json", metavar="FILE", help="write a JSON report")
    output_group.add_argument(
        "-oS", "--sarif", metavar="FILE", help="write a SARIF 2.1.0 report (GitHub Code Scanning)"
    )
    output_group.add_argument("-oM", "--markdown", metavar="FILE", help="write a Markdown report")
    output_group.add_argument("-oH", "--html", metavar="FILE", help="write a standalone HTML report")
    output_group.add_argument(
        "--include-passed", action="store_true", help="include PASS findings in JSON output"
    )
    output_group.add_argument(
        "-q", "--quiet", action="store_true", help="suppress the terminal report (exports still run)"
    )
    output_group.add_argument("--no-color", action="store_true", help="disable ANSI colours")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--config", metavar="FILE", help="YAML configuration file")
    misc.add_argument("--version", action="version", version=f"secaudit {__version__}")
    return parser


def read_targets(args: argparse.Namespace) -> list[str]:
    """Collect targets from positionals, ``-d`` and ``-iL`` (order preserved, deduped)."""
    raw: list[str] = list(args.targets) + list(args.domain)
    failures: list[str] = []
    if args.input_list:
        try:
            if args.input_list == "-":
                content = sys.stdin.read()
            else:
                content = Path(args.input_list).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"secaudit: error: could not read {args.input_list}: {exc}") from exc
        for line in content.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                raw.append(line)

    targets: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        for candidate in str(entry).replace(",", " ").split():
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                host = normalise_domain(candidate)
            except ValueError as exc:
                failures.append(f"{candidate}: {exc}")
                continue
            if host not in seen:
                seen.add(host)
                targets.append(candidate)
    if failures:
        raise SystemExit("secaudit: error: invalid target(s): " + "; ".join(failures))
    return targets


# --------------------------------------------------------------------------------------
# Audit orchestration
# --------------------------------------------------------------------------------------
class Auditor:
    """Builds the three auditors from configuration and audits targets concurrently."""

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings
        self.concurrency = max(1, int(cfg(settings, "scan.concurrency", 10)))
        self.timeout = float(cfg(settings, "scan.timeout", 10.0))
        self.user_agent = cfg(settings, "scan.user_agent", DEFAULT_USER_AGENT)
        self.max_redirects = int(cfg(settings, "scan.max_redirects", 10))
        self.nameservers = normalise_nameservers(
            cfg(settings, "dns.nameservers", []) + list(settings.get("_cli_nameservers", []))
        )
        self.scorer = Scorer(
            category_weights=cfg(settings, "scoring.category_weights"),
            ignore_checks=list(cfg(settings, "scoring.ignore_checks", []) or [])
            + list(settings.get("_cli_ignore", [])),
        )

    def build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=bool(cfg(self.settings, "scan.verify_tls", True)),
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,
            headers={"User-Agent": self.user_agent},
            limits=httpx.Limits(
                max_connections=max(20, self.concurrency * 4),
                max_keepalive_connections=max(10, self.concurrency * 2),
            ),
        )

    async def audit_target(
        self, target: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore
    ) -> TargetReport:
        async with semaphore:
            started = time.perf_counter()
            http_auditor = HttpAuditor(
                timeout=self.timeout,
                max_redirects=self.max_redirects,
                hsts_min_max_age=int(cfg(self.settings, "http.hsts_min_max_age", 31_536_000)),
                check_security_txt=bool(cfg(self.settings, "http.check_security_txt", True)),
                check_cookies=bool(cfg(self.settings, "http.check_cookies", True)),
                user_agent=self.user_agent,
            )
            tls_auditor = TlsAuditor(
                timeout=self.timeout,
                https_port=int(cfg(self.settings, "scan.https_port", 443)),
                http_port=int(cfg(self.settings, "scan.http_port", 80)),
                user_agent=self.user_agent,
            )
            dns_auditor = DnsAuditor(
                nameservers=self.nameservers,
                timeout=min(5.0, self.timeout),
                lifetime=self.timeout,
                spf_lookup_limit=int(cfg(self.settings, "dns.spf_lookup_limit", 10)),
                fingerprints_path=cfg(self.settings, "dns.fingerprints_file"),
                probe_subdomains=cfg(self.settings, "dns.probe_subdomains", []) or [],
                user_agent=self.user_agent,
            )

            results = await asyncio.gather(
                http_auditor.audit(target, client),
                tls_auditor.audit(target, client),
                dns_auditor.audit(target, client),
                return_exceptions=True,
            )
            sections: dict[str, SectionResult] = {}
            for category, result in zip((Category.HTTP, Category.TLS, Category.DNS), results, strict=True):
                if isinstance(result, BaseException):
                    log.exception("auditor %s crashed for %s", category.value, target)
                    section = SectionResult(category=category)
                    section.error = f"{type(result).__name__}: {result}"
                else:
                    section = result
                sections[category.value] = section

            try:
                host = normalise_domain(target)
            except ValueError:  # pragma: no cover - validated earlier
                host = target
            report = TargetReport(target=host, sections=sections)
            http_data = sections[Category.HTTP.value].data
            report.metadata = {
                "requested_target": target,
                "final_url": http_data.get("final_url"),
                "status_code": http_data.get("status_code"),
                "redirect_chain": http_data.get("redirect_chain", []),
                "https": http_data.get("https"),
                "certificate_issuer": (sections[Category.TLS.value].data.get("certificate") or {}).get(
                    "issuer"
                ),
                "certificate_expires": (sections[Category.TLS.value].data.get("certificate") or {}).get(
                    "not_after"
                ),
                "protocols": sections[Category.TLS.value].data.get("protocols"),
                "nameservers": sections[Category.DNS.value].data.get("nameservers"),
                "spf": (sections[Category.DNS.value].data.get("spf") or {}).get("records"),
                "dmarc": (sections[Category.DNS.value].data.get("dmarc") or {}).get("records"),
            }
            self.scorer.apply(report)
            report.duration_ms = (time.perf_counter() - started) * 1000
            return report

    async def run(
        self, targets: Sequence[str], progress: Progress | None = None, task_id: Any = None
    ) -> AuditReport:
        semaphore = asyncio.Semaphore(self.concurrency)
        client = self.build_client()
        started = time.perf_counter()
        reports: list[TargetReport] = []
        try:
            pending = [
                asyncio.create_task(self.audit_target(target, client, semaphore))
                for target in targets
            ]
            for coroutine in asyncio.as_completed(pending):
                try:
                    report = await coroutine
                except Exception as exc:  # pragma: no cover - last-resort isolation
                    log.exception("target audit failed: %s", exc)
                    report = TargetReport(
                        target=str(exc),
                        sections={
                            category.value: SectionResult(category=category, error=str(exc))
                            for category in Category
                        },
                    )
                    self.scorer.apply(report)
                reports.append(report)
                if progress is not None and task_id is not None:
                    progress.update(
                        task_id,
                        advance=1,
                        description=(
                            f"[cyan]{report.target}[/cyan] → "
                            f"[{grade_to_colour(report.grade)}]{report.grade}[/] "
                            f"({report.overall_score:.1f})"
                        ),
                    )
        finally:
            await client.aclose()

        order = {target.lower(): index for index, target in enumerate(targets)}
        reports.sort(key=lambda r: order.get(r.target.lower(), 999))

        report = AuditReport(
            targets=reports,
            tool_version=__version__,
            generated_at=datetime.now(timezone.utc),
            duration_ms=(time.perf_counter() - started) * 1000,
            options={
                "concurrency": self.concurrency,
                "timeout": self.timeout,
                "nameservers": self.nameservers or ["system"],
                "category_weights": self.scorer.category_weights,
                "ignore_checks": list(self.scorer.ignore_checks),
            },
        )
        return report


# --------------------------------------------------------------------------------------
# Terminal rendering
# --------------------------------------------------------------------------------------
def severity_badge(severity: Severity) -> Text:
    return Text(f" {severity.value} ", style=SEVERITY_STYLE.get(severity.value, "bold"))


def grade_text(grade: str, score: float | None = None) -> Text:
    text = Text(grade, style=f"bold {grade_to_colour(grade)}")
    if score is not None:
        text.append(f"  {score:.1f}", style="dim")
    return text


def render_banner(console: Console, targets: Sequence[str]) -> None:
    subtitle = Text()
    subtitle.append("Security Headers · TLS · DNS/E-mail posture auditor\n", style="bold cyan")
    subtitle.append(
        f"{len(targets)} target(s) · OWASP Secure Headers · RFC 9116 · RFC 7208 · RFC 7489 · "
        "RFC 8659 · RFC 8461",
        style="dim",
    )
    console.print(
        Panel(
            subtitle,
            title=f"[bold]secaudit[/bold] [dim]v{__version__}[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


def render_summary(console: Console, report: AuditReport) -> None:
    counts = report.counts()
    colour = grade_to_colour(report.grade)
    grid = Table.grid(padding=(0, 3))
    for _ in range(6):
        grid.add_column(justify="center")
    grid.add_row(
        Text("SCORE", style="dim"),
        Text("GRADE", style="dim"),
        Text("CRITICAL", style="dim"),
        Text("HIGH", style="dim"),
        Text("MEDIUM", style="dim"),
        Text("LOW", style="dim"),
    )
    grid.add_row(
        Text(f"{report.overall_score:.1f}", style=f"bold {colour}"),
        Text(report.grade, style=f"bold {colour}"),
        Text(str(counts.get("CRITICAL", 0)), style="bold red" if counts.get("CRITICAL") else "dim"),
        Text(str(counts.get("HIGH", 0)), style="bold dark_orange3" if counts.get("HIGH") else "dim"),
        Text(str(counts.get("MEDIUM", 0)), style="bold yellow" if counts.get("MEDIUM") else "dim"),
        Text(str(counts.get("LOW", 0)), style="green_yellow" if counts.get("LOW") else "dim"),
    )

    gate = Text()
    if report.passed:
        gate.append("  QUALITY GATE PASSED  ", style="bold black on green")
        if report.fail_under is not None:
            gate.append(f"  threshold {report.fail_under:g}", style="dim")
    else:
        gate.append("  QUALITY GATE FAILED  ", style="bold white on red3")
        for reason in report.gate_failures():
            gate.append(f"\n  • {reason}", style="red")
    console.print(
        Panel(
            Group(grid, Text(), gate),
            title="[bold]Overall posture[/bold]",
            border_style=colour,
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


def render_target_table(console: Console, report: AuditReport) -> None:
    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="bold",
        expand=True,
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("Target", style="bold", min_width=14, max_width=44, overflow="fold")
    table.add_column("Grade", justify="center", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("HTTP", justify="right", no_wrap=True)
    table.add_column("TLS", justify="right", no_wrap=True)
    table.add_column("DNS", justify="right", no_wrap=True)
    table.add_column("Crit", justify="right", no_wrap=True)
    table.add_column("High", justify="right", no_wrap=True)
    table.add_column("Med", justify="right", no_wrap=True)
    table.add_column("Low", justify="right", no_wrap=True)

    for target in report.targets:
        counts = target.counts()
        table.add_row(
            target.target,
            grade_text(target.grade),
            f"{target.overall_score:.1f}",
            _score_cell(target.scores.get(Category.HTTP.value)),
            _score_cell(target.scores.get(Category.TLS.value)),
            _score_cell(target.scores.get(Category.DNS.value)),
            Text(str(counts.get("CRITICAL", 0)), style="red" if counts.get("CRITICAL") else "dim"),
            Text(str(counts.get("HIGH", 0)), style="dark_orange3" if counts.get("HIGH") else "dim"),
            Text(str(counts.get("MEDIUM", 0)), style="yellow" if counts.get("MEDIUM") else "dim"),
            Text(str(counts.get("LOW", 0)), style="green_yellow" if counts.get("LOW") else "dim"),
        )
    console.print()
    console.print(Rule("[bold]Targets[/bold]", style="grey37", align="left"))
    console.print(table)


def _score_cell(score: float | None) -> Text:
    if score is None:
        return Text("—", style="dim")
    if score >= 90:
        style = "green"
    elif score >= 80:
        style = "bright_green"
    elif score >= 70:
        style = "yellow"
    elif score >= 60:
        style = "dark_orange3"
    else:
        style = "red"
    return Text(f"{score:.0f}", style=style)


def render_target_detail(
    console: Console,
    target: TargetReport,
    *,
    verbose: bool = False,
    remediation_min: Severity = Severity.HIGH,
) -> None:
    console.print()
    header = Text()
    header.append(target.target, style="bold white")
    header.append("  ")
    header.append(target.grade, style=f"bold {grade_to_colour(target.grade)}")
    header.append(f"  {target.overall_score:.1f}/100", style="dim")
    header.append(f"  ·  {target.duration_ms / 1000:.1f}s", style="dim")
    meta_bits = []
    if target.metadata.get("final_url"):
        meta_bits.append(str(target.metadata["final_url"]))
    if target.metadata.get("status_code"):
        meta_bits.append(f"HTTP {target.metadata['status_code']}")
    if target.metadata.get("certificate_expires"):
        meta_bits.append(f"cert until {str(target.metadata['certificate_expires'])[:10]}")
    console.print(Rule(header, style="grey37", align="left"))
    if meta_bits:
        console.print(Text("  " + " · ".join(meta_bits), style="dim"))

    category_chips = Text("  ")
    for row in category_summary(target):
        score = row["score"]
        style = "green" if (score or 0) >= 90 else "yellow" if (score or 0) >= 70 else "red"
        category_chips.append(f"{row['category']} ", style="dim")
        category_chips.append(f"{_fmt(score)}  ", style=style)
    console.print(category_chips)

    problems = target.sorted_problems()
    if not problems:
        console.print(Text("  ✔ No problems detected", style="green"))
        return

    table = Table(
        box=box.SIMPLE,
        show_edge=False,
        pad_edge=False,
        header_style="bold dim",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("", width=10, no_wrap=True)
    table.add_column("Finding", ratio=3, overflow="fold")
    table.add_column("Observed", ratio=2, style="dim", overflow="fold")
    for finding in problems:
        label = Text(finding.title, style="white")
        label.append("\n")
        label.append(finding.check_id, style="dim cyan")
        evidence = finding.evidence or ""
        table.add_row(severity_badge(finding.severity), label, Text(evidence))
    console.print(table)

    if verbose:
        console.print(Text("  Details & remediation", style="bold"))
    for finding in problems:
        show_remediation = finding.remediation is not None and (
            verbose or finding.severity.rank >= remediation_min.rank
        )
        if not verbose and not show_remediation:
            continue
        render_finding_detail(console, finding, verbose=verbose)

    passed = [f for f in target.findings if f.status is Status.PASS]
    infos = [f for f in target.findings if f.status is Status.INFO]
    if verbose:
        for finding in infos:
            if finding.remediation and finding.severity.rank >= remediation_min.rank:
                render_finding_detail(console, finding, verbose=True)
    console.print(
        Text(
            f"  {len(passed)} check(s) passed · {len(infos)} informational · "
            f"{len(problems)} problem(s)",
            style="dim",
        )
    )


def render_finding_detail(console: Console, finding: Finding, *, verbose: bool = False) -> None:
    body: list[Any] = [Text(finding.description, style="white")]
    if finding.evidence:
        body.append(Text(f"Observed: {finding.evidence}", style="dim italic"))
    remediation = finding.remediation
    if remediation:
        body.append(Text(remediation.summary, style="cyan"))
        blocks = [
            ("Nginx", remediation.nginx, "nginx"),
            ("Apache", remediation.apache, "apache"),
            ("Cloudflare", remediation.cloudflare, "text"),
            ("DNS", remediation.dns, "dns"),
        ]
        for platform, snippet, lexer in blocks:
            if not snippet:
                continue
            body.append(Text(f"{platform}:", style="bold dim"))
            body.append(
                Syntax(
                    snippet.strip(),
                    lexer,
                    theme="monokai",
                    line_numbers=False,
                    word_wrap=True,
                    background_color="default",
                )
            )
        if remediation.reference:
            body.append(Text(f"Reference: {remediation.reference}", style="dim"))
    if verbose and finding.references:
        body.append(Text("References: " + " · ".join(finding.references), style="dim"))
    console.print(
        Panel(
            Group(*body),
            title=f"[{SEVERITY_STYLE.get(finding.severity.value, 'bold')}]"
            f"{finding.severity.value}[/] [bold]{escape(finding.check_id)}[/bold]",
            border_style="grey30",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )


def render_console(
    console: Console,
    report: AuditReport,
    *,
    verbose: bool = False,
    remediation_min: Severity = Severity.HIGH,
    export_note: str | None = None,
) -> None:
    render_summary(console, report)
    console.print()
    render_target_table(console, report)
    for target in report.targets:
        render_target_detail(
            console, target, verbose=verbose, remediation_min=remediation_min
        )
    console.print()
    if export_note:
        console.print(Text(export_note, style="dim"))
    if report.passed:
        console.print(Text("✔ Audit passed the configured quality gate.", style="bold green"))
    else:
        console.print(Text("✘ Audit failed the configured quality gate.", style="bold red"))
        for reason in report.gate_failures():
            console.print(Text(f"  • {reason}", style="red"))


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------
def _fmt(score: float | None) -> str:
    return "—" if score is None else f"{score:.0f}"


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    for noisy in ("httpx", "httpcore", "dns", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _settings_from_args(args: argparse.Namespace) -> dict[str, Any]:
    try:
        settings = load_config(args.config)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"secaudit: error: {exc}") from None
    settings = with_overrides(
        settings,
        {
            "scan.concurrency": args.concurrency,
            "scan.timeout": args.timeout,
            "scan.user_agent": args.user_agent,
        },
    )
    settings["_cli_nameservers"] = list(args.nameserver)
    settings["_cli_ignore"] = list(args.ignore)
    return settings


def _resolve_gate(args: argparse.Namespace, settings: dict[str, Any]) -> tuple[float | None, str | None]:
    fail_under = args.fail_under if args.fail_under is not None else cfg(settings, "scoring.fail_under")
    if fail_under is not None:
        try:
            fail_under = float(fail_under)
        except (TypeError, ValueError):
            raise SystemExit(
                "secaudit: error: --fail-under must be a number between 0 and 100"
            ) from None
        if not 0 <= fail_under <= 100:
            raise SystemExit("secaudit: error: --fail-under must be between 0 and 100")

    fail_on = args.fail_on_severity or cfg(settings, "scoring.fail_on_severity")
    if isinstance(fail_on, str):
        fail_on = fail_on.lower()
        if fail_on == "none":
            fail_on = None
        elif fail_on not in {"critical", "high", "medium", "low"}:
            raise SystemExit(
                "secaudit: error: --fail-on-severity must be one of critical, high, medium, low, none"
            )
    return fail_under, fail_on


async def _run_async(args: argparse.Namespace, console: Console) -> int:
    targets = read_targets(args)
    if not targets:
        raise SystemExit(
            "secaudit: error: no targets supplied (use -d example.com, -iL domains.txt or positional domains)"
        )
    settings = _settings_from_args(args)
    fail_under, fail_on = _resolve_gate(args, settings)
    remediation_min = Severity(
        str(cfg(settings, "reporting.remediation_min_severity", "HIGH")).upper()
        if str(cfg(settings, "reporting.remediation_min_severity", "HIGH")).upper() in Severity.__members__
        else "HIGH"
    )

    auditor = Auditor(settings)
    err_console = Console(stderr=True, no_color=args.no_color, highlight=False)
    if args.quiet:
        # Quiet mode keeps stdout clean for `-oJ -` style pipelines.
        report = await auditor.run(targets)
    else:
        render_banner(console, targets)
        progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}", table_column=None),
            BarColumn(bar_width=28, style="grey37", complete_style="cyan"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        with progress:
            task_id = progress.add_task(
                f"[dim]auditing {len(targets)} target(s)…[/dim]", total=len(targets)
            )
            report = await auditor.run(targets, progress=progress, task_id=task_id)
            progress.update(task_id, description="[green]scan complete[/green]")

    report.fail_under = fail_under
    report.fail_on_severity = fail_on

    export_note = None
    exporter = Exporter(report, include_passed=args.include_passed or bool(cfg(settings, "reporting.include_passed_in_json", True)))
    written: list[str] = []
    try:
        if args.json:
            exporter.write_json(args.json)
            written.append(f"JSON → {args.json}")
        if args.sarif:
            exporter.write_sarif(args.sarif)
            written.append(f"SARIF → {args.sarif}")
        if args.markdown:
            exporter.write_markdown(args.markdown)
            written.append(f"Markdown → {args.markdown}")
        if args.html:
            exporter.write_html(args.html)
            written.append(f"HTML → {args.html}")
    except OSError as exc:
        err_console.print(Text(f"Could not write report: {exc}", style="bold red"))
        return 2
    if written:
        export_note = "Reports written: " + " · ".join(written)

    if not args.quiet:
        console.print()
        render_console(
            console,
            report,
            verbose=args.verbose,
            remediation_min=remediation_min,
            export_note=export_note,
        )
    elif export_note:
        err_console.print(Text(export_note, style="dim"))

    return 0 if report.passed else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    console = Console(no_color=args.no_color, highlight=False)
    try:
        return asyncio.run(_run_async(args, console))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        if exc.code:
            console.print(Text(str(exc), style="bold red"), highlight=False)
        return int(code)
    except KeyboardInterrupt:
        console.print(Text("\nInterrupted.", style="bold yellow"))
        return 130
    except Exception as exc:  # pragma: no cover - unexpected crash
        log.exception("fatal error")
        console.print(Text(f"secaudit: fatal error: {type(exc).__name__}: {exc}", style="bold red"))
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

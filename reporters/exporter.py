"""Report exporters: JSON, SARIF 2.1.0, Markdown and standalone HTML.

All four renderers work from :class:`core.models.AuditReport`, so they always
agree on scores, severities and remediation text.

* **JSON** – machine readable, complete evidence and remediation payload.
* **SARIF** – GitHub Code Scanning / Security-tab ingestion.
* **Markdown** – PR comments, wikis, ticket attachments.
* **HTML** – self-contained dashboard (no external CSS/JS/CDN).
"""

from __future__ import annotations

import html
import json
import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import AuditReport, Category, Finding, Remediation, Severity, Status, TargetReport
from core.scorer import category_summary, severity_to_sarif_level, severity_to_score

log = logging.getLogger(__name__)

TOOL_NAME = "secaudit"
TOOL_URI = "https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor"

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.PASS,
]

#: Fence language hint per remediation platform (GitHub syntax highlighting).
_LEXERS = {"Nginx": "nginx", "Apache": "apache", "Cloudflare": "text", "DNS": "dns"}

SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
    Severity.PASS: "PASS",
}


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_time(value: datetime | None) -> str:
    if value is None:
        return "n/a"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _fmt_score(score: float | None) -> str:
    return "—" if score is None else f"{score:.1f}"


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (
            0 if f.status.is_problem else 1,
            order.get(f.severity, 99),
            f.category.value,
            f.check_id,
        ),
    )


def _problems(report: TargetReport) -> list[Finding]:
    return sort_findings(report.problems)


def _remediation_blocks(remediation: Remediation | None) -> list[tuple[str, str]]:
    """Return ``[(platform, snippet), …]`` for the non-empty snippets."""
    if remediation is None:
        return []
    blocks = [
        ("Nginx", remediation.nginx),
        ("Apache", remediation.apache),
        ("Cloudflare", remediation.cloudflare),
        ("DNS", remediation.dns),
    ]
    return [(name, snippet.strip()) for name, snippet in blocks if snippet]


def _fence(content: str, language: str = "") -> str:
    """Pick a fence long enough to survive backticks in ``content``."""
    longest = 0
    for line in content.splitlines():
        stripped = line.strip()
        if set(stripped) == {"`"}:
            longest = max(longest, len(stripped))
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content.strip()}\n{fence}"


def _md_escape(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _gate_line(report: AuditReport) -> str:
    if report.passed:
        if report.fail_under is not None or report.fail_on_severity:
            return "✅ Quality gate **passed**."
        return "✅ Audit completed."
    reasons = "; ".join(report.gate_failures())
    return f"❌ Quality gate **failed** — {reasons}."


# --------------------------------------------------------------------------------------
# Exporter
# --------------------------------------------------------------------------------------
class Exporter:
    """Render an :class:`AuditReport` in one of the supported formats."""

    def __init__(self, report: AuditReport, *, include_passed: bool = True) -> None:
        self.report = report
        self.include_passed = include_passed

    # ---------------------------------------------------------------- JSON ----
    def to_json(self, indent: int = 2) -> str:
        data = self.report.to_dict(include_remediation=True)
        if not self.include_passed:
            for result in data.get("results", []):
                result["findings"] = [
                    finding
                    for finding in result["findings"]
                    if finding["status"] in ("fail", "warn", "info")
                ]
                for section in result.get("sections", {}).values():
                    section["findings"] = [
                        finding
                        for finding in section["findings"]
                        if finding["status"] in ("fail", "warn", "info")
                    ]
        return json.dumps(data, indent=indent, default=str, ensure_ascii=False)

    def write_json(self, path: str | Path, indent: int = 2) -> None:
        _write(path, self.to_json(indent=indent) + "\n")

    # --------------------------------------------------------------- SARIF ----
    def to_sarif(self) -> dict[str, Any]:
        """Build a SARIF 2.1.0 log for GitHub Code Scanning."""
        report = self.report
        rules: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}
        results: list[dict[str, Any]] = []

        for target in report.targets:
            for finding in sort_findings(target.problems):
                # INFO findings are informational only; keep the Security tab focused.
                if finding.severity is Severity.INFO:
                    continue
                if finding.check_id not in rule_index:
                    rule_index[finding.check_id] = len(rules)
                    rules.append(self._sarif_rule(finding))
                results.append(self._sarif_result(target, finding, rule_index[finding.check_id]))

        log_entry = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "fullName": "secaudit — Security Headers & DNS Misconfiguration Auditor",
                            "semanticVersion": report.tool_version,
                            "informationUri": TOOL_URI,
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": (report.generated_at).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "endTimeUtc": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "toolExecutionNotifications": [],
                        }
                    ],
                    "results": results,
                    "properties": {
                        "overallScore": report.overall_score,
                        "grade": report.grade,
                        "failUnder": report.fail_under,
                        "failOnSeverity": report.fail_on_severity,
                        "gatePassed": report.passed,
                        "gateFailures": report.gate_failures(),
                        "targets": [t.target for t in report.targets],
                    },
                }
            ],
        }
        return log_entry

    def _sarif_rule(self, finding: Finding) -> dict[str, Any]:
        remediation = finding.remediation
        help_markdown = [f"**{finding.title}**", "", finding.description]
        if finding.evidence:
            help_markdown += ["", f"Observed: `{finding.evidence}`"]
        if remediation:
            help_markdown += ["", "### Remediation", remediation.summary]
            for platform, snippet in _remediation_blocks(remediation):
                help_markdown += ["", f"**{platform}**", _fence(snippet)]
        if finding.references:
            help_markdown += ["", "### References"] + [f"- {ref}" for ref in finding.references]
        return {
            "id": finding.check_id,
            "name": "".join(part.capitalize() for part in finding.check_id.replace(".", " ").split()),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": help_markdown and "\n".join(help_markdown), "markdown": "\n".join(help_markdown)},
            "helpUri": (finding.references[0] if finding.references else (remediation.reference if remediation else TOOL_URI)),
            "defaultConfiguration": {
                "level": severity_to_sarif_level(finding.severity),
            },
            "properties": {
                "tags": ["security", finding.category.value, finding.severity.value.lower()],
                "precision": "high",
                "security-severity": severity_to_score(finding.severity),
                "category": finding.category.label,
            },
        }

    def _sarif_result(self, target: TargetReport, finding: Finding, index: int) -> dict[str, Any]:
        url = target.metadata.get("final_url") or f"https://{target.target}/"
        message = finding.title
        if finding.evidence:
            message += f" — observed: {finding.evidence}"
        return {
            "ruleId": finding.check_id,
            "ruleIndex": index,
            "level": severity_to_sarif_level(finding.severity),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": url},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
            "partialFingerprints": {f"{TOOL_NAME}/v1": finding.fingerprint},
            "properties": {
                "target": target.target,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "category": finding.category.value,
                "score": target.overall_score,
                "grade": target.grade,
            },
        }

    def write_sarif(self, path: str | Path) -> None:
        _write(path, json.dumps(self.to_sarif(), indent=2, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------ Markdown ----
    def to_markdown(self) -> str:
        report = self.report
        lines: list[str] = []
        counts = report.counts()

        lines += [
            "# 🛡️ Security Headers & DNS Misconfiguration Audit",
            "",
            f"**Generated:** {_fmt_time(report.generated_at)}  ",
            f"**Tool:** `{TOOL_NAME}` v{report.tool_version}  ",
            f"**Targets:** {len(report.targets)}  ",
            f"**Overall score:** **{report.overall_score:.1f}/100** (grade **{report.grade}**)",
            "",
            _gate_line(report),
            "",
        ]
        if report.fail_under is not None:
            lines.append(f"> Quality gate threshold: `--fail-under {report.fail_under:g}`")
            lines.append("")

        lines += [
            f"**Findings:** {counts.get('CRITICAL', 0)} critical · {counts.get('HIGH', 0)} high · "
            f"{counts.get('MEDIUM', 0)} medium · {counts.get('LOW', 0)} low · "
            f"{counts.get('PASS', 0)} passed",
            "",
            "## Summary",
            "",
            "| Target | Grade | Score | HTTP | TLS | DNS/Email | Critical | High | Medium | Low |",
            "|:--|:--:|--:|--:|--:|--:|--:|--:|--:|--:|",
        ]
        for target in report.targets:
            counts_t = target.counts()
            lines.append(
                "| {target} | **{grade}** | {score} | {http} | {tls} | {dns} | {c} | {h} | {m} | {l} |".format(
                    target=target.target,
                    grade=target.grade,
                    score=_fmt_score(target.overall_score),
                    http=_fmt_score(target.scores.get(Category.HTTP.value)),
                    tls=_fmt_score(target.scores.get(Category.TLS.value)),
                    dns=_fmt_score(target.scores.get(Category.DNS.value)),
                    c=counts_t.get("CRITICAL", 0),
                    h=counts_t.get("HIGH", 0),
                    m=counts_t.get("MEDIUM", 0),
                    l=counts_t.get("LOW", 0),
                )
            )
        lines.append("")

        for target in report.targets:
            lines.extend(self._markdown_target(target))
        lines += [
            "---",
            "",
            f"<sub>Generated by [{TOOL_NAME}]({TOOL_URI}) — "
            "an OWASP Secure Headers, TLS and DNS/e-mail auditing tool.</sub>",
            "",
        ]
        return "\n".join(lines)

    def _markdown_target(self, target: TargetReport) -> list[str]:
        lines = [
            f"## {target.target} — grade {target.grade} ({target.overall_score:.1f}/100)",
            "",
        ]
        meta = target.metadata
        rows: list[tuple[str, str]] = []
        if meta.get("final_url"):
            rows.append(("Final URL", f"`{meta['final_url']}`"))
        if meta.get("status_code"):
            rows.append(("HTTP status", str(meta["status_code"])))
        chain = meta.get("redirect_chain") or []
        if len(chain) > 1:
            rows.append(("Redirects", f"{len(chain) - 1} hop(s): " + " → ".join(h["url"] for h in chain)))
        cert = (target.sections.get(Category.TLS.value).data if target.sections.get(Category.TLS.value) else {}).get("certificate") or {}
        if cert:
            rows.append(("Certificate", f"{cert.get('issuer', 'n/a')}"))
            rows.append(("Valid until", f"{cert.get('not_after', 'n/a')} ({cert.get('days_remaining', 'n/a')} days)"))
            rows.append(("SANs", ", ".join(cert.get("san", [])[:6]) or "n/a"))
        dns = target.sections.get(Category.DNS.value).data if target.sections.get(Category.DNS.value) else {}
        if dns.get("spf", {}).get("records"):
            rows.append(("SPF", f"`{_md_escape(dns['spf']['records'][0])}`"))
        if dns.get("dmarc", {}).get("records"):
            rows.append(("DMARC", f"`{_md_escape(dns['dmarc']['records'][0])}`"))
        rows.append(
            (
                "Category scores",
                " · ".join(
                    f"{row['category']}: {_fmt_score(row['score'])}"
                    for row in category_summary(target)
                ),
            )
        )
        if rows:
            lines += ["| Attribute | Value |", "|:--|:--|"]
            lines += [f"| {key} | {_md_escape(value)} |" for key, value in rows]
            lines.append("")

        problems = _problems(target)
        if not problems:
            lines += ["✅ No problems were found for this target.", ""]
        else:
            lines += [f"### Findings ({len(problems)})", ""]
            for finding in problems:
                lines.extend(self._markdown_finding(finding))

        passed = [
            f
            for f in sort_findings(target.findings)
            if f.status is Status.PASS or f.status is Status.INFO
        ]
        if passed:
            lines += [
                "<details><summary>✅ Checks that passed / informational "
                f"({len(passed)})</summary>",
                "",
            ]
            lines += [
                f"- `{f.check_id}` — {f.title}" + (f" (`{_md_escape(f.evidence)}`)" if f.evidence else "")
                for f in passed
            ]
            lines += ["", "</details>", ""]
        return lines

    def _markdown_finding(self, finding: Finding) -> list[str]:
        header = f"#### {SEVERITY_LABEL[finding.severity]} · {finding.title}"
        lines = [
            header,
            "",
            f"`{finding.check_id}` · {finding.category.label} · status `{finding.status.value}`",
            "",
            finding.description,
            "",
        ]
        if finding.evidence:
            lines += [f"**Observed:** `{_md_escape(finding.evidence)}`", ""]
        remediation = finding.remediation
        if remediation:
            lines += [
                "<details><summary>🔧 Remediation</summary>",
                "",
                remediation.summary,
                "",
            ]
            for platform, snippet in _remediation_blocks(remediation):
                lines += [f"**{platform}**", "", _fence(snippet, _LEXERS.get(platform, "")), ""]
            if remediation.reference:
                lines += [f"Reference: <{remediation.reference}>", ""]
            lines += ["</details>", ""]
        if finding.references:
            lines += ["References: " + " · ".join(f"<{ref}>" for ref in finding.references), ""]
        lines += ["---", ""]
        return lines

    def write_markdown(self, path: str | Path) -> None:
        _write(path, self.to_markdown())

    # ---------------------------------------------------------------- HTML ----
    def to_html(self, title: str | None = None) -> str:
        report = self.report
        counts = report.counts()
        doc_title = title or f"Security Audit — {', '.join(t.target for t in report.targets[:3])}"
        grade = report.grade
        gate_class = "pass" if report.passed else "fail"
        gate_text = (
            "Quality gate passed" if report.passed else "Quality gate failed"
        )
        ring = _score_ring(report.overall_score, grade)

        summary_rows = []
        for target in report.targets:
            tc = target.counts()
            summary_rows.append(
                f"""<tr>
      <td class="mono">{html.escape(target.target)}</td>
      <td><span class="grade-pill grade-{_grade_class(target.grade)}">{html.escape(target.grade)}</span></td>
      <td class="num">{target.overall_score:.1f}</td>
      <td class="num">{_fmt_score(target.scores.get(Category.HTTP.value))}</td>
      <td class="num">{_fmt_score(target.scores.get(Category.TLS.value))}</td>
      <td class="num">{_fmt_score(target.scores.get(Category.DNS.value))}</td>
      <td class="num sev-critical">{tc.get('CRITICAL', 0)}</td>
      <td class="num sev-high">{tc.get('HIGH', 0)}</td>
      <td class="num sev-medium">{tc.get('MEDIUM', 0)}</td>
      <td class="num sev-low">{tc.get('LOW', 0)}</td>
    </tr>"""
            )

        target_sections = "\n".join(self._html_target(target) for target in report.targets)
        filter_buttons = "".join(
            f'<button class="filter-btn" data-severity="{sev.value}">{sev.value}</button>'
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(doc_title)}</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #0b0f16;
  --bg-soft: #111827;
  --card: #131a26;
  --card-2: #182233;
  --border: #243044;
  --text: #e6edf7;
  --muted: #93a2b8;
  --accent: #38bdf8;
  --pass: #22c55e;
  --info: #60a5fa;
  --low: #a3e635;
  --medium: #f59e0b;
  --high: #f97316;
  --critical: #ef4444;
  --radius: 14px;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background:
    radial-gradient(1200px 600px at 10% -10%, rgba(56,189,248,.12), transparent 60%),
    radial-gradient(900px 500px at 100% 0%, rgba(168,85,247,.12), transparent 55%),
    var(--bg);
  color: var(--text);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code, pre, .mono {{ font-family: var(--mono); }}
code {{ background: rgba(148,163,184,.12); padding: .12em .35em; border-radius: 5px; font-size: .88em; }}
pre {{ background: #0a0f18; border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; overflow-x: auto; font-size: 12.5px; line-height: 1.55; }}
pre code {{ background: none; padding: 0; }}
.wrap {{ max-width: 1180px; margin: 0 auto; padding: 32px 22px 64px; }}
header.hero {{ border-bottom: 1px solid var(--border); background: linear-gradient(180deg, rgba(17,24,39,.75), transparent); }}
.hero-inner {{ max-width: 1180px; margin: 0 auto; padding: 34px 22px 30px; display: flex; gap: 30px; align-items: center; flex-wrap: wrap; }}
.brand {{ font: 600 15px/1 var(--mono); letter-spacing: .16em; text-transform: uppercase; color: var(--accent); }}
.brand span {{ color: var(--muted); font-weight: 400; letter-spacing: .05em; margin-left: 8px; }}
h1 {{ font-size: 30px; line-height: 1.2; margin: 10px 0 6px; letter-spacing: -.02em; }}
.subtitle {{ color: var(--muted); margin: 0; font-size: 14px; }}
.hero-copy {{ flex: 1 1 420px; }}
.hero-score {{ display: flex; align-items: center; gap: 22px; background: rgba(19,26,38,.8); border: 1px solid var(--border); border-radius: 18px; padding: 18px 24px; }}
.ring-wrap {{ position: relative; width: 124px; height: 124px; }}
.ring-wrap svg {{ transform: rotate(-90deg); }}
.ring-bg {{ stroke: #1f2937; }}
.ring-fg {{ stroke-linecap: round; transition: stroke-dashoffset .6s ease; }}
.ring-label {{ position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }}
.ring-score {{ font: 700 30px/1 var(--mono); }}
.ring-max {{ color: var(--muted); font-size: 11px; margin-top: 4px; letter-spacing: .08em; }}
.grade-block {{ text-align: center; }}
.grade-big {{ font: 800 54px/1 var(--mono); letter-spacing: -.03em; }}
.grade-caption {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .16em; margin-top: 6px; }}
.gate {{ display: inline-flex; align-items: center; gap: 8px; margin-top: 14px; padding: 7px 14px; border-radius: 999px; font-size: 13px; font-weight: 600; }}
.gate.pass {{ background: rgba(34,197,94,.12); color: #86efac; border: 1px solid rgba(34,197,94,.35); }}
.gate.fail {{ background: rgba(239,68,68,.12); color: #fca5a5; border: 1px solid rgba(239,68,68,.35); }}
.stats {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }}
.stat {{ background: rgba(19,26,38,.7); border: 1px solid var(--border); border-radius: 10px; padding: 8px 12px; font-size: 12.5px; color: var(--muted); }}
.stat b {{ display: block; font: 700 18px/1.2 var(--mono); color: var(--text); }}
.stat.sev-critical b {{ color: var(--critical); }}
.stat.sev-high b {{ color: var(--high); }}
.stat.sev-medium b {{ color: var(--medium); }}
.stat.sev-low b {{ color: var(--low); }}
.stat.sev-pass b {{ color: var(--pass); }}
h2 {{ font-size: 20px; margin: 40px 0 14px; letter-spacing: -.01em; }}
h3 {{ font-size: 16px; margin: 26px 0 10px; }}
section.summary table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }}
section.summary th, section.summary td {{ padding: 11px 14px; text-align: left; border-bottom: 1px solid rgba(36,48,68,.7); font-size: 13.5px; }}
section.summary th {{ background: rgba(24,34,51,.9); color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase; letter-spacing: .09em; }}
section.summary tr:last-child td {{ border-bottom: none; }}
.num {{ text-align: right; font-family: var(--mono); font-variant-numeric: tabular-nums; }}
.grade-pill {{ display: inline-block; min-width: 36px; text-align: center; padding: 2px 8px; border-radius: 7px; font: 700 13px/1.5 var(--mono); }}
.grade-a {{ background: rgba(34,197,94,.16); color: #86efac; }}
.grade-b {{ background: rgba(163,230,53,.16); color: #d9f99d; }}
.grade-c {{ background: rgba(245,158,11,.16); color: #fcd34d; }}
.grade-d {{ background: rgba(249,115,22,.16); color: #fdba74; }}
.grade-f {{ background: rgba(239,68,68,.16); color: #fca5a5; }}
.target {{ margin-top: 30px; border: 1px solid var(--border); border-radius: var(--radius); background: linear-gradient(180deg, rgba(19,26,38,.95), rgba(15,21,32,.95)); overflow: hidden; }}
.target-head {{ padding: 20px 22px 16px; border-bottom: 1px solid var(--border); background: rgba(24,34,51,.45); }}
.target-title {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 0; font-size: 19px; }}
.target-title .mono {{ font-size: 19px; letter-spacing: -.01em; }}
.target-meta {{ color: var(--muted); font-size: 13px; margin-top: 8px; display: flex; gap: 16px; flex-wrap: wrap; }}
.chips {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
.chip {{ font-size: 12px; padding: 4px 10px; border-radius: 999px; background: rgba(148,163,184,.1); border: 1px solid var(--border); color: var(--muted); }}
.chip b {{ color: var(--text); font-family: var(--mono); }}
.target-body {{ padding: 18px 22px 22px; }}
.filters {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 0 0 14px; }}
.filter-btn {{ background: rgba(148,163,184,.08); color: var(--muted); border: 1px solid var(--border); border-radius: 999px; padding: 5px 12px; font-size: 12px; cursor: pointer; }}
.filter-btn:hover, .filter-btn.active {{ color: var(--text); border-color: var(--accent); }}
.filter-btn[data-severity="CRITICAL"] {{ color: #fca5a5; }}
.filter-btn[data-severity="HIGH"] {{ color: #fdba74; }}
.filter-btn[data-severity="MEDIUM"] {{ color: #fcd34d; }}
details.finding {{ border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 10px; margin-bottom: 10px; background: var(--card-2); overflow: hidden; }}
details.finding[data-severity="CRITICAL"] {{ border-left-color: var(--critical); }}
details.finding[data-severity="HIGH"] {{ border-left-color: var(--high); }}
details.finding[data-severity="MEDIUM"] {{ border-left-color: var(--medium); }}
details.finding[data-severity="LOW"] {{ border-left-color: var(--low); }}
details.finding[data-severity="INFO"] {{ border-left-color: var(--info); }}
details.finding[data-severity="PASS"] {{ border-left-color: var(--pass); }}
details.finding summary {{ list-style: none; cursor: pointer; padding: 12px 14px; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }}
details.finding summary::-webkit-details-marker {{ display: none; }}
details.finding summary::after {{ content: "▸"; margin-left: auto; color: var(--muted); }}
details.finding[open] summary::after {{ content: "▾"; }}
.badge {{ font: 700 10.5px/1 var(--mono); letter-spacing: .1em; padding: 5px 7px; border-radius: 5px; text-transform: uppercase; }}
.badge.CRITICAL {{ background: rgba(239,68,68,.18); color: #fca5a5; }}
.badge.HIGH {{ background: rgba(249,115,22,.18); color: #fdba74; }}
.badge.MEDIUM {{ background: rgba(245,158,11,.18); color: #fcd34d; }}
.badge.LOW {{ background: rgba(163,230,53,.14); color: #d9f99d; }}
.badge.INFO {{ background: rgba(96,165,250,.16); color: #bfdbfe; }}
.badge.PASS {{ background: rgba(34,197,94,.16); color: #86efac; }}
.finding-title {{ font-weight: 600; }}
.check-id {{ color: var(--muted); font: 11.5px/1.4 var(--mono); }}
.finding-body {{ padding: 2px 16px 18px 16px; border-top: 1px solid rgba(36,48,68,.7); }}
.finding-body p {{ margin: 12px 0; }}
.evidence {{ background: rgba(148,163,184,.08); border: 1px dashed var(--border); border-radius: 8px; padding: 10px 12px; font-family: var(--mono); font-size: 12.5px; color: #cbd5e1; overflow-x: auto; }}
.rem-block {{ margin-top: 16px; background: rgba(56,189,248,.05); border: 1px solid rgba(56,189,248,.18); border-radius: 10px; padding: 14px 16px; }}
.rem-block h4 {{ margin: 0 0 8px; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); }}
.platform {{ font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin: 14px 0 6px; }}
.refs {{ margin-top: 12px; font-size: 12.5px; color: var(--muted); }}
.no-findings {{ color: #86efac; background: rgba(34,197,94,.08); border: 1px solid rgba(34,197,94,.25); border-radius: 10px; padding: 14px 16px; }}
details.passed {{ margin-top: 16px; }}
details.passed summary {{ cursor: pointer; color: var(--muted); font-size: 13px; }}
details.passed ul {{ margin: 10px 0 0; padding-left: 20px; color: var(--muted); font-size: 13px; }}
details.passed li {{ margin-bottom: 4px; }}
footer {{ margin-top: 46px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12.5px; }}
@media (max-width: 720px) {{
  .hero-score {{ width: 100%; }}
  h1 {{ font-size: 24px; }}
}}
</style>
</head>
<body>
<header class="hero">
  <div class="hero-inner">
    <div class="hero-copy">
      <div class="brand">{TOOL_NAME}<span>v{html.escape(report.tool_version)}</span></div>
      <h1>Security Headers &amp; DNS Posture Report</h1>
      <p class="subtitle">Generated {_fmt_time(report.generated_at)} · {len(report.targets)} target(s) · {report.duration_ms / 1000:.1f}s runtime</p>
      <div class="gate {gate_class}">{gate_text}</div>
      <div class="stats">
        <div class="stat sev-critical"><b>{counts.get('CRITICAL', 0)}</b>critical</div>
        <div class="stat sev-high"><b>{counts.get('HIGH', 0)}</b>high</div>
        <div class="stat sev-medium"><b>{counts.get('MEDIUM', 0)}</b>medium</div>
        <div class="stat sev-low"><b>{counts.get('LOW', 0)}</b>low</div>
        <div class="stat sev-pass"><b>{counts.get('PASS', 0)}</b>passed</div>
      </div>
    </div>
    <div class="hero-score">
      <div class="ring-wrap">
        {ring}
        <div class="ring-label">
          <div class="ring-score">{report.overall_score:.0f}</div>
          <div class="ring-max">/ 100</div>
        </div>
      </div>
      <div class="grade-block">
        <div class="grade-big grade-{_grade_class(grade)}">{html.escape(grade)}</div>
        <div class="grade-caption">Overall grade</div>
      </div>
    </div>
  </div>
</header>
<main class="wrap">
  <section class="summary">
    <h2>Targets</h2>
    <table>
      <thead>
        <tr><th>Target</th><th>Grade</th><th>Score</th><th>HTTP</th><th>TLS</th><th>DNS</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th></tr>
      </thead>
      <tbody>
        {''.join(summary_rows)}
      </tbody>
    </table>
  </section>
  <div class="filters">
    <span class="check-id">Show:</span>
    <button class="filter-btn active" data-severity="ALL">All</button>
    {filter_buttons}
  </div>
  {target_sections}
  <footer>
    Generated by <a href="{TOOL_URI}">{TOOL_NAME}</a> v{html.escape(report.tool_version)} · findings are based on OWASP Secure Headers, RFC 9116, RFC 7208, RFC 7489, RFC 8659 and RFC 8461 guidance.
    Category weights: HTTP {report.options.get('category_weights', {}).get('http_headers', 45)}% · TLS {report.options.get('category_weights', {}).get('tls', 25)}% · DNS {report.options.get('category_weights', {}).get('dns_email', 30)}%.
  </footer>
</main>
<script>
document.querySelectorAll('.filter-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    const severity = btn.dataset.severity;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b === btn));
    document.querySelectorAll('details.finding').forEach(card => {{
      card.style.display = (severity === 'ALL' || card.dataset.severity === severity) ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>"""

    def _html_target(self, target: TargetReport) -> str:
        problems = _problems(target)
        chips = "".join(
            f'<span class="chip">{html.escape(row["category"])} <b>{_fmt_score(row["score"])}</b></span>'
            for row in category_summary(target)
        )
        meta_bits: list[str] = []
        meta = target.metadata
        if meta.get("final_url"):
            meta_bits.append(f'<span>{html.escape(str(meta["final_url"]))}</span>')
        if meta.get("status_code"):
            meta_bits.append(f"<span>HTTP {meta['status_code']}</span>")
        chain = meta.get("redirect_chain") or []
        if len(chain) > 1:
            meta_bits.append(f"<span>{len(chain) - 1} redirect(s)</span>")
        tls_section = target.sections.get(Category.TLS.value)
        cert = (tls_section.data.get("certificate") if tls_section else None) or {}
        if cert:
            meta_bits.append(f"<span>cert expires {html.escape(str(cert.get('not_after', 'n/a'))[:10])}</span>")
        dns_section = target.sections.get(Category.DNS.value)
        dns_data = dns_section.data if dns_section else {}
        spf = (dns_data.get("spf") or {}).get("records") or []
        dmarc = (dns_data.get("dmarc") or {}).get("records") or []
        if spf:
            meta_bits.append(f"<span>SPF {html.escape(spf[0][:70])}</span>")
        if dmarc:
            meta_bits.append(f"<span>DMARC {html.escape(dmarc[0][:70])}</span>")

        cards = "\n".join(self._html_finding(finding) for finding in problems) or (
            '<div class="no-findings">✅ No problems detected for this target.</div>'
        )

        passed = [f for f in sort_findings(target.findings) if f.status in (Status.PASS, Status.INFO)]
        passed_html = ""
        if passed:
            items = "".join(
                f'<li><code>{html.escape(f.check_id)}</code> — {html.escape(f.title)}</li>'
                for f in passed
            )
            passed_html = (
                f'<details class="passed"><summary>✅ {len(passed)} passed / informational checks</summary>'
                f"<ul>{items}</ul></details>"
            )

        return f"""<article class="target">
  <div class="target-head">
    <h2 class="target-title"><span class="mono">{html.escape(target.target)}</span>
      <span class="grade-pill grade-{_grade_class(target.grade)}">{html.escape(target.grade)}</span>
      <span class="check-id">{target.overall_score:.1f}/100</span>
    </h2>
    <div class="target-meta">{''.join(meta_bits)}</div>
    <div class="chips">{chips}</div>
  </div>
  <div class="target-body">
    {cards}
    {passed_html}
  </div>
</article>"""

    def _html_finding(self, finding: Finding) -> str:
        severity = finding.severity.value
        evidence = (
            f'<div class="evidence">{html.escape(finding.evidence)}</div>'
            if finding.evidence
            else ""
        )
        remediation_html = ""
        remediation = finding.remediation
        if remediation:
            blocks = "".join(
                f'<div class="platform">{html.escape(platform)}</div><pre><code>{html.escape(snippet)}</code></pre>'
                for platform, snippet in _remediation_blocks(remediation)
            )
            reference = (
                f'<p class="refs">Reference: <a href="{html.escape(remediation.reference)}">'
                f"{html.escape(remediation.reference)}</a></p>"
                if remediation.reference
                else ""
            )
            remediation_html = f"""<div class="rem-block">
  <h4>Remediation</h4>
  <p>{html.escape(remediation.summary)}</p>
  {blocks}
  {reference}
</div>"""
        refs = ""
        if finding.references:
            refs = '<p class="refs">References: ' + " · ".join(
                f'<a href="{html.escape(ref)}">{html.escape(ref)}</a>' for ref in finding.references
            ) + "</p>"

        return f"""<details class="finding" data-severity="{severity}">
  <summary>
    <span class="badge {severity}">{severity}</span>
    <span class="finding-title">{html.escape(finding.title)}</span>
    <span class="check-id">{html.escape(finding.check_id)}</span>
  </summary>
  <div class="finding-body">
    <p>{html.escape(finding.description)}</p>
    {evidence}
    {remediation_html}
    {refs}
  </div>
</details>"""

    def write_html(self, path: str | Path, title: str | None = None) -> None:
        _write(path, self.to_html(title=title))

    # ------------------------------------------------------------- dispatch ----
    def export(self, fmt: str, path: str | Path) -> None:
        fmt = fmt.lower().lstrip(".")
        if fmt in ("json", "j"):
            self.write_json(path)
        elif fmt in ("sarif", "s"):
            self.write_sarif(path)
        elif fmt in ("md", "markdown", "m"):
            self.write_markdown(path)
        elif fmt in ("html", "htm", "h"):
            self.write_html(path)
        else:
            raise ValueError(f"unsupported export format: {fmt}")


def _grade_class(grade: str) -> str:
    return grade[0].lower() if grade else "f"


def _score_ring(score: float, grade: str) -> str:
    radius = 52
    circumference = 2 * 3.141592653589793 * radius
    offset = circumference * (1 - max(0.0, min(100.0, score)) / 100.0)
    colour = {
        "A": "#22c55e",
        "B": "#a3e635",
        "C": "#f59e0b",
        "D": "#f97316",
        "F": "#ef4444",
    }.get(grade[:1].upper(), "#ef4444")
    return f"""<svg width="124" height="124" viewBox="0 0 124 124" aria-hidden="true">
  <circle class="ring-bg" cx="62" cy="62" r="{radius}" fill="none" stroke-width="10"></circle>
  <circle class="ring-fg" cx="62" cy="62" r="{radius}" fill="none" stroke-width="10"
          stroke="{colour}" stroke-dasharray="{circumference:.2f}"
          stroke-dashoffset="{offset:.2f}"></circle>
</svg>"""


def _write(path: str | Path, content: str) -> None:
    """Write to a file, or to stdout when ``path`` is ``-``."""
    if str(path) == "-":
        print(content, end="")
        return
    destination = Path(path).expanduser()
    if destination.parent and str(destination.parent) not in ("", "."):
        destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    log.info("wrote %s", destination)


# --------------------------------------------------------------------------------------
# Convenience functions
# --------------------------------------------------------------------------------------
def export_json(report: AuditReport, path: str | Path, indent: int = 2) -> None:
    Exporter(report).write_json(path, indent=indent)


def export_sarif(report: AuditReport, path: str | Path) -> None:
    Exporter(report).write_sarif(path)


def export_markdown(report: AuditReport, path: str | Path) -> None:
    Exporter(report).write_markdown(path)


def export_html(report: AuditReport, path: str | Path, title: str | None = None) -> None:
    Exporter(report).write_html(path, title=title)

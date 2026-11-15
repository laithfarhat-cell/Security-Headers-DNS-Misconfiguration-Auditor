"""Domain model for the auditor.

Everything that flows between the auditors, the scoring engine, the reporters and
the CLI is defined here.  The models are deliberately dependency-free (stdlib
only) so they can be imported from tests and from third-party integrations
without pulling in ``httpx``/``dnspython``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------
class Severity(str, Enum):
    """Severity of a finding, ordered from informational to critical."""

    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank used for comparisons / sorting (``PASS`` == 0)."""
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.PASS: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

#: Severities that represent an actual problem (everything but PASS/INFO).
PROBLEM_SEVERITIES = frozenset(
    {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
)


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "pass"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"

    @property
    def is_problem(self) -> bool:
        return self in (Status.WARN, Status.FAIL)

    @property
    def score_factor(self) -> float:
        """Fraction of the check weight that is credited to the final score."""
        return {
            Status.PASS: 1.0,
            Status.INFO: 1.0,   # purely informational checks neither help nor hurt
            Status.WARN: 0.4,
            Status.FAIL: 0.0,
        }[self]


class Category(str, Enum):
    """Audit category (also the top level grouping in every report)."""

    HTTP = "http_headers"
    TLS = "tls"
    DNS = "dns_email"

    @property
    def label(self) -> str:
        return {
            Category.HTTP: "HTTP Headers",
            Category.TLS: "TLS",
            Category.DNS: "DNS / Email",
        }[self]

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


# --------------------------------------------------------------------------------------
# Remediation
# --------------------------------------------------------------------------------------
@dataclass
class Remediation:
    """Copy-pasteable remediation guidance for one security control.

    Every field except :attr:`summary` is optional; exporters render whichever
    snippets are available.  Snippets may contain ``{placeholders}`` that are
    filled from :attr:`Finding.context` (unknown placeholders are left intact so
    that server-side templating syntax such as ``${HTTP_HOST}`` survives).
    """

    summary: str
    nginx: str | None = None
    apache: str | None = None
    cloudflare: str | None = None
    dns: str | None = None
    reference: str | None = None

    def render(self, context: dict[str, Any] | None = None) -> Remediation:
        """Return a copy with ``{placeholders}`` interpolated."""
        mapping = _SafeDict(context or {})
        return Remediation(
            summary=self.summary.format_map(mapping),
            nginx=self.nginx.format_map(mapping) if self.nginx else None,
            apache=self.apache.format_map(mapping) if self.apache else None,
            cloudflare=self.cloudflare.format_map(mapping) if self.cloudflare else None,
            dns=self.dns.format_map(mapping) if self.dns else None,
            reference=self.reference,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "nginx": self.nginx,
            "apache": self.apache,
            "cloudflare": self.cloudflare,
            "dns": self.dns,
            "reference": self.reference,
        }


class _SafeDict(dict):
    """``dict`` that leaves unknown ``{placeholders}`` untouched."""

    def __missing__(self, key: str) -> str:  # pragma: no cover - trivial
        return "{" + key + "}"


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------
@dataclass
class Finding:
    """A single check result.

    ``weight`` is the number of points the check is worth inside its category.
    The category score is ``100 * sum(weight * status.score_factor) / sum(weight)``,
    which keeps every category in a predictable ``0-100`` range regardless of how
    many checks it contains.
    """

    check_id: str
    title: str
    category: Category
    severity: Severity
    status: Status
    weight: float
    description: str
    evidence: str | None = None
    remediation_key: str | None = None
    remediation: Remediation | None = None
    context: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    target: str | None = None

    def __post_init__(self) -> None:
        if self.severity is Severity.PASS and self.status is not Status.PASS:
            self.status = Status.PASS

    @property
    def score_factor(self) -> float:
        return self.status.score_factor

    @property
    def fingerprint(self) -> str:
        """Stable identifier used for SARIF ``partialFingerprints``."""
        raw = f"{self.target}|{self.check_id}|{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self, include_remediation: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "weight": round(self.weight, 2),
            "description": self.description,
            "evidence": self.evidence,
            "target": self.target,
            "references": self.references,
            "fingerprint": self.fingerprint,
        }
        if include_remediation and self.remediation:
            data["remediation"] = self.remediation.to_dict()
        return data


# --------------------------------------------------------------------------------------
# Section / target results
# --------------------------------------------------------------------------------------
@dataclass
class SectionResult:
    """Result of one auditor (HTTP, TLS or DNS) for one target."""

    category: Category
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0

    def add(self, finding: Finding) -> Finding:
        finding.category = self.category
        self.findings.append(finding)
        return finding

    def extend(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.FAIL]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.WARN]

    def to_dict(self, include_remediation: bool = True) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 1),
            "findings": [f.to_dict(include_remediation) for f in self.findings],
            "data": self.data,
        }


@dataclass
class TargetReport:
    """Aggregated report for a single audited domain."""

    target: str
    sections: dict[str, SectionResult] = field(default_factory=dict)
    scores: dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    grade: str = "F"
    metadata: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0

    # -- accessors ---------------------------------------------------------------
    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for section in self.sections.values():
            out.extend(section.findings)
        return out

    @property
    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.status.is_problem]

    def counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            if finding.status.is_problem:
                counts[finding.severity.value] += 1
            elif finding.status is Status.INFO:
                counts[Severity.INFO.value] += 1
            else:
                counts[Severity.PASS.value] += 1
        return counts

    def highest_severity(self) -> Severity:
        worst = Severity.PASS
        for finding in self.problems:
            if finding.severity.rank > worst.rank:
                worst = finding.severity
        return worst

    @property
    def failed(self) -> bool:
        return any(f.status is Status.FAIL for f in self.findings)

    def sorted_problems(self) -> list[Finding]:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(
            self.problems,
            key=lambda f: (order.get(f.severity, 9), f.category.value, f.check_id),
        )

    # -- serialisation -----------------------------------------------------------
    def to_dict(self, include_remediation: bool = True) -> dict[str, Any]:
        return {
            "target": self.target,
            "score": round(self.overall_score, 2),
            "grade": self.grade,
            "category_scores": {k: round(v, 2) for k, v in self.scores.items()},
            "counts": self.counts(),
            "highest_severity": self.highest_severity().value,
            "failed": self.failed,
            "duration_ms": round(self.duration_ms, 1),
            "started_at": self.started_at.isoformat(),
            "metadata": self.metadata,
            "sections": {
                key: section.to_dict(include_remediation)
                for key, section in self.sections.items()
            },
            "findings": [f.to_dict(include_remediation) for f in self.findings],
        }


@dataclass
class AuditReport:
    """Top level report: metadata about the scan plus one entry per target."""

    targets: list[TargetReport] = field(default_factory=list)
    tool_version: str = "1.0.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    options: dict[str, Any] = field(default_factory=dict)
    fail_under: float | None = None
    fail_on_severity: str | None = None

    # -- aggregation -------------------------------------------------------------
    @property
    def overall_score(self) -> float:
        scored = [t.overall_score for t in self.targets if t.sections]
        if not scored:
            return 0.0
        return round(sum(scored) / len(scored), 2)

    @property
    def grade(self) -> str:
        from core.scorer import score_to_grade  # local import avoids a cycle

        return score_to_grade(self.overall_score)

    def counts(self) -> dict[str, int]:
        totals = {sev.value: 0 for sev in Severity}
        for target in self.targets:
            for key, value in target.counts().items():
                totals[key] = totals.get(key, 0) + value
        return totals

    def all_problems(self) -> list[Finding]:
        out: list[Finding] = []
        for target in self.targets:
            out.extend(target.problems)
        return out

    def worst_severity(self) -> Severity:
        worst = Severity.PASS
        for finding in self.all_problems():
            if finding.severity.rank > worst.rank:
                worst = finding.severity
        return worst

    @property
    def passed(self) -> bool:
        """Whether the scan satisfies the configured CI/CD quality gate."""
        if self.fail_under is not None:
            if self.overall_score < self.fail_under:
                return False
            if any(t.sections and t.overall_score < self.fail_under for t in self.targets):
                return False
        if self.fail_on_severity:
            try:
                threshold = Severity(self.fail_on_severity.upper())
            except ValueError:
                threshold = Severity.CRITICAL
            if self.worst_severity().rank >= threshold.rank:
                return False
        return True

    def gate_failures(self) -> list[str]:
        """Human readable reasons why the quality gate failed (empty when it passed)."""
        reasons: list[str] = []
        if self.fail_under is not None:
            if self.overall_score < self.fail_under:
                reasons.append(
                    f"overall score {self.overall_score:.1f} is below --fail-under {self.fail_under:.1f}"
                )
            for target in self.targets:
                if target.sections and target.overall_score < self.fail_under:
                    reasons.append(
                        f"{target.target}: score {target.overall_score:.1f} is below "
                        f"--fail-under {self.fail_under:.1f}"
                    )
        if self.fail_on_severity:
            try:
                threshold = Severity(self.fail_on_severity.upper())
            except ValueError:
                threshold = Severity.CRITICAL
            offenders = [f for f in self.all_problems() if f.severity.rank >= threshold.rank]
            if offenders:
                reasons.append(
                    f"{len(offenders)} finding(s) at or above {threshold.value} severity"
                )
        return reasons

    # -- serialisation -----------------------------------------------------------
    def to_dict(self, include_remediation: bool = True) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "tool": {"name": "secaudit", "version": self.tool_version},
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": round(self.duration_ms, 1),
            "options": self.options,
            "gate": {
                "fail_under": self.fail_under,
                "fail_on_severity": self.fail_on_severity,
                "passed": self.passed,
                "reasons": self.gate_failures(),
            },
            "summary": {
                "targets": len(self.targets),
                "overall_score": self.overall_score,
                "grade": self.grade,
                "worst_severity": self.worst_severity().value,
                "counts": self.counts(),
            },
            "results": [t.to_dict(include_remediation) for t in self.targets],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str, ensure_ascii=False)

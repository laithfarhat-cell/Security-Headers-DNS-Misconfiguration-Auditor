"""DNS & e-mail security misconfiguration auditor.

Checks:

* SPF (RFC 7208) – presence, permissive ``all`` mechanisms, deprecated
  mechanisms and the recursive 10-DNS-lookup budget;
* DMARC (RFC 7489) – presence, policy enforcement, reporting addresses and the
  sub-domain policy;
* CAA (RFC 8659) – issuance restrictions, including inheritance from the
  organisational domain;
* DNSSEC – DNSKEY/DS presence and chain completeness;
* dangling CNAMEs / sub-domain takeover – matched against the local fingerprint
  list in ``data/dangling_cnames.json`` and validated with an optional HTTP probe;
* MTA-STS (RFC 8461) and SMTP TLS Reporting (RFC 8460) as informational checks.

All lookups go through :class:`dns.asyncresolver.Resolver`, so a custom
nameserver can be supplied for split-horizon / internal zones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from core.config import resource_file
from core.models import Category, Finding, SectionResult, Severity, Status

log = logging.getLogger(__name__)

#: Mechanisms that consume one of the ten RFC 7208 DNS lookups.
SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
#: Mechanisms that are deprecated by RFC 7208.
SPF_DEPRECATED_MECHANISMS = {"ptr"}

#: Public suffixes with two labels below the TLD (used for the DMARC/CAA
#: organisational-domain fallback when no Public Suffix List is available).
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br",
    "co.za", "org.za", "net.za",
    "com.tr", "org.tr", "net.tr", "gov.tr",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "org.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "co.in", "net.in", "org.in", "co.id", "co.kr", "or.kr",
    "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn",
    "co.il", "com.sa", "com.eg", "com.ng", "co.ke",
    "com.pk", "com.bd", "com.ua", "com.pl", "com.ru", "co.ae", "com.ly",
}


def _to_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):  # pragma: no cover - exotic input
        return host


def normalise_domain(target: str) -> str:
    """Extract a bare hostname from a URL-ish target."""
    raw = (target or "").strip()
    if not raw:
        raise ValueError("empty target")
    if "://" in raw:
        from urllib.parse import urlsplit

        parts = urlsplit(raw)
        host = parts.hostname or ""
    else:
        host = raw.split("/", 1)[0]
        if host.count(":") == 1 and host.rsplit(":", 1)[-1].isdigit():
            host = host.rsplit(":", 1)[0]
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"could not parse a domain from {target!r}")
    if any(ch in host for ch in " <>\"'"):
        raise ValueError(f"invalid domain: {host!r}")
    return _to_ascii(host)


def organisational_domain(host: str) -> str:
    """Best-effort eTLD+1 (no Public Suffix List dependency)."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return host.lower().rstrip(".")
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_spf(record: str) -> dict[str, Any]:
    """Parse an SPF record into mechanisms / qualifiers / ``all`` policy."""
    tokens = [t for t in re.split(r"\s+", (record or "").strip()) if t]
    if not tokens or tokens[0].lower() != "v=spf1":
        return {"valid": False, "all": None, "mechanisms": [], "terms": tokens}
    mechanisms: list[dict[str, str]] = []
    all_policy: str | None = None
    for token in tokens[1:]:
        qualifier = token[0] if token[:1] in "+-~?" else "+"
        body = token[1:] if token[:1] in "+-~?" else token
        name = re.split(r"[:=]", body, maxsplit=1)[0].lower()
        mechanisms.append({"term": token, "mechanism": name, "qualifier": qualifier})
        if name == "all":
            all_policy = qualifier
    return {
        "valid": True,
        "all": all_policy,
        "mechanisms": mechanisms,
        "terms": tokens,
        "redirect": next(
            (
                mech["term"].split("=", 1)[1]
                for mech in mechanisms
                if mech["mechanism"] == "redirect" and "=" in mech["term"]
            ),
            None,
        ),
    }


def parse_dmarc(record: str) -> dict[str, str] | None:
    """Parse a DMARC record into a lower-cased tag/value mapping."""
    if not record or not re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", record, re.IGNORECASE):
        return None
    tags: dict[str, str] = {}
    for chunk in record.split(";"):
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        tags[key.strip().lower()] = value.strip()
    tags.setdefault("v", "DMARC1")
    return tags


@dataclass
class DnsAnswer:
    name: str
    rdtype: str
    values: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def nxdomain(self) -> bool:
        return self.error == "NXDOMAIN"

    @property
    def exists(self) -> bool:
        return bool(self.values)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.rdtype, "values": self.values, "error": self.error}


@dataclass
class CnameLink:
    name: str
    target: str
    fingerprint: dict[str, Any] | None = None
    resolves: bool | None = None
    resolution_error: str | None = None
    unclaimed_signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target,
            "service": (self.fingerprint or {}).get("service"),
            "claim_url": (self.fingerprint or {}).get("claim_url"),
            "resolves": self.resolves,
            "resolution_error": self.resolution_error,
            "unclaimed_signature": self.unclaimed_signature,
        }


class DnsAuditor:
    """Asynchronous DNS / e-mail security auditor."""

    def __init__(
        self,
        *,
        nameservers: Sequence[str] | None = None,
        timeout: float = 5.0,
        lifetime: float = 10.0,
        spf_lookup_limit: int = 10,
        fingerprints_path: str | Path | None = None,
        probe_subdomains: Sequence[str] | None = None,
        probe_http: bool = True,
        user_agent: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.lifetime = lifetime
        self.spf_lookup_limit = spf_lookup_limit
        self.nameservers = list(nameservers or [])
        self.probe_subdomains = [s.strip().rstrip(".") for s in (probe_subdomains or []) if s.strip()]
        self.probe_http = probe_http
        self.user_agent = user_agent or "secaudit/1.0"
        self._fingerprints = self._load_fingerprints(fingerprints_path)
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self._resolver: dns.asyncresolver.Resolver | None = None
        self._resolver_error: str | None = None

    # -- resolver plumbing ---------------------------------------------------------
    def _get_resolver(self) -> dns.asyncresolver.Resolver | None:
        if self._resolver is not None or self._resolver_error:
            return self._resolver
        try:
            resolver = dns.asyncresolver.Resolver(configure=True)
            resolver.timeout = self.timeout
            resolver.lifetime = self.lifetime
            if self.nameservers:
                resolver.nameservers = self.nameservers
            self._resolver = resolver
        except Exception as exc:  # pragma: no cover - broken resolv.conf
            self._resolver_error = f"{type(exc).__name__}: {exc}"
            log.error("could not configure resolver: %s", exc)
        return self._resolver

    async def _query(self, name: str, rdtype: str) -> DnsAnswer:
        name = name.rstrip(".").lower()
        rdtype = rdtype.upper()
        key = (name, rdtype)
        if key in self._cache:
            return self._cache[key]
        answer = DnsAnswer(name=name, rdtype=rdtype)
        resolver = self._get_resolver()
        if resolver is None:
            answer.error = self._resolver_error or "no resolver"
            self._cache[key] = answer
            return answer
        try:
            response = await resolver.resolve(
                name, rdtype, raise_on_no_answer=False, lifetime=self.lifetime
            )
            rrset = getattr(response, "rrset", None)
            if rrset is not None:
                answer.values = [self._rdata_to_text(rdtype, rdata) for rdata in rrset]
        except dns.resolver.NXDOMAIN:
            answer.error = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            answer.error = None
        except dns.resolver.NoNameservers:
            answer.error = "NoNameservers (SERVFAIL)"
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            answer.error = "timeout"
        except dns.resolver.YXDOMAIN:  # pragma: no cover - rare
            answer.error = "YXDOMAIN"
        except dns.exception.DNSException as exc:
            answer.error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # pragma: no cover - defensive
            answer.error = f"{type(exc).__name__}: {exc}"
        self._cache[key] = answer
        return answer

    @staticmethod
    def _rdata_to_text(rdtype: str, rdata: Any) -> str:
        if rdtype == "TXT":
            try:
                return b"".join(rdata.strings).decode("utf-8", errors="replace")
            except AttributeError:  # pragma: no cover - dnspython variations
                return rdata.to_text().strip('"')
        if rdtype == "CAA":
            tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag)
            value = rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
            return f"{rdata.flags} {tag} \"{value}\""
        if rdtype == "MX":
            return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
        if rdtype in {"NS", "CNAME", "PTR"}:
            return rdata.target.to_text().rstrip(".")
        if rdtype == "DNSKEY":
            return f"flags={rdata.flags} algorithm={rdata.algorithm} key_tag={self_key_tag(rdata)}"
        if rdtype == "DS":
            return f"key_tag={rdata.key_tag} algorithm={rdata.algorithm} digest_type={rdata.digest_type}"
        return rdata.to_text()

    # -- fingerprints --------------------------------------------------------------
    @staticmethod
    def _load_fingerprints(path: str | Path | None) -> dict[str, Any]:
        candidates: list[Path] = []
        if path:
            candidates.append(Path(path).expanduser())
        resource = resource_file("data", "dangling_cnames.json")
        if resource:
            candidates.append(resource)
        candidates.append(Path(__file__).resolve().parent.parent / "data" / "dangling_cnames.json")
        for candidate in candidates:
            try:
                if candidate.is_file():
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                    services = data.get("services", [])
                    if not isinstance(services, list):
                        raise ValueError("'services' must be a list")
                    log.debug("loaded %d CNAME fingerprints from %s", len(services), candidate)
                    return data
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                log.warning("could not load CNAME fingerprints from %s: %s", candidate, exc)
        log.warning("no dangling CNAME fingerprint file found; generic checks only")
        return {"version": "none", "services": []}

    @property
    def fingerprints(self) -> list[dict[str, Any]]:
        return list(self._fingerprints.get("services", []))

    def match_fingerprint(self, target: str) -> dict[str, Any] | None:
        """Return the service fingerprint whose CNAME suffix matches ``target``."""
        host = target.rstrip(".").lower()
        best: dict[str, Any] | None = None
        best_length = -1
        for service in self.fingerprints:
            for suffix in service.get("cname_suffixes", []):
                suffix = str(suffix).rstrip(".").lower()
                if host == suffix or host.endswith("." + suffix):
                    if len(suffix) > best_length:
                        best, best_length = service, len(suffix)
        return best

    # -- public API ----------------------------------------------------------------
    async def audit(self, target: str, client: Any | None = None) -> SectionResult:
        started = time.perf_counter()
        section = SectionResult(category=Category.DNS)
        owns_client = False
        try:
            host = normalise_domain(target)
            section.data["domain"] = host
            section.data["nameservers"] = self.nameservers or ["system"]
            section.data["fingerprint_db"] = {
                "version": self._fingerprints.get("version"),
                "updated": self._fingerprints.get("updated"),
                "services": len(self.fingerprints),
            }

            # Kick off the independent lookups concurrently.
            lookup_names: dict[str, tuple[str, str]] = {
                "a": (host, "A"),
                "aaaa": (host, "AAAA"),
                "cname": (host, "CNAME"),
                "mx": (host, "MX"),
                "ns": (host, "NS"),
                "txt": (host, "TXT"),
                "caa": (host, "CAA"),
                "dnskey": (host, "DNSKEY"),
                "ds": (host, "DS"),
                "dmarc": (f"_dmarc.{host}", "TXT"),
                "mta_sts": (f"_mta-sts.{host}", "TXT"),
                "tls_rpt": (f"_smtp._tls.{host}", "TXT"),
            }
            results = await asyncio.gather(
                *(self._query(name, rdtype) for name, rdtype in lookup_names.values()),
                return_exceptions=True,
            )
            answers: dict[str, DnsAnswer] = {}
            for key, result in zip(lookup_names, results, strict=True):
                if isinstance(result, BaseException):  # pragma: no cover - defensive
                    name, rdtype = lookup_names[key]
                    answers[key] = DnsAnswer(name=name, rdtype=rdtype, error=str(result))
                else:
                    answers[key] = result

            section.data["records"] = {
                key: answer.to_dict()
                for key, answer in answers.items()
                if key not in {"dmarc", "mta_sts", "tls_rpt"}
            }

            resolver_errors = {a.error for a in answers.values() if a.error}
            transport_failure = {
                error
                for error in resolver_errors
                if any(
                    marker in error
                    for marker in ("timeout", "NoNameservers", "SERVFAIL", "no resolver", "Errno")
                )
            }
            # NXDOMAIN means the resolver answered — that is a resolution finding,
            # not a broken resolver.
            if all(a.error for a in answers.values()) and transport_failure:
                section.error = next(iter(sorted(transport_failure)), "DNS resolution failed")
                section.add(
                    self._finding(
                        "dns.unreachable",
                        "DNS lookups failed for this domain",
                        Status.FAIL,
                        Severity.HIGH,
                        10.0,
                        "Every DNS query failed (timeout or SERVFAIL). The domain, the "
                        "delegation or the configured resolver is broken.",
                        evidence=section.error,
                        remediation_key="dns.unreachable",
                        context={"target": host},
                    )
                )
                return self._finish(section, started)

            self._check_resolution(section, host, answers)
            await self._check_spf(section, host, answers["txt"])
            await self._check_dmarc(section, host, answers["dmarc"], answers["txt"])
            await self._check_caa(section, host, answers["caa"])
            self._check_dnssec(section, host, answers["dnskey"], answers["ds"])
            self._check_mta_sts(section, host, answers["mta_sts"], answers["tls_rpt"])

            if client is None and self.probe_http:
                import httpx

                client = httpx.AsyncClient(
                    verify=False,
                    timeout=self.timeout,
                    headers={"User-Agent": self.user_agent},
                    follow_redirects=True,
                )
                owns_client = True
            try:
                await self._check_cnames(section, host, client)
            finally:
                if owns_client and client is not None:
                    await client.aclose()
            return self._finish(section, started)
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("DNS audit crashed: %s", exc)
            section.error = f"{type(exc).__name__}: {exc}"
            section.add(
                self._finding(
                    "dns.error",
                    "DNS audit failed unexpectedly",
                    Status.FAIL,
                    Severity.MEDIUM,
                    10.0,
                    "The DNS auditor raised an exception; the zone could not be evaluated.",
                    evidence=section.error,
                    remediation_key="dns.unreachable",
                )
            )
            return self._finish(section, started)

    # -- checks --------------------------------------------------------------------
    def _check_resolution(
        self, section: SectionResult, host: str, answers: dict[str, DnsAnswer]
    ) -> None:
        a, aaaa, cname = answers["a"], answers["aaaa"], answers["cname"]
        if a.exists or aaaa.exists or cname.exists:
            addresses = a.values[:4] + aaaa.values[:2]
            section.add(
                self._finding(
                    "dns.resolve",
                    "Domain resolves to address records",
                    Status.PASS,
                    Severity.PASS,
                    10.0,
                    "The domain has usable A/AAAA (or CNAME) records.",
                    evidence=", ".join(addresses) or ", ".join(cname.values),
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.resolve",
                    "Domain does not resolve",
                    Status.FAIL,
                    Severity.CRITICAL,
                    10.0,
                    "No A, AAAA or CNAME record could be resolved. Visitors cannot reach the "
                    "site and mail delivery may fail as well.",
                    evidence=a.error or aaaa.error or "no address records",
                    remediation_key="dns.resolve",
                    context={"target": host},
                )
            )

    async def _check_spf(self, section: SectionResult, host: str, txt: DnsAnswer) -> None:
        spf_records = [value for value in txt.values if value.lower().startswith("v=spf1")]
        section.data["spf"] = {"records": spf_records}

        if not spf_records:
            section.add(
                self._finding(
                    "dns.spf.missing",
                    "No SPF record is published",
                    Status.FAIL,
                    Severity.HIGH,
                    8.0,
                    "Without SPF, anyone can send mail claiming to be @"
                    + host
                    + "; receivers cannot distinguish your infrastructure from a spoofing host.",
                    evidence="TXT: " + (", ".join(txt.values) if txt.values else "no TXT records"),
                    remediation_key="dns.spf",
                    context={"target": host},
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                )
            )
            return

        if len(spf_records) > 1:
            section.add(
                self._finding(
                    "dns.spf.multiple",
                    "Multiple SPF records are published",
                    Status.FAIL,
                    Severity.CRITICAL,
                    8.0,
                    "More than one v=spf1 record is a permanent error (permerror) per RFC 7208; "
                    "receivers treat the domain as having no valid SPF policy.",
                    evidence=" | ".join(spf_records),
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )
            return

        record = spf_records[0]
        parsed = parse_spf(record)
        section.data["spf"]["parsed"] = {
            "all": parsed.get("all"),
            "mechanisms": parsed.get("mechanisms"),
            "redirect": parsed.get("redirect"),
        }
        section.add(
            self._finding(
                "dns.spf.present",
                "SPF record is published",
                Status.PASS,
                Severity.PASS,
                8.0,
                "Exactly one v=spf1 record was found at the zone apex.",
                evidence=record,
            )
        )

        all_policy = parsed.get("all")
        if all_policy == "-":
            section.add(
                self._finding(
                    "dns.spf.all",
                    "SPF policy is 'fail' (-all)",
                    Status.PASS,
                    Severity.PASS,
                    8.0,
                    "Unauthorised senders are rejected outright.",
                    evidence=record,
                )
            )
        elif all_policy == "~":
            section.add(
                self._finding(
                    "dns.spf.all",
                    "SPF policy soft-fails (~all)",
                    Status.WARN,
                    Severity.LOW,
                    8.0,
                    "SoftFail lets receivers accept the message but mark it as suspicious; "
                    "move to -all once all legitimate senders are listed.",
                    evidence=record,
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )
        elif all_policy == "?":
            section.add(
                self._finding(
                    "dns.spf.all",
                    "SPF policy is neutral (?all)",
                    Status.WARN,
                    Severity.MEDIUM,
                    8.0,
                    "?all explicitly declines to make a statement, so receivers fall back to "
                    "other signals and spoofed mail is likely to be delivered.",
                    evidence=record,
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )
        elif all_policy == "+":
            section.add(
                self._finding(
                    "dns.spf.all",
                    "SPF policy allows every sender (+all)",
                    Status.FAIL,
                    Severity.CRITICAL,
                    8.0,
                    "+all authorises the entire internet to send mail for this domain, "
                    "which is worse than having no SPF record at all.",
                    evidence=record,
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.spf.all",
                    "SPF record has no 'all' mechanism",
                    Status.WARN,
                    Severity.MEDIUM,
                    8.0,
                    "Without an explicit all mechanism the policy defaults to ?all (neutral).",
                    evidence=record,
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )

        lookups, detail = await self._count_spf_lookups(host, record)
        section.data["spf"]["lookup_count"] = lookups
        section.data["spf"]["lookup_detail"] = detail
        if lookups > self.spf_lookup_limit:
            section.add(
                self._finding(
                    "dns.spf.lookups",
                    f"SPF exceeds the {self.spf_lookup_limit}-lookup limit ({lookups})",
                    Status.FAIL,
                    Severity.HIGH,
                    5.0,
                    "RFC 7208 caps a policy evaluation at 10 DNS lookups; exceeding it returns "
                    "permerror and receivers ignore the record, re-enabling spoofing.",
                    evidence=f"{lookups} lookups: " + "; ".join(detail[:12]),
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )
        elif lookups >= self.spf_lookup_limit - 2:
            section.add(
                self._finding(
                    "dns.spf.lookups",
                    f"SPF is close to the {self.spf_lookup_limit}-lookup limit ({lookups})",
                    Status.WARN,
                    Severity.MEDIUM,
                    5.0,
                    "Any new sender will push the policy over the RFC 7208 limit; flatten "
                    "includes or move transactional mail to a sub-domain.",
                    evidence=f"{lookups} lookups: " + "; ".join(detail[:12]),
                    remediation_key="dns.spf",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.spf.lookups",
                    f"SPF uses {lookups} of {self.spf_lookup_limit} allowed DNS lookups",
                    Status.PASS,
                    Severity.PASS,
                    5.0,
                    "The policy stays within the RFC 7208 DNS-lookup budget.",
                    evidence="; ".join(detail[:12]) or "no lookup mechanisms",
                )
            )

        deprecated = [
            mech["term"] for mech in parsed.get("mechanisms", []) if mech["mechanism"] in SPF_DEPRECATED_MECHANISMS
        ]
        section.add(
            self._finding(
                "dns.spf.ptr",
                "SPF uses the deprecated 'ptr' mechanism"
                if deprecated
                else "SPF does not use deprecated mechanisms",
                Status.WARN if deprecated else Status.PASS,
                Severity.LOW if deprecated else Severity.PASS,
                2.0,
                "The ptr mechanism is slow, unreliable and deprecated by RFC 7208.",
                evidence=", ".join(deprecated) or record,
                remediation_key="dns.spf" if deprecated else None,
                context={"target": host},
            )
        )

    async def _count_spf_lookups(
        self,
        domain: str,
        record: str,
        depth: int = 0,
        visited: set[str] | None = None,
    ) -> tuple[int, list[str]]:
        """Recursively count DNS lookups performed when evaluating the record."""
        if depth > 5:
            return 0, []
        visited = visited or set()
        if domain in visited:
            return 0, []
        visited.add(domain)

        parsed = parse_spf(record)
        total = 0
        detail: list[str] = []
        for mech in parsed.get("mechanisms", []):
            mechanism = mech["mechanism"]
            term = mech["term"]
            body = term.lstrip("+-~?")
            if mechanism not in SPF_LOOKUP_MECHANISMS:
                continue
            total += 1
            detail.append(term)
            target: str | None = None
            if mechanism == "include" and ":" in body:
                target = body.split(":", 1)[1]
            elif mechanism == "redirect" and "=" in body:
                target = body.split("=", 1)[1]
            if not target:
                continue
            target = target.rstrip(".")
            txt = await self._query(target, "TXT")
            nested_record = next(
                (v for v in txt.values if v.lower().startswith("v=spf1")), None
            )
            if nested_record:
                nested_total, nested_detail = await self._count_spf_lookups(
                    target, nested_record, depth + 1, visited
                )
                total += nested_total
                detail.extend(f"{target}: {item}" for item in nested_detail[:6])
        return total, detail

    async def _check_dmarc(
        self, section: SectionResult, host: str, dmarc: DnsAnswer, apex_txt: DnsAnswer
    ) -> None:
        records = [value for value in dmarc.values if "v=dmarc1" in value.lower()]
        source = f"_dmarc.{host}"
        inherited = False

        org = organisational_domain(host)
        if not records and org != host:
            # The record for the organisational domain applies to sub-domains.
            inherited_answer = await self._query(f"_dmarc.{org}", "TXT")
            if inherited_answer.values:
                inherited_records = [
                    value for value in inherited_answer.values if "v=dmarc1" in value.lower()
                ]
                if inherited_records:
                    records = inherited_records
                    source = f"_dmarc.{org} (inherited)"
                    inherited = True
            else:
                source = f"_dmarc.{host} / _dmarc.{org}"

        section.data["dmarc"] = {
            "source": source,
            "records": records,
            "inherited": inherited,
            "queried": {"host": dmarc.to_dict(), "apex_txt": apex_txt.to_dict()},
        }

        if not records:
            section.add(
                self._finding(
                    "dns.dmarc.missing",
                    "No DMARC record is published",
                    Status.FAIL,
                    Severity.HIGH,
                    8.0,
                    "Without DMARC, receivers have no instruction for handling mail that fails "
                    "SPF/DKIM and no reporting channel. Domain spoofing remains viable.",
                    evidence=f"TXT {dmarc.name}: {dmarc.error or 'no record'}",
                    remediation_key="dns.dmarc",
                    context={"target": host},
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                )
            )
            return

        if len(records) > 1:
            section.add(
                self._finding(
                    "dns.dmarc.multiple",
                    "Multiple DMARC records are published",
                    Status.FAIL,
                    Severity.HIGH,
                    8.0,
                    "Multiple DMARC records are treated as no record at all (RFC 7489 §6.6.3).",
                    evidence=" | ".join(records),
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )
            return

        tags = parse_dmarc(records[0])
        if tags is None:
            section.add(
                self._finding(
                    "dns.dmarc.invalid",
                    "DMARC record is malformed",
                    Status.WARN,
                    Severity.MEDIUM,
                    8.0,
                    "The record does not start with v=DMARC1, so receivers ignore it.",
                    evidence=records[0],
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )
            return

        section.data["dmarc"]["tags"] = tags
        section.add(
            self._finding(
                "dns.dmarc.present",
                "DMARC record is published",
                Status.PASS,
                Severity.PASS,
                8.0,
                "A DMARC policy is available to receivers.",
                evidence=records[0],
            )
        )

        policy = (tags.get("p") or "").lower()
        if policy == "reject":
            section.add(
                self._finding(
                    "dns.dmarc.policy",
                    "DMARC policy enforces reject (p=reject)",
                    Status.PASS,
                    Severity.PASS,
                    6.0,
                    "Mail that fails DMARC alignment is rejected.",
                    evidence=records[0],
                )
            )
        elif policy == "quarantine":
            section.add(
                self._finding(
                    "dns.dmarc.policy",
                    "DMARC policy enforces quarantine (p=quarantine)",
                    Status.PASS,
                    Severity.PASS,
                    6.0,
                    "Failing mail is quarantined; consider p=reject once reports are clean.",
                    evidence=records[0],
                )
            )
        elif policy == "none":
            section.add(
                self._finding(
                    "dns.dmarc.policy",
                    "DMARC policy is monitor-only (p=none)",
                    Status.WARN,
                    Severity.MEDIUM,
                    6.0,
                    "p=none requests reports but tells receivers to deliver failing mail, so "
                    "spoofing still reaches inboxes. Move to quarantine then reject.",
                    evidence=records[0],
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.dmarc.policy",
                    "DMARC record has no valid policy",
                    Status.WARN,
                    Severity.MEDIUM,
                    6.0,
                    "The p= tag is missing or invalid; the default is p=none.",
                    evidence=records[0],
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )

        rua = tags.get("rua")
        if not rua:
            section.add(
                self._finding(
                    "dns.dmarc.rua",
                    "DMARC aggregate reports (rua) are not configured",
                    Status.WARN,
                    Severity.LOW,
                    2.0,
                    "Without rua you receive no visibility into who is sending as your domain.",
                    evidence=records[0],
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.dmarc.rua",
                    "DMARC aggregate reporting is configured",
                    Status.PASS,
                    Severity.PASS,
                    2.0,
                    "Aggregate reports are delivered to the listed addresses.",
                    evidence=f"rua={rua}",
                )
            )

        pct = tags.get("pct")
        if pct is not None and pct.isdigit() and int(pct) < 100:
            section.add(
                self._finding(
                    "dns.dmarc.pct",
                    f"DMARC only applies to {pct}% of messages",
                    Status.WARN,
                    Severity.LOW,
                    1.5,
                    "Partial enforcement leaves a window for spoofed mail; raise pct to 100.",
                    evidence=records[0],
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )

        sp = (tags.get("sp") or "").lower()
        if policy in {"reject", "quarantine"} and sp == "none":
            section.add(
                self._finding(
                    "dns.dmarc.sp",
                    "DMARC sub-domain policy is weaker than the domain policy",
                    Status.WARN,
                    Severity.LOW,
                    1.5,
                    "sp=none lets attackers spoof any sub-domain even though the apex is "
                    "protected. Publish sp=reject or remove sp.",
                    evidence=records[0],
                    remediation_key="dns.dmarc",
                    context={"target": host},
                )
            )

    async def _check_caa(self, section: SectionResult, host: str, answer: DnsAnswer) -> None:
        records = list(answer.values)
        source = host
        if not records:
            org = organisational_domain(host)
            if org != host:
                inherited = await self._query(org, "CAA")
                if inherited.values:
                    records = list(inherited.values)
                    source = f"{org} (inherited)"

        section.data["caa"] = {"source": source, "records": records}
        if not records:
            section.add(
                self._finding(
                    "dns.caa.missing",
                    "No CAA records restrict certificate issuance",
                    Status.WARN,
                    Severity.MEDIUM,
                    4.0,
                    "Without CAA any public CA may issue a certificate for this domain after "
                    "domain-validation. CAA narrows that to the CAs you actually use.",
                    evidence=f"CAA {source}: none",
                    remediation_key="dns.caa",
                    context={"target": host},
                    references=["https://www.rfc-editor.org/rfc/rfc8659"],
                )
            )
            return

        tags: dict[str, list[str]] = {}
        critical_unknown: list[str] = []
        known_tags = {"issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone"}
        for value in records:
            match = re.match(r'^(\d+)\s+(\S+)\s+"?([^"]*)"?$', value.strip())
            if not match:
                continue
            flags, tag, content = match.groups()
            tag = tag.lower()
            tags.setdefault(tag, []).append(content)
            if flags != "0" and tag not in known_tags:
                critical_unknown.append(tag)

        section.data["caa"]["tags"] = tags
        issue = tags.get("issue", [])
        deny_all = bool(issue) and all(item.strip() == ";" for item in issue)
        if deny_all:
            section.add(
                self._finding(
                    "dns.caa.present",
                    "CAA forbids all certificate issuance (issue \";\")",
                    Status.INFO,
                    Severity.INFO,
                    4.0,
                    "No CA is authorised to issue certificates for this domain. This is a valid "
                    "hardening choice, but confirm it is intentional.",
                    evidence="; ".join(records),
                    remediation_key="dns.caa",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.caa.present",
                    "CAA records restrict certificate issuance",
                    Status.PASS,
                    Severity.PASS,
                    4.0,
                    "Only the listed CAs may issue certificates for this domain.",
                    evidence="; ".join(records),
                )
            )

        if not issue and not deny_all:
            section.add(
                self._finding(
                    "dns.caa.no_issue",
                    "CAA records do not define an issue policy",
                    Status.WARN,
                    Severity.LOW,
                    2.0,
                    "Records without an issue/issuewild tag do not actually restrict which CA "
                    "may issue certificates.",
                    evidence="; ".join(records),
                    remediation_key="dns.caa",
                    context={"target": host},
                )
            )

        if critical_unknown:
            section.add(
                self._finding(
                    "dns.caa.unknown_critical",
                    "CAA record uses unknown critical tags",
                    Status.WARN,
                    Severity.LOW,
                    1.0,
                    "An unknown tag with the critical flag set makes CAs refuse issuance "
                    f"({', '.join(sorted(set(critical_unknown)))}).",
                    evidence="; ".join(records),
                    remediation_key="dns.caa",
                    context={"target": host},
                )
            )

        if "iodef" not in tags:
            section.add(
                self._finding(
                    "dns.caa.iodef",
                    "CAA has no iodef reporting address",
                    Status.INFO,
                    Severity.INFO,
                    1.0,
                    "iodef lets CAs notify you about unauthorised issuance attempts.",
                    evidence="; ".join(records),
                    remediation_key="dns.caa",
                    context={"target": host},
                )
            )

    def _check_dnssec(
        self, section: SectionResult, host: str, dnskey: DnsAnswer, ds: DnsAnswer
    ) -> None:
        section.data["dnssec"] = {"dnskey": dnskey.to_dict(), "ds": ds.to_dict()}
        has_dnskey = dnskey.exists
        has_ds = ds.exists

        if has_dnskey and has_ds:
            section.add(
                self._finding(
                    "dns.dnssec.enabled",
                    "DNSSEC is enabled and chained to the parent zone",
                    Status.PASS,
                    Severity.PASS,
                    4.0,
                    "DNSKEY and DS records are published, so validating resolvers can prove "
                    "the zone has not been tampered with.",
                    evidence=f"DNSKEY: {len(dnskey.values)}; DS: {'; '.join(ds.values[:2])}",
                )
            )
        elif has_dnskey and not has_ds:
            section.add(
                self._finding(
                    "dns.dnssec.missing_ds",
                    "DNSSEC is signed but the DS record is missing",
                    Status.WARN,
                    Severity.MEDIUM,
                    4.0,
                    "Without a DS record in the parent zone the chain of trust is broken; "
                    "validating resolvers cannot verify the zone ('island of trust').",
                    evidence="DNSKEY present, DS absent",
                    remediation_key="dns.dnssec",
                    context={"target": host},
                    references=["https://www.rfc-editor.org/rfc/rfc4033"],
                )
            )
        elif has_ds and not has_dnskey:
            section.add(
                self._finding(
                    "dns.dnssec.bogus",
                    "DS record exists but the zone publishes no DNSKEY",
                    Status.FAIL,
                    Severity.HIGH,
                    4.0,
                    "Validating resolvers treat the zone as bogus and return SERVFAIL — the "
                    "site becomes unreachable for DNSSEC-validating clients.",
                    evidence=f"DS: {'; '.join(ds.values[:2])}",
                    remediation_key="dns.dnssec",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.dnssec.missing",
                    "DNSSEC is not enabled",
                    Status.WARN,
                    Severity.LOW,
                    4.0,
                    "Unsigned zones are vulnerable to cache-poisoning and forged DNS answers on "
                    "the resolution path.",
                    evidence="DNSKEY: none; DS: none",
                    remediation_key="dns.dnssec",
                    context={"target": host},
                )
            )

    def _check_mta_sts(
        self, section: SectionResult, host: str, mta_sts: DnsAnswer, tls_rpt: DnsAnswer
    ) -> None:
        sts_records = [v for v in mta_sts.values if v.lower().startswith("v=stsv1")]
        section.data["mta_sts"] = sts_records
        if sts_records:
            section.add(
                self._finding(
                    "dns.mta_sts.present",
                    "MTA-STS policy is advertised",
                    Status.PASS,
                    Severity.PASS,
                    1.0,
                    "Inbound SMTP connections can be forced to use TLS.",
                    evidence="; ".join(sts_records),
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.mta_sts.missing",
                    "MTA-STS is not configured",
                    Status.INFO,
                    Severity.INFO,
                    1.0,
                    "MTA-STS (RFC 8461) prevents SMTP downgrade attacks for inbound mail. "
                    "It is optional but strongly recommended.",
                    evidence=f"TXT _mta-sts.{host}: none",
                    remediation_key="dns.mta_sts",
                    context={"target": host},
                )
            )

        rpt_records = [v for v in tls_rpt.values if v.lower().startswith("v=tlsrptv1")]
        section.data["tls_rpt"] = rpt_records
        if rpt_records:
            section.add(
                self._finding(
                    "dns.tls_rpt.present",
                    "SMTP TLS reporting is configured",
                    Status.PASS,
                    Severity.PASS,
                    1.0,
                    "TLS failure reports will be delivered to your reporting address.",
                    evidence="; ".join(rpt_records),
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.tls_rpt.missing",
                    "SMTP TLS reporting is not configured",
                    Status.INFO,
                    Severity.INFO,
                    1.0,
                    "TLS-RPT (RFC 8460) gives you visibility into failed TLS negotiations for "
                    "your mail domains.",
                    evidence=f"TXT _smtp._tls.{host}: none",
                    remediation_key="dns.tls_rpt",
                    context={"target": host},
                )
            )

    # -- dangling CNAMEs -----------------------------------------------------------
    async def _cname_chain(self, name: str, max_hops: int = 8) -> list[CnameLink]:
        links: list[CnameLink] = []
        current = name
        seen: set[str] = set()
        for _ in range(max_hops):
            if current in seen:
                break
            seen.add(current)
            answer = await self._query(current, "CNAME")
            if not answer.values:
                break
            target = answer.values[0].rstrip(".")
            links.append(CnameLink(name=current, target=target))
            current = target
        return links

    async def _check_cnames(
        self, section: SectionResult, host: str, client: Any | None
    ) -> None:
        candidates = [host]
        for sub in self.probe_subdomains:
            candidates.append(sub if sub.endswith(host) else f"{sub}.{host}")

        links: list[CnameLink] = []
        for name in candidates:
            chain = await self._cname_chain(name)
            for link in chain:
                link.fingerprint = self.match_fingerprint(link.target)
                # Does the final target actually resolve?
                resolution = await self._query(link.target, "A")
                if not resolution.values:
                    resolution = await self._query(link.target, "AAAA")
                link.resolves = resolution.exists
                link.resolution_error = resolution.error
                if link.fingerprint and self.probe_http and client is not None:
                    signature = await self._probe_unclaimed(client, link.target, link.fingerprint)
                    link.unclaimed_signature = signature
            links.extend(chain)

        section.data["cname_chain"] = [link.to_dict() for link in links]

        if not links:
            section.add(
                self._finding(
                    "dns.cname.chain",
                    "No dangling CNAME records were found",
                    Status.PASS,
                    Severity.PASS,
                    2.0,
                    "The audited names resolve without CNAME indirection.",
                    evidence=f"{len(candidates)} name(s) checked",
                )
            )
            return

        section.add(
            self._finding(
                "dns.cname.chain",
                "CNAME chain recorded",
                Status.PASS,
                Severity.PASS,
                2.0,
                "CNAME targets were resolved; every hop was checked against the takeover "
                "fingerprint database.",
                evidence="; ".join(f"{link.name} → {link.target}" for link in links[:6]),
            )
        )

        for link in links:
            await self._evaluate_cname(section, link)

    async def _evaluate_cname(self, section: SectionResult, link: CnameLink) -> None:
        fingerprint = link.fingerprint or {}
        service = fingerprint.get("service")
        severity_name = str(fingerprint.get("severity", "high")).lower()
        severity = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }.get(severity_name, Severity.HIGH)

        context = {
            "target": link.name,
            "cname_target": link.target,
            "service": service or link.target,
            "claim_url": fingerprint.get("claim_url") or "",
        }

        if link.unclaimed_signature:
            section.add(
                self._finding(
                    "dns.cname.dangling",
                    f"Dangling CNAME to unclaimed {service or 'third-party endpoint'}",
                    Status.FAIL,
                    Severity.CRITICAL,
                    10.0,
                    f"{link.name} points at {link.target}, which answers with {service or 'the provider'}'s "
                    f"'unclaimed' page (\"{link.unclaimed_signature}\"). An attacker can register "
                    "that endpoint and serve arbitrary content on your domain (sub-domain takeover).",
                    evidence=f"{link.name} CNAME {link.target} → unclaimed",
                    remediation_key="dns.cname",
                    context=context,
                    references=[fingerprint.get("reference") or "https://owasp.org/www-community/attacks/Subdomain_takeover"],
                )
            )
            return

        if link.resolves is False:
            provider = f" ({service})" if service else ""
            section.add(
                self._finding(
                    "dns.cname.dangling",
                    f"Dangling CNAME to a non-existent host{provider}",
                    Status.FAIL,
                    Severity.CRITICAL,
                    10.0,
                    f"{link.name} is a CNAME to {link.target}, which does not resolve "
                    f"({link.resolution_error or 'no A/AAAA record'}). Whoever registers that "
                    "endpoint inherits your hostname — remove or repoint the record.",
                    evidence=f"{link.name} CNAME {link.target} → {link.resolution_error or 'NXDOMAIN'}",
                    remediation_key="dns.cname",
                    context=context,
                    references=[fingerprint.get("reference") or "https://owasp.org/www-community/attacks/Subdomain_takeover"],
                )
            )
            return

        if fingerprint:
            claim = fingerprint.get("claim_url") or ""
            section.add(
                self._finding(
                    "dns.cname.claimable",
                    f"CNAME points at a claimable {service} endpoint",
                    Status.WARN,
                    severity,
                    6.0,
                    f"{link.name} → {link.target} ({service}). The endpoint currently answers, so "
                    "the takeover is not confirmed, but ownership of the provider-side resource "
                    "must be verified — providers release these names when an account or site "
                    "is deleted."
                    + (f" Claim/verify at {claim}." if claim else ""),
                    evidence=f"{link.name} CNAME {link.target} (resolves={link.resolves})",
                    remediation_key="dns.cname",
                    context=context,
                    references=[fingerprint.get("reference") or "https://owasp.org/www-community/attacks/Subdomain_takeover"],
                )
            )
        else:
            section.add(
                self._finding(
                    "dns.cname.third_party",
                    "CNAME points at a third-party endpoint",
                    Status.INFO,
                    Severity.INFO,
                    2.0,
                    f"{link.name} delegates to {link.target}. Keep the provider-side resource "
                    "alive for as long as the DNS record exists.",
                    evidence=f"{link.name} CNAME {link.target}",
                )
            )

    async def _probe_unclaimed(
        self, client: Any, host: str, fingerprint: dict[str, Any]
    ) -> str | None:
        """Return the provider signature if the endpoint looks unclaimed."""
        signatures = [
            str(sig).lower() for sig in fingerprint.get("unclaimed_signatures", []) if sig
        ]
        if not signatures:
            return None
        url = f"https://{host.rstrip('.')}/"
        try:
            response = await client.get(url, timeout=self.timeout)
            body = response.text[:65536].lower()
        except Exception as exc:  # network errors are expected for dead endpoints
            log.debug("takeover probe for %s failed: %s", host, exc)
            return None
        for signature in signatures:
            if signature in body:
                return signature
        return None

    # -- helpers -------------------------------------------------------------------
    def _finding(
        self,
        check_id: str,
        title: str,
        status: Status,
        severity: Severity,
        weight: float,
        description: str,
        *,
        evidence: str | None = None,
        remediation_key: str | None = None,
        context: dict[str, Any] | None = None,
        references: list[str] | None = None,
    ) -> Finding:
        if evidence:
            evidence = " ".join(str(evidence).split())
            if len(evidence) > 300:
                evidence = evidence[:299] + "…"
        return Finding(
            check_id=check_id,
            title=title,
            category=Category.DNS,
            severity=severity,
            status=status,
            weight=weight,
            description=description,
            evidence=evidence,
            remediation_key=remediation_key,
            context=context or {},
            references=references or [],
        )

    @staticmethod
    def _finish(section: SectionResult, started: float) -> SectionResult:
        section.duration_ms = (time.perf_counter() - started) * 1000
        return section


def self_key_tag(rdata: Any) -> int:  # pragma: no cover - simple DNSKEY helper
    """Compute the RFC 4034 key tag for a DNSKEY rdata object."""
    try:
        wire = rdata.to_wire()
    except Exception:
        return 0
    tag = 0
    for index, byte in enumerate(wire):
        tag += byte if index % 2 == 0 else byte << 8
    tag += (tag >> 16) & 0xFFFF
    return tag & 0xFFFF

#!/usr/bin/env python3
"""Generate the sample reports in ``docs/samples/``.

The findings below are **synthetic demo data** — they exercise every renderer
(JSON, SARIF, Markdown, HTML) through the real model, scoring and export code so
the samples in the README stay in sync with the tool output.

Usage::

    python scripts/generate_samples.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.models import (  # noqa: E402  (path bootstrap must come first)
    AuditReport,
    Category,
    Finding,
    SectionResult,
    Severity,
    Status,
    TargetReport,
)
from core.scorer import Scorer  # noqa: E402
from reporters.exporter import Exporter  # noqa: E402

OUTPUT = ROOT / "docs" / "samples"
TARGET = "example.com"


def f(
    check_id: str,
    title: str,
    category: Category,
    status: Status,
    severity: Severity,
    weight: float,
    description: str,
    *,
    evidence: str | None = None,
    remediation_key: str | None = None,
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


def build_report() -> AuditReport:
    http = SectionResult(
        category=Category.HTTP,
        duration_ms=612.0,
        data={
            "host": TARGET,
            "start_url": f"https://{TARGET}/",
            "final_url": f"https://{TARGET}/",
            "status_code": 200,
            "https": True,
            "redirect_chain": [
                {
                    "url": f"http://{TARGET}/",
                    "status": 301,
                    "location": f"https://{TARGET}/",
                    "set_cookie": 0,
                },
                {
                    "url": f"https://{TARGET}/",
                    "status": 200,
                    "location": None,
                    "set_cookie": 2,
                },
            ],
            "cookies": [
                {"name": "session", "attributes": {"secure": True, "httponly": True, "samesite": "Lax"}},
                {"name": "cart", "attributes": {"samesite": "Lax"}},
                {"name": "_ga", "attributes": {"secure": True, "samesite": "Lax"}},
            ],
            "security_txt": {
                "url": f"https://{TARGET}/.well-known/security.txt",
                "status": 200,
                "content_type": "text/plain",
                "present": True,
                "fields": {
                    "contact": ["mailto:security@example.com"],
                    "expires": ["2027-06-01T00:00:00.000Z"],
                },
            },
        },
        findings=[
            f(
                "http.hsts.max_age_short",
                "HSTS max-age is shorter than 31536000 seconds",
                Category.HTTP,
                Status.WARN,
                Severity.MEDIUM,
                9.0,
                "A short HSTS lifetime leaves visitors unprotected between policy expiry and "
                "renewal. Use at least one year (31536000).",
                evidence="max-age=86400 (1.0 days)",
                remediation_key="http.hsts",
            ),
            f(
                "http.hsts.include_subdomains",
                "HSTS includeSubDomains is missing",
                Category.HTTP,
                Status.WARN,
                Severity.LOW,
                3.0,
                "includeSubDomains prevents attackers from downgrading any sub-domain, "
                "including forgotten staging hosts.",
                evidence="max-age=86400",
                remediation_key="http.hsts",
            ),
            f(
                "http.csp.present",
                "Content-Security-Policy is enforced",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                10.0,
                "An enforced CSP limits which sources the browser may load resources from.",
                evidence="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.net",
            ),
            f(
                "http.csp.unsafe_inline",
                "CSP allows 'unsafe-inline' for scripts",
                Category.HTTP,
                Status.WARN,
                Severity.MEDIUM,
                3.0,
                "'unsafe-inline' re-enables inline <script> execution, which neutralises most of "
                "CSP's XSS protection. Replace inline handlers with nonces or hashes.",
                evidence="script-src 'self' 'unsafe-inline' https://cdn.example.net",
                remediation_key="http.csp",
            ),
            f(
                "http.x_content_type_options.nosniff",
                "X-Content-Type-Options: nosniff is set",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                6.0,
                "MIME sniffing is disabled, preventing content-type confusion attacks.",
                evidence="nosniff",
            ),
            f(
                "http.x_frame_options.valid",
                "X-Frame-Options: SAMEORIGIN is set",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                5.0,
                "Framing by third-party origins is blocked.",
                evidence="SAMEORIGIN",
            ),
            f(
                "http.referrer_policy.valid",
                "Referrer-Policy restricts referrer leakage",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                6.0,
                "Cross-origin requests only receive the origin, not the full path.",
                evidence="strict-origin-when-cross-origin",
            ),
            f(
                "http.permissions_policy.missing",
                "Permissions-Policy header is missing",
                Category.HTTP,
                Status.WARN,
                Severity.LOW,
                5.0,
                "Without Permissions-Policy, embedded third-party frames may request camera, "
                "microphone, geolocation and other powerful features.",
                evidence="Permissions-Policy: absent",
                remediation_key="http.permissions_policy",
            ),
            f(
                "http.coop.present",
                "Cross-Origin-Opener-Policy: same-origin is set",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                4.0,
                "The browsing context is isolated from cross-origin openers.",
                evidence="same-origin",
            ),
            f(
                "http.cookies.secure",
                "Cookies are missing the Secure flag",
                Category.HTTP,
                Status.FAIL,
                Severity.HIGH,
                8.0,
                "Cookies without Secure are transmitted over plaintext HTTP and can be captured "
                "by any on-path attacker. Session cookies must be Secure.",
                evidence="1/3 cookie(s) without Secure: cart",
                remediation_key="http.cookies",
            ),
            f(
                "http.cookies.httponly",
                "All cookies carry the HttpOnly flag",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                5.0,
                "HttpOnly stops JavaScript from reading the cookie, blunting session hijacking "
                "after an XSS.",
                evidence="3 cookie(s) verified",
            ),
            f(
                "http.header.server",
                "Server header discloses software version",
                Category.HTTP,
                Status.WARN,
                Severity.LOW,
                2.0,
                "Version banners let attackers map the target to known CVEs; hide the token and "
                "patch promptly.",
                evidence="Server: nginx/1.18.0",
                remediation_key="http.tech_disclosure",
            ),
            f(
                "http.security_txt.valid",
                "security.txt is published and RFC 9116 compliant",
                Category.HTTP,
                Status.PASS,
                Severity.PASS,
                4.0,
                "A valid security.txt is served with 1 contact(s) and a future Expires field.",
                evidence="1 contact(s), expires 2027-06-01T00:00:00.000Z",
            ),
        ],
    )

    tls = SectionResult(
        category=Category.TLS,
        duration_ms=884.0,
        data={
            "host": TARGET,
            "port": 443,
            "certificate": {
                "subject": "CN=example.com",
                "issuer": "C=US, O=Let's Encrypt, CN=R11",
                "serial": "04a1b2c3d4e5f6",
                "not_before": "2026-09-09T08:15:00+00:00",
                "not_after": "2026-12-08T08:14:59+00:00",
                "days_remaining": 22.5,
                "san": ["example.com", "www.example.com", "api.example.com"],
                "key_type": "EC",
                "key_size": 256,
                "signature_algorithm": "ecdsa-with-SHA256",
                "is_self_signed": False,
                "is_ca": False,
                "verified": True,
                "verification_error": None,
            },
            "negotiated": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "bits": 256},
            "protocols": {"TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            "https_redirect": {
                "url": f"http://{TARGET}/",
                "status": 301,
                "location": f"https://{TARGET}/",
                "error": None,
            },
        },
        findings=[
            f(
                "tls.trust",
                "TLS certificate chain validates against the system trust store",
                Category.TLS,
                Status.PASS,
                Severity.PASS,
                10.0,
                "The leaf certificate chains to a trusted root and the hostname matches.",
                evidence="issuer: C=US, O=Let's Encrypt, CN=R11",
            ),
            f(
                "tls.expiry",
                "TLS certificate expires in 22.5 days",
                Category.TLS,
                Status.WARN,
                Severity.MEDIUM,
                9.0,
                "Certificates must be renewed before they expire; automate renewal and alert at 30 days.",
                evidence="notAfter=2026-12-08 (22.5 days remaining)",
                remediation_key="tls.expiry",
            ),
            f(
                "tls.protocol.tls1_0",
                "Deprecated TLSv1.0 is supported",
                Category.TLS,
                Status.FAIL,
                Severity.HIGH,
                4.0,
                "TLSv1.0 is deprecated by RFC 8996 and vulnerable to a long list of downgrade "
                "and padding-oracle attacks. Disable it and require TLS 1.2+.",
                evidence="TLSv1.0: accepted",
                remediation_key="tls.protocol",
            ),
            f(
                "tls.protocol.tls1_1",
                "Deprecated TLSv1.1 is disabled",
                Category.TLS,
                Status.PASS,
                Severity.PASS,
                4.0,
                "TLSv1.1 is deprecated by RFC 8996.",
                evidence="TLSv1.1: rejected",
            ),
            f(
                "tls.protocol.tls13",
                "TLS 1.3 is enabled",
                Category.TLS,
                Status.PASS,
                Severity.PASS,
                2.0,
                "TLS 1.3 removes legacy crypto and is faster.",
                evidence="TLSv1.3: accepted",
            ),
            f(
                "tls.cipher",
                "Negotiated cipher suite is strong",
                Category.TLS,
                Status.PASS,
                Severity.PASS,
                3.0,
                "The handshake selected an AEAD / forward-secret suite with adequate strength.",
                evidence="TLS_AES_256_GCM_SHA384 (256 bits, TLSv1.3)",
            ),
            f(
                "tls.certificate_san",
                "Certificate covers example.com",
                Category.TLS,
                Status.PASS,
                Severity.PASS,
                4.0,
                "The hostname is present in the certificate's SAN extension.",
                evidence="SAN: example.com, www.example.com, api.example.com",
            ),
            f(
                "tls.https_redirect",
                "Plaintext HTTP redirects to HTTPS",
                Category.TLS,
                Status.PASS,
                Severity.PASS,
                6.0,
                "Port 80 answers with a redirect to the HTTPS origin.",
                evidence=f"HTTP 301 → https://{TARGET}/",
            ),
        ],
    )

    dns = SectionResult(
        category=Category.DNS,
        duration_ms=418.0,
        data={
            "domain": TARGET,
            "nameservers": ["1.1.1.1", "8.8.8.8"],
            "spf": {
                "records": ["v=spf1 include:_spf.google.com include:mail.zendesk.com ~all"],
                "lookup_count": 12,
                "lookup_detail": [
                    "include:_spf.google.com",
                    "include:mail.zendesk.com",
                    "include:_netblocks.google.com",
                    "redirect:_spf.example.net",
                ],
            },
            "dmarc": {
                "source": f"_dmarc.{TARGET}",
                "records": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
                "inherited": False,
                "tags": {"v": "DMARC1", "p": "none", "rua": "mailto:dmarc@example.com"},
            },
            "caa": {"source": TARGET, "records": ['0 issue "letsencrypt.org"', '0 iodef "mailto:security@example.com"']},
            "dnssec": {"dnskey": {"values": []}, "ds": {"values": []}},
            "cname_chain": [
                {
                    "name": f"status.{TARGET}",
                    "target": "status-old.github.io",
                    "service": "GitHub Pages",
                    "claim_url": "https://github.com/settings/pages",
                    "resolves": False,
                    "resolution_error": "NXDOMAIN",
                    "unclaimed_signature": None,
                }
            ],
        },
        findings=[
            f(
                "dns.spf.present",
                "SPF record is published",
                Category.DNS,
                Status.PASS,
                Severity.PASS,
                8.0,
                "Exactly one v=spf1 record was found at the zone apex.",
                evidence="v=spf1 include:_spf.google.com include:mail.zendesk.com ~all",
            ),
            f(
                "dns.spf.all",
                "SPF policy soft-fails (~all)",
                Category.DNS,
                Status.WARN,
                Severity.LOW,
                8.0,
                "SoftFail lets receivers accept the message but mark it as suspicious; move to "
                "-all once all legitimate senders are listed.",
                evidence="v=spf1 include:_spf.google.com include:mail.zendesk.com ~all",
                remediation_key="dns.spf",
            ),
            f(
                "dns.spf.lookups",
                "SPF exceeds the 10-lookup limit (12)",
                Category.DNS,
                Status.FAIL,
                Severity.HIGH,
                5.0,
                "RFC 7208 caps a policy evaluation at 10 DNS lookups; exceeding it returns "
                "permerror and receivers ignore the record, re-enabling spoofing.",
                evidence="12 lookups: include:_spf.google.com; include:mail.zendesk.com; …",
                remediation_key="dns.spf",
            ),
            f(
                "dns.dmarc.present",
                "DMARC record is published",
                Category.DNS,
                Status.PASS,
                Severity.PASS,
                8.0,
                "A DMARC policy is available to receivers.",
                evidence="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            ),
            f(
                "dns.dmarc.policy",
                "DMARC policy is monitor-only (p=none)",
                Category.DNS,
                Status.WARN,
                Severity.MEDIUM,
                6.0,
                "p=none requests reports but tells receivers to deliver failing mail, so "
                "spoofing still reaches inboxes. Move to quarantine then reject.",
                evidence="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                remediation_key="dns.dmarc",
            ),
            f(
                "dns.caa.present",
                "CAA records restrict certificate issuance",
                Category.DNS,
                Status.PASS,
                Severity.PASS,
                4.0,
                "Only the listed CAs may issue certificates for this domain.",
                evidence='0 issue "letsencrypt.org"; 0 iodef "mailto:security@example.com"',
            ),
            f(
                "dns.dnssec.missing",
                "DNSSEC is not enabled",
                Category.DNS,
                Status.WARN,
                Severity.LOW,
                4.0,
                "Unsigned zones are vulnerable to cache-poisoning and forged DNS answers on the "
                "resolution path.",
                evidence="DNSKEY: none; DS: none",
                remediation_key="dns.dnssec",
            ),
            f(
                "dns.cname.dangling",
                "Dangling CNAME to a non-existent host (GitHub Pages)",
                Category.DNS,
                Status.FAIL,
                Severity.CRITICAL,
                10.0,
                f"status.{TARGET} is a CNAME to status-old.github.io, which does not resolve "
                "(NXDOMAIN). Whoever registers that endpoint inherits your hostname — remove or "
                "repoint the record.",
                evidence=f"status.{TARGET} CNAME status-old.github.io → NXDOMAIN",
                remediation_key="dns.cname",
            ),
            f(
                "dns.mta_sts.missing",
                "MTA-STS is not configured",
                Category.DNS,
                Status.INFO,
                Severity.INFO,
                1.0,
                "MTA-STS (RFC 8461) prevents SMTP downgrade attacks for inbound mail.",
                evidence=f"TXT _mta-sts.{TARGET}: none",
                remediation_key="dns.mta_sts",
            ),
        ],
    )

    target = TargetReport(
        target=TARGET,
        sections={
            Category.HTTP.value: http,
            Category.TLS.value: tls,
            Category.DNS.value: dns,
        },
        metadata={
            "requested_target": TARGET,
            "final_url": f"https://{TARGET}/",
            "status_code": 200,
            "redirect_chain": [
                {"url": f"http://{TARGET}/", "status": 301, "location": f"https://{TARGET}/"},
                {"url": f"https://{TARGET}/", "status": 200, "location": None},
            ],
            "https": True,
            "certificate_issuer": "C=US, O=Let's Encrypt, CN=R11",
            "certificate_expires": "2026-12-08T08:14:59+00:00",
            "protocols": {"TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            "nameservers": ["1.1.1.1", "8.8.8.8"],
            "spf": ["v=spf1 include:_spf.google.com include:mail.zendesk.com ~all"],
            "dmarc": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
        },
        duration_ms=1913.0,
    )
    Scorer().apply(target)

    report = AuditReport(
        targets=[target],
        duration_ms=2140.0,
        fail_under=85.0,
        fail_on_severity="critical",
        options={
            "concurrency": 10,
            "timeout": 10.0,
            "nameservers": ["1.1.1.1", "8.8.8.8"],
            "category_weights": {"http_headers": 45, "tls": 25, "dns_email": 30},
        },
    )
    return report


def main() -> None:
    report = build_report()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    exporter = Exporter(report)
    exporter.write_json(OUTPUT / "sample-report.json")
    exporter.write_sarif(OUTPUT / "sample-report.sarif")
    exporter.write_markdown(OUTPUT / "sample-report.md")
    exporter.write_html(OUTPUT / "sample-report.html", title=f"Security Audit — {TARGET}")

    summary = {
        "target": TARGET,
        "score": report.overall_score,
        "grade": report.grade,
        "gate_passed": report.passed,
        "severity_counts": report.counts(),
        "files": sorted(p.name for p in OUTPUT.iterdir()),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

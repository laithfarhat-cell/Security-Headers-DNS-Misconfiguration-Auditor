"""Weighted scoring engine, grading and remediation catalogue.

Scoring model
-------------
Every check contributes a fixed ``weight`` to its category.  A check that passes
credits the full weight, a warning credits 40 % and a failure credits nothing::

    category_score = 100 * Σ(weight_i × factor_i) / Σ(weight_i)

The overall score is the weighted mean of the three category scores (HTTP 45 %,
TLS 25 %, DNS/E-mail 30 % by default).  Because the weights are normalised, a
category can never escape the ``0-100`` range no matter how many findings a
target produces, and adding a new check does not silently reshape the grade.

The remediation catalogue lives in this module as well: every finding carries a
``remediation_key`` that resolves to a :class:`~core.models.Remediation` with
copy-pasteable Nginx, Apache, Cloudflare and DNS snippets.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from core.models import (
    AuditReport,
    Category,
    Finding,
    Remediation,
    SectionResult,
    Severity,
    Status,
    TargetReport,
)

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------
# Grade thresholds
# --------------------------------------------------------------------------------------
GRADE_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (97.0, "A+"),
    (93.0, "A"),
    (90.0, "A-"),
    (87.0, "B+"),
    (83.0, "B"),
    (80.0, "B-"),
    (77.0, "C+"),
    (73.0, "C"),
    (70.0, "C-"),
    (67.0, "D+"),
    (63.0, "D"),
    (60.0, "D-"),
)

#: Default weighting of the three categories (must sum to 100).
DEFAULT_CATEGORY_WEIGHTS: dict[str, float] = {
    Category.HTTP.value: 45.0,
    Category.TLS.value: 25.0,
    Category.DNS.value: 30.0,
}

#: Score factor for checks that are informational only.
_STATUS_FACTOR = {Status.PASS: 1.0, Status.INFO: 1.0, Status.WARN: 0.4, Status.FAIL: 0.0}


def score_to_grade(score: float) -> str:
    """Map a ``0-100`` score onto a letter grade (``A+`` … ``F``)."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def grade_to_colour(grade: str) -> str:
    """Rich/terminal colour name for a grade (kept here so all UIs agree)."""
    if grade.startswith("A"):
        return "green"
    if grade.startswith("B"):
        return "bright_green"
    if grade.startswith("C"):
        return "yellow"
    if grade.startswith("D"):
        return "dark_orange"
    return "red"


def severity_to_sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
        Severity.PASS: "none",
    }[severity]


def severity_to_score(severity: Severity) -> str:
    """GitHub code-scanning ``security-severity`` value (CVSS-like bucket)."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "0.0",
        Severity.PASS: "0.0",
    }[severity]


# --------------------------------------------------------------------------------------
# Remediation catalogue
# --------------------------------------------------------------------------------------
#: ``{target}`` / ``{cookie}`` / ``{header}`` style placeholders are interpolated
#: from ``Finding.context``.  Unknown placeholders are preserved verbatim, so
#: Apache's ``%{HTTP_HOST}`` and Nginx's ``$host`` are safe.
REMEDIATIONS: dict[str, Remediation] = {
    # ------------------------------- HTTP headers -------------------------------------
    "http.hsts": Remediation(
        summary=(
            "Send Strict-Transport-Security on every HTTPS response with a max-age of at "
            "least one year, includeSubDomains and (once you are confident) preload. "
            "HSTS closes the SSL-stripping window for returning visitors."
        ),
        nginx=(
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'
        ),
        apache=(
            "<IfModule mod_headers.c>\n"
            '    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n'
            "</IfModule>"
        ),
        cloudflare=(
            "SSL/TLS → Edge Certificates → HSTS: enable, Max-Age 12 months, "
            "Include subdomains = On, Preload = On, No-Sniff header = On."
        ),
        reference="https://owasp.org/www-project-secure-headers/#strict-transport-security",
    ),
    "http.csp": Remediation(
        summary=(
            "Deploy a restrictive Content-Security-Policy built from a nonce or hash based "
            "script-src, drop 'unsafe-inline'/'unsafe-eval', and lock down framing with "
            "frame-ancestors.  Roll it out with Content-Security-Policy-Report-Only first."
        ),
        nginx=(
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-$request_id'; "
            "style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; "
            "upgrade-insecure-requests\" always;"
        ),
        apache=(
            "<IfModule mod_headers.c>\n"
            "    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; "
            "style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'self'; form-action 'self'\"\n"
            "</IfModule>"
        ),
        cloudflare=(
            "Cloudflare does not synthesise a CSP. Inject it with a Transform Rule "
            "(Modify Response Header → Set → Content-Security-Policy) or at your origin."
        ),
        reference="https://owasp.org/www-project-secure-headers/#content-security-policy",
    ),
    "http.x_content_type_options": Remediation(
        summary=(
            "Set X-Content-Type-Options: nosniff so browsers refuse to MIME-sniff responses "
            "away from their declared Content-Type."
        ),
        nginx='add_header X-Content-Type-Options "nosniff" always;',
        apache='Header always set X-Content-Type-Options "nosniff"',
        cloudflare=(
            "SSL/TLS → Edge Certificates → “No-Sniff” header is part of the HSTS toggle; "
            "or add it with a Transform Rule."
        ),
        reference="https://owasp.org/www-project-secure-headers/#x-content-type-options",
    ),
    "http.x_frame_options": Remediation(
        summary=(
            "Deny framing to third parties.  Prefer CSP frame-ancestors (X-Frame-Options is "
            "ignored by modern browsers when frame-ancestors is present) and keep "
            "X-Frame-Options: DENY as a legacy fallback."
        ),
        nginx=(
            'add_header X-Frame-Options "DENY" always;\n'
            "# and in your CSP: frame-ancestors 'none'; or frame-ancestors 'self' https://app.example.com;"
        ),
        apache='Header always set X-Frame-Options "DENY"',
        cloudflare="Transform Rule → Set response header X-Frame-Options: DENY.",
        reference="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    ),
    "http.referrer_policy": Remediation(
        summary=(
            "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer) so URLs, "
            "query strings and fragments are not leaked to third parties."
        ),
        nginx='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        apache='Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        cloudflare="Transform Rule → Set response header Referrer-Policy: strict-origin-when-cross-origin.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    "http.permissions_policy": Remediation(
        summary=(
            "Restrict powerful browser features with Permissions-Policy.  Deny everything you "
            "do not explicitly need and never grant camera/microphone/geolocation to '*'."
        ),
        nginx=(
            'add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), '
            'gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;'
        ),
        apache=(
            'Header always set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), '
            'gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"'
        ),
        cloudflare="Transform Rule → Set response header Permissions-Policy with an explicit allow-list.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    "http.coop": Remediation(
        summary=(
            "Cross-Origin-Opener-Policy: same-origin isolates your browsing context from "
            "cross-origin windows (XS-Leak / Spectre class defences)."
        ),
        nginx='add_header Cross-Origin-Opener-Policy "same-origin" always;',
        apache='Header always set Cross-Origin-Opener-Policy "same-origin"',
        cloudflare="Transform Rule → Set response header Cross-Origin-Opener-Policy: same-origin.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    ),
    "http.corps": Remediation(
        summary=(
            "Deploy Cross-Origin-Resource-Policy to stop other origins from embedding your "
            "responses (use same-origin, or same-site for shared assets)."
        ),
        nginx='add_header Cross-Origin-Resource-Policy "same-origin" always;',
        apache='Header always set Cross-Origin-Resource-Policy "same-origin"',
        cloudflare="Transform Rule → Set response header Cross-Origin-Resource-Policy: same-origin.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    ),
    "http.cookies": Remediation(
        summary=(
            "Every session cookie needs Secure + HttpOnly + SameSite.  Use the __Host- prefix "
            "(requires Secure, Path=/ and no Domain attribute) for authentication cookies."
        ),
        nginx=(
            "# nginx ≥ 1.19.3 – rewrite flags on all proxied cookies\n"
            "proxy_cookie_flags ~ secure httponly samesite=strict;"
        ),
        apache=(
            "# mod_headers – append the flags if missing\n"
            'Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"'
        ),
        cloudflare="Cloudflare cannot rewrite Set-Cookie; fix it at the origin or in the application framework.",
        reference="https://owasp.org/www-community/controls/SecureCookieAttribute",
    ),
    "http.tech_disclosure": Remediation(
        summary=(
            "Remove version banners from Server, X-Powered-By and X-AspNet-Version.  Banner "
            "grabbing is the first step of most targeted exploitation playbooks."
        ),
        nginx=(
            "# nginx.conf (http block)\n"
            "server_tokens off;\n"
            "more_clear_headers Server X-Powered-By X-AspNet-Version X-AspNetMvc-Version;  "
            "# headers-more module\n"
            "# without headers-more:\n"
            "proxy_hide_header X-Powered-By;"
        ),
        apache=(
            "ServerTokens Prod\n"
            "ServerSignature Off\n"
            "<IfModule mod_headers.c>\n"
            "    Header unset X-Powered-By\n"
            "    Header unset X-AspNet-Version\n"
            "    Header unset Server\n"
            "</IfModule>"
        ),
        cloudflare="Cloudflare already strips/rewrites the Server header; add Transform Rules for X-Powered-By.",
        reference="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    ),
    "http.security_txt": Remediation(
        summary=(
            "Publish RFC 9116 security.txt at /.well-known/security.txt with a Contact and an "
            "Expires field so researchers can reach you securely."
        ),
        nginx=(
            "location = /.well-known/security.txt {\n"
            "    default_type text/plain;\n"
            '    add_header Cache-Control "max-age=86400";\n'
            "}"
        ),
        apache=(
            '<If "%{REQUEST_URI} == /.well-known/security.txt">\n'
            '    ForceType text/plain\n'
            "</If>"
        ),
        cloudflare="Upload /.well-known/security.txt to your origin or serve it from Cloudflare Pages.",
        reference="https://www.rfc-editor.org/rfc/rfc9116",
    ),
    "http.unreachable": Remediation(
        summary=(
            "The target did not answer over HTTPS.  Confirm DNS, the listening socket, firewall "
            "rules and that the certificate chains to a public root before re-running the audit."
        ),
        nginx="# verify the server block listens on 443\nlisten 443 ssl;\nlisten [::]:443 ssl;",
        apache="# verify the vhost\n<VirtualHost *:443>\n    SSLEngine on\n</VirtualHost>",
        cloudflare="Check SSL/TLS → Overview is not set to “Off” and that the origin is reachable.",
        reference="https://httpstatus.io/",
    ),
    # ---------------------------------- TLS -----------------------------------------
    "tls.expiry": Remediation(
        summary=(
            "Renew the leaf certificate before it expires and monitor the remaining lifetime "
            "(alert at 30 days, page at 14).  Automate renewal with ACME."
        ),
        nginx=(
            "# certbot\ncertbot renew --quiet --deploy-hook \"nginx -s reload\"\n"
            "# cron: 0 3 * * * certbot renew --quiet --deploy-hook \"systemctl reload nginx\""
        ),
        apache="certbot renew --quiet --deploy-hook \"systemctl reload apache2\"",
        cloudflare="Cloudflare managed certificates renew automatically – verify Edge Certificates shows an active cert.",
        reference="https://letsencrypt.org/docs/renewal-reminder/",
    ),
    "tls.trust": Remediation(
        summary=(
            "Serve the complete chain (leaf + intermediates) and make sure the certificate is "
            "issued by a publicly trusted CA for the exact hostname."
        ),
        nginx=(
            "ssl_certificate     /etc/letsencrypt/live/{target}/fullchain.pem;\n"
            "ssl_certificate_key /etc/letsencrypt/live/{target}/privkey.pem;"
        ),
        apache=(
            "SSLCertificateFile    /etc/letsencrypt/live/{target}/fullchain.pem\n"
            "SSLCertificateKeyFile /etc/letsencrypt/live/{target}/privkey.pem"
        ),
        cloudflare="SSL/TLS → Overview: use “Full (strict)” so Cloudflare validates the origin certificate.",
        reference="https://www.ssllabs.com/ssltest/",
    ),
    "tls.protocol": Remediation(
        summary=(
            "Disable TLS 1.0 and TLS 1.1 (deprecated by RFC 8996) and allow only TLS 1.2/1.3 "
            "with modern cipher suites."
        ),
        nginx=(
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_prefer_server_ciphers off;\n"
            "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;"
        ),
        apache=(
            "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
            "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
            "SSLHonorCipherOrder off"
        ),
        cloudflare="SSL/TLS → Edge Certificates → Minimum TLS Version: TLS 1.2 (or TLS 1.3).",
        reference="https://www.rfc-editor.org/rfc/rfc8996",
    ),
    "tls.cipher": Remediation(
        summary=(
            "Remove NULL, RC4, 3DES and export-grade suites.  Prefer AEAD ciphers "
            "(AES-GCM / ChaCha20-Poly1305) with forward secrecy and ≥112-bit security."
        ),
        nginx=(
            "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\n"
            "ssl_prefer_server_ciphers off;"
        ),
        apache=(
            "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
            "SSLHonorCipherOrder off"
        ),
        cloudflare="Cloudflare only offers modern AEAD suites on the edge; the origin still needs hardening.",
        reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ),
    "tls.https_redirect": Remediation(
        summary=(
            "Port 80 must answer with a 301/308 redirect to the HTTPS origin (or be closed "
            "entirely).  Never serve content over plaintext HTTP."
        ),
        nginx=(
            "server {\n"
            "    listen 80;\n"
            "    listen [::]:80;\n"
            "    server_name {target};\n"
            "    return 301 https://$host$request_uri;\n"
            "}"
        ),
        apache=(
            "<VirtualHost *:80>\n"
            "    ServerName {target}\n"
            "    RewriteEngine On\n"
            "    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
            "</VirtualHost>"
        ),
        cloudflare="SSL/TLS → Edge Certificates → “Always Use HTTPS”: On.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
    ),
    "tls.certificate_key": Remediation(
        summary=(
            "Use at least RSA 2048 (preferably 3072) or EC P-256 keys, and sign with SHA-256 "
            "or better.  MD5/SHA-1 signatures are considered broken."
        ),
        nginx=(
            "# issue a modern certificate\n"
            "certbot certonly --webroot -w /var/www/html -d {target} --key-type ecdsa --elliptic-curve secp256r1"
        ),
        apache=(
            "# issue a modern certificate\n"
            "certbot certonly --webroot -w /var/www/html -d {target} --key-type ecdsa --elliptic-curve secp256r1"
        ),
        cloudflare="Cloudflare edge certificates use ECDSA P-256 by default; rotate the origin certificate.",
        reference="https://www.rfc-editor.org/rfc/rfc9151",
    ),
    "tls.certificate_san": Remediation(
        summary=(
            "Include every hostname you serve in the certificate's Subject Alternative Name "
            "extension; modern clients ignore the legacy Common Name field."
        ),
        nginx="certbot certonly --webroot -w /var/www/html -d {target} -d www.{target}",
        apache="certbot certonly --webroot -w /var/www/html -d {target} -d www.{target}",
        cloudflare="Edge Certificates → add the hostname to the certificate (universal or advanced).",
        reference="https://www.rfc-editor.org/rfc/rfc6125",
    ),
    "tls.unreachable": Remediation(
        summary=(
            "The TLS endpoint could not be reached on port 443.  Validate DNS records, the "
            "listener, security groups / firewall rules and SNI configuration."
        ),
        nginx="listen 443 ssl;\nssl_certificate /etc/ssl/certs/{target}.pem;\nssl_certificate_key /etc/ssl/private/{target}.key;",
        apache="<VirtualHost *:443>\n    SSLEngine on\n    SSLCertificateFile /etc/ssl/certs/{target}.pem\n</VirtualHost>",
        cloudflare="Verify the DNS record is proxied (orange cloud) and the origin supports TLS.",
        reference="https://developers.cloudflare.com/ssl/",
    ),
    # ------------------------------- DNS / e-mail -----------------------------------
    "dns.spf": Remediation(
        summary=(
            "Publish exactly one SPF record per domain, end it with -all (hard fail), keep the "
            "DNS-lookup count at or below 10 and remove deprecated mechanisms such as ptr."
        ),
        dns=(
            '{target}.        TXT  "v=spf1 mx include:_spf.example-provider.com -all"\n'
            "# count lookups first:  https://www.kitterman.com/spf/validate.html\n"
            "# >10 lookups? flatten includes or split transactional mail onto a subdomain:\n"
            "mail.{target}.   TXT  \"v=spf1 include:_spf.example-provider.com -all\""
        ),
        reference="https://www.rfc-editor.org/rfc/rfc7208",
    ),
    "dns.dmarc": Remediation(
        summary=(
            "Publish a DMARC record with p=quarantine or p=reject and rua reporting so you can "
            "detect spoofing attempts and receive aggregate reports."
        ),
        dns=(
            '_dmarc.{target}.  TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; '
            'fo=1; rua=mailto:dmarc-reports@{target}; ruf=mailto:dmarc-forensics@{target}"\n'
            "# rollout: start with p=none, review rua reports for 2-4 weeks, then move to "
            "p=quarantine and finally p=reject"
        ),
        cloudflare=(
            "Cloudflare Email Security / DNS → add the TXT record at _dmarc.{target}. "
            "Keep Email Routing's own SPF/DKIM records intact."
        ),
        reference="https://www.rfc-editor.org/rfc/rfc7489",
    ),
    "dns.caa": Remediation(
        summary=(
            "Add CAA records pinning which CAs may issue certificates for the domain, and "
            "include an iodef contact for violation reports."
        ),
        dns=(
            '{target}.        CAA  0 issue "letsencrypt.org"\n'
            '{target}.        CAA  0 issuewild ";"\n'
            '{target}.        CAA  0 iodef "mailto:security@{target}"\n'
            "# allow your secondary CA too, e.g. 0 issue \"pki.goog\" / \"digicert.com\""
        ),
        cloudflare="DNS → Records → Add record → CAA (Cloudflare's UI exposes issue/issuewild/iodef).",
        reference="https://www.rfc-editor.org/rfc/rfc8659",
    ),
    "dns.dnssec": Remediation(
        summary=(
            "Enable DNSSEC so resolvers can cryptographically validate your zone: publish "
            "DNSKEY/RRSIG in the zone and the matching DS record at the registrar/parent."
        ),
        dns=(
            "# after enabling DNSSEC at the provider, publish the DS record at the parent:\n"
            "{target}.  IN DS  <keytag> <algorithm> <digest-type> <digest>\n"
            "# verify:  dig +dnssec DNSKEY {target}  /  dig +trace DS {target}"
        ),
        cloudflare="DNS → Settings → DNSSEC → Enable DNSSEC, then add the DS record at your registrar.",
        reference="https://www.rfc-editor.org/rfc/rfc4033",
    ),
    "dns.cname": Remediation(
        summary=(
            "A CNAME points at a third-party endpoint that no longer exists — an attacker can "
            "often claim it and serve content on your domain.  Remove or repoint the record, "
            "or re-claim the service."
        ),
        dns=(
            "{target}.   IN CNAME   <active-provider-endpoint>\n"
            "# or delete the record entirely:\n"
            "# dig +short {target} CNAME  # confirm the chain is gone"
        ),
        cloudflare="DNS → Records → delete or repoint the dangling CNAME, then purge the edge cache.",
        reference="https://owasp.org/www-community/attacks/Subdomain_takeover",
    ),
    "dns.mta_sts": Remediation(
        summary=(
            "Publish MTA-STS (RFC 8461) to force TLS for inbound SMTP, together with the "
            "_mta-sts TXT record and the HTTPS policy file."
        ),
        dns=(
            '_mta-sts.{target}.   TXT   "v=STSv1; id=20260101000000"\n'
            "# https://mta-sts.{target}/.well-known/mta-sts.txt\n"
            "version: STSv1\nmode: enforce\nmx: mx1.{target}\nmx: mx2.{target}\nmax_age: 604800"
        ),
        reference="https://www.rfc-editor.org/rfc/rfc8461",
    ),
    "dns.tls_rpt": Remediation(
        summary=(
            "Publish SMTP TLS Reporting (RFC 8460) so you learn about TLS failures on inbound "
            "and outbound mail flows."
        ),
        dns='_smtp._tls.{target}.  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@{target}"',
        reference="https://www.rfc-editor.org/rfc/rfc8460",
    ),
    "dns.resolve": Remediation(
        summary=(
            "The domain does not resolve to an address.  Verify the A/AAAA records, the "
            "delegation at the registrar and the zone's NS records."
        ),
        dns=(
            "{target}.        A     203.0.113.10\n"
            "{target}.        AAAA  2001:db8::10\n"
            "# check delegation:\n"
            "dig +trace NS {target}"
        ),
        reference="https://www.rfc-editor.org/rfc/rfc1035",
    ),
    "dns.unreachable": Remediation(
        summary=(
            "DNS lookups for this target failed (timeout/SERVFAIL).  Check the resolver, the "
            "delegation and the zone's availability, then re-run the audit."
        ),
        dns=(
            "# query the authoritative servers directly\n"
            "dig +norecurse @ns1.example.net {target} SOA\n"
            "# or re-run with an explicit resolver\n"
            "secaudit -d {target} --nameserver 1.1.1.1"
        ),
        reference="https://www.rfc-editor.org/rfc/rfc1035",
    ),
}

#: Fallback used when a finding references an unknown remediation key.
GENERIC_REMEDIATION = Remediation(
    summary="Review the finding details and apply the vendor's hardening guidance for this control.",
    reference="https://owasp.org/www-project-secure-headers/",
)

#: Every key that auditors are allowed to reference (validated by the unit tests).
REMEDIATION_KEYS: frozenset[str] = frozenset(REMEDIATIONS)


def get_remediation(key: str | None, context: dict[str, Any] | None = None) -> Remediation | None:
    """Look up and render a remediation template."""
    if not key:
        return None
    template = REMEDIATIONS.get(key)
    if template is None:
        log.debug("No remediation template registered for key %r", key)
        return None
    return template.render(context)


# --------------------------------------------------------------------------------------
# Scorer
# --------------------------------------------------------------------------------------
@dataclass
class CategoryResult:
    category: Category
    score: float
    weight: float
    earned: float
    possible: float
    checks: int
    failed: int
    warnings: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "weight": self.weight,
            "earned": round(self.earned, 2),
            "possible": round(self.possible, 2),
            "checks": self.checks,
            "failed": self.failed,
            "warnings": self.warnings,
        }


class Scorer:
    """Turns findings into category scores, an overall score and a grade."""

    def __init__(
        self,
        category_weights: dict[str, float] | None = None,
        ignore_checks: Iterable[str] | None = None,
    ) -> None:
        weights = dict(DEFAULT_CATEGORY_WEIGHTS)
        if category_weights:
            for key, value in category_weights.items():
                try:
                    weights[str(key)] = max(0.0, float(value))
                except (TypeError, ValueError):
                    log.warning("Ignoring invalid category weight %r=%r", key, value)
        if sum(weights.values()) <= 0:
            raise ValueError("Category weights must sum to a positive number")
        self.category_weights = weights
        self.ignore_checks = tuple(ignore_checks or ())

    # -- filtering -----------------------------------------------------------------
    def _ignored(self, finding: Finding) -> bool:
        for pattern in self.ignore_checks:
            if finding.check_id == pattern or finding.check_id.startswith(pattern.rstrip("*")):
                return True
        return False

    # -- scoring -------------------------------------------------------------------
    @staticmethod
    def score_findings(findings: Sequence[Finding]) -> tuple[float, float, float]:
        """Return ``(score, earned, possible)`` for one category."""
        possible = 0.0
        earned = 0.0
        for finding in findings:
            weight = max(0.0, float(finding.weight))
            if weight == 0:
                continue
            possible += weight
            earned += weight * _STATUS_FACTOR.get(finding.status, 0.0)
        if possible <= 0:
            return 0.0, 0.0, 0.0
        return round(100.0 * earned / possible, 2), earned, possible

    def score_section(self, section: SectionResult) -> CategoryResult | None:
        findings = [f for f in section.findings if not self._ignored(f)]
        if not findings:
            return None
        score, earned, possible = self.score_findings(findings)
        return CategoryResult(
            category=section.category,
            score=score,
            weight=self.category_weights.get(section.category.value, 0.0),
            earned=earned,
            possible=possible,
            checks=len(findings),
            failed=sum(1 for f in findings if f.status is Status.FAIL),
            warnings=sum(1 for f in findings if f.status is Status.WARN),
        )

    def score_target(self, report: TargetReport) -> TargetReport:
        category_results: list[CategoryResult] = []
        scores: dict[str, float] = {}
        for section in report.sections.values():
            result = self.score_section(section)
            if result is None:
                continue
            category_results.append(result)
            scores[result.category.value] = result.score

        total_weight = sum(r.weight for r in category_results)
        if total_weight <= 0:
            # No weights configured for the categories we have: fall back to a mean.
            overall = (
                sum(r.score for r in category_results) / len(category_results)
                if category_results
                else 0.0
            )
        else:
            overall = sum(r.score * r.weight for r in category_results) / total_weight

        report.scores = scores
        report.overall_score = round(overall, 2)
        report.grade = score_to_grade(report.overall_score)
        return report

    # -- remediation ---------------------------------------------------------------
    def attach_remediations(self, report: TargetReport) -> TargetReport:
        for section in report.sections.values():
            for finding in section.findings:
                finding.target = report.target
                if finding.remediation is None and finding.status.is_problem:
                    context = dict(finding.context)
                    context.setdefault("target", report.target)
                    context.setdefault("domain", report.target)
                    finding.remediation = get_remediation(
                        finding.remediation_key or finding.check_id, context
                    )
                    if finding.remediation is None and finding.status is Status.FAIL:
                        finding.remediation = GENERIC_REMEDIATION.render(context)
        return report

    def apply(self, report: TargetReport) -> TargetReport:
        """Attach remediation snippets and compute all scores."""
        self.attach_remediations(report)
        return self.score_target(report)

    def apply_all(self, report: AuditReport) -> AuditReport:
        for target in report.targets:
            self.apply(target)
        return report


def category_summary(report: TargetReport) -> list[dict[str, Any]]:
    """Convenience helper for reporters: per-category score + finding counts."""
    rows: list[dict[str, Any]] = []
    for category in Category:
        section = report.sections.get(category.value)
        if section is None:
            continue
        problems = [f for f in section.findings if f.status.is_problem]
        rows.append(
            {
                "category": category.label,
                "key": category.value,
                "score": report.scores.get(category.value),
                "findings": len(section.findings),
                "problems": len(problems),
                "error": section.error,
            }
        )
    return rows

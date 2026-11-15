# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-11-15

### Added

- **HTTP auditor** — manual redirect-chain tracking, OWASP Secure Headers evaluation
  (HSTS, CSP with directive parsing, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, COOP/CORP), cookie flag analysis across
  every hop (`Secure`, `HttpOnly`, `SameSite`, `__Host-`/`__Secure-` prefixes),
  technology-disclosure detection and RFC 9116 `security.txt` validation.
- **TLS auditor** — certificate expiry countdown, chain validation, self-signed
  detection, SAN coverage (DNS + IP), key/signature strength, live TLS 1.0/1.1/1.2/1.3
  probes, negotiated-cipher analysis and port-80 HTTPS redirect verification.
- **DNS auditor** — SPF (single record, `all` policy, deprecated `ptr`, recursive
  10-lookup budget), DMARC (presence, inheritance, policy, `rua`/`ruf`, `pct`, `sp`),
  CAA (issuance restrictions, inheritance, critical tags, `iodef`), DNSSEC
  (DNSKEY/DS/chain completeness), MTA-STS and TLS-RPT.
- **Sub-domain takeover detection** — 33 provider fingerprints with CNAME-suffix
  matching, target resolution checks and HTTP "unclaimed site" signature probes.
- **Scoring engine** — normalised per-category weights (HTTP 45 / TLS 25 / DNS 30),
  `A+` … `F` grading, per-check weights and 29 remediation templates covering Nginx,
  Apache, Cloudflare and DNS.
- **CL I** — `argparse` interface with `-d`, `-iL`, `--nameserver`, `-c`, `--timeout`,
  `--ignore`, `--fail-under`, `--fail-on-severity`, `-oJ/-oS/-oM/-oH`, YAML config and
  a `rich` terminal report with severity badges and inline fixes.
- **Exporters** — JSON, SARIF 2.1.0 (GitHub Code Scanning with `security-severity` and
  stable `partialFingerprints`), Markdown and a self-contained HTML dashboard.
- **Packaging & CI** — `pyproject.toml` console scripts (`secaudit`, `domain-audit`),
  `requirements.txt`, multi-stage non-root `Dockerfile`, `.gitignore`, `.dockerignore`,
  sample GitHub Actions workflow with SARIF upload and artifact publishing.
- **Tests** — 163 tests (parsers, auditors with mocked HTTP/resolver and a local TLS
  server, scoring/gates, all exporters, CLI exit codes) plus ruff configuration.

[1.0.0]: https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor/releases/tag/v1.0.0

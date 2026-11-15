# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-11-15

### Fixed

- **CI: `Domain Security Audit` failed on every push to `main`.** The
  *Resolve target list* step exited with status 1 when neither `domains.txt` nor
  the `domains` workflow-dispatch input existed, so the audit job went red (and
  every later step was skipped) on a repository without configured domains.
  Resolution now always succeeds: an empty target list emits a
  `::notice::`, writes a `⏭️ Domain audit skipped` block to the job summary and
  short-circuits the audit via the `preflight` job output instead of failing the
  build. A repository is therefore green out of the box and turns into a real
  gate as soon as `domains.txt` (or the dispatch input) provides targets.

### Changed

- **Workflow split into `quality` → `preflight` → `audit`.** Target resolution
  lives in its own job and hands `targets.txt` to the audit job through an
  artifact; the audit only runs when `needs.preflight.outputs.has_targets == 'true'`.
- **Workflow now runs on `pull_request`** (lint + unit tests only), so changes are
  validated before merging while the domain audit stays limited to `main`.
- **Gate thresholds are configurable without editing YAML** via the
  `AUDIT_FAIL_UNDER` and `AUDIT_FAIL_ON_SEVERITY` repository variables, with
  workflow-dispatch inputs taking precedence (`fail_under`, `fail_on_severity`).
- **Target-list normalisation**: CRLF endings, `#` comments, inline comments,
  blank lines, full URLs and duplicates are stripped/de-duplicated before the
  audit runs, and the resolved count is echoed to the log and step summary.
- Added `domains.example.txt` as a copy-and-fill template.
- `AuditReport.tool_version` now derives from `core.__version__` (single source of
  truth) instead of being hard-coded.

### Added

- **Workflow regression tests** (`tests/test_workflow.py`, 12 tests) asserting the
  trigger set, job gating, artifact hand-over, SARIF upload guard and the
  no-`exit 1` behaviour of the resolve script — plus end-to-end execution of that
  script against dispatch input and `domains.txt` fixtures. Suite: 163 → 175 tests.

### Docs

- README CI section rewritten: how to provide targets, the two gate variables,
  exit-code semantics and the "skipped, not failed" behaviour when nothing is
  configured.

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
- **CLI** — `argparse` interface with `-d`, `-iL`, `--nameserver`, `-c`, `--timeout`,
  `--ignore`, `--fail-under`, `--fail-on-severity`, `-oJ/-oS/-oM/-oH`, YAML config and
  a `rich` terminal report with severity badges and inline fixes.
- **Exporters** — JSON, SARIF 2.1.0 (GitHub Code Scanning with `security-severity` and
  stable `partialFingerprints`), Markdown and a self-contained HTML dashboard.
- **Packaging & CI** — `pyproject.toml` console scripts (`secaudit`, `domain-audit`),
  `requirements.txt`, multi-stage non-root `Dockerfile`, `.gitignore`, `.dockerignore`,
  sample GitHub Actions workflow with SARIF upload and artifact publishing.
- **Tests** — 163 tests (parsers, auditors with mocked HTTP/resolver and a local TLS
  server, scoring/gates, all exporters, CLI exit codes) plus ruff configuration.

[1.0.1]: https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor/releases/tag/v1.0.0

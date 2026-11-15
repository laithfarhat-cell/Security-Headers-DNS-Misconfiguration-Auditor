# secaudit — Security Headers & DNS Misconfiguration Auditor

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)](#requirements)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](#)
[![Tests](https://img.shields.io/badge/tests-175%20passing-brightgreen.svg)](#development)
[![Lint](https://img.shields.io/badge/lint-ruff%20clean-261230.svg)](https://docs.astral.sh/ruff/)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-purple.svg)](#sarif--github-code-scanning)
[![OWASP](https://img.shields.io/badge/OWASP-Secure%20Headers-000000?logo=owasp&logoColor=white)](https://owasp.org/www-project-secure-headers/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](#docker)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

> **One command to audit the security posture of a domain across HTTP headers, TLS and
> DNS/e-mail — with weighted grading, copy-pasteable fixes and a CI/CD quality gate.**

`secaudit` is an asynchronous, black-box auditor for the parts of an application's
security posture that are visible from the outside and most often forgotten:

- **HTTP security headers & cookies** — HSTS, CSP, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, cookie flags and
  RFC 9116 `security.txt`.
- **TLS & transport hygiene** — certificate expiry/chain/SANs, weak keys and signatures,
  TLS 1.0/1.1 support, cipher strength and the HTTP → HTTPS redirect.
- **DNS & e-mail misconfiguration** — SPF (including the RFC 7208 10-lookup budget),
  DMARC enforcement, CAA, DNSSEC and **dangling-CNAME / sub-domain takeover** detection
  against a local fingerprint database.

Every failed or warning finding ships with **copy-pasteable remediation** for Nginx,
Apache, Cloudflare and DNS, an overall **0–100 score with an A+ … F grade**, and a
`--fail-under` gate that exits `1` so a pipeline can block the release.

---

## Table of contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [CLI reference](#cli-reference)
- [What gets audited](#what-gets-audited)
- [Scoring & grading](#scoring--grading)
- [Remediation snippets](#remediation-snippets)
- [Report formats](#report-formats)
- [CI/CD integration](#cicd-integration)
- [SARIF & GitHub Code Scanning](#sarif--github-code-scanning)
- [Configuration](#configuration)
- [Docker](#docker)
- [Project layout](#project-layout)
- [Development](#development)
- [Design notes & limitations](#design-notes--limitations)
- [License](#license)

---

## Quick start

### Install

```bash
# from a clone
git clone https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor.git
cd Security-Headers-DNS-Misconfiguration-Auditor
python -m pip install .

# or just the dependencies, then run the CLI directly
python -m pip install -r requirements.txt
python main.py -d example.com
```

`pip install .` registers two identical console scripts: **`secaudit`** and
**`domain-audit`**.

> **Requirements:** Python 3.10+, ~15 MB of dependencies
> ([`httpx`](https://www.python-httpx.org/), [`dnspython`](https://www.dnspython.org/),
> [`cryptography`](https://cryptography.io/), [`PyYAML`](https://pyyaml.org/),
> [`rich`](https://rich.readthedocs.io/)).

### Audit a domain

```bash
secaudit -d example.com
```

### Audit a fleet and export every format

```bash
cat > domains.txt <<'EOF'
example.com
www.example.com
api.example.com   # comments and blank lines are ignored
EOF

secaudit -iL domains.txt \
  --nameserver 1.1.1.1 --nameserver 8.8.8.8 \
  -c 20 --fail-under 85 \
  -oJ reports/audit.json \
  -oS reports/secaudit.sarif \
  -oM reports/audit.md \
  -oH reports/audit.html
echo "exit code: $?"     # 1 when the posture is below the gate
```

### Sample terminal output

```text
╭──────────────────────────────────────── secaudit v1.0.1 ─────────────────────────────────────────╮
│  Security Headers · TLS · DNS/E-mail posture auditor                                             │
│  1 target(s) · OWASP Secure Headers · RFC 9116 · RFC 7208 · RFC 7489 · RFC 8659 · RFC 8461       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────── Overall posture ─────────────────────────────────────────╮
│  SCORE   GRADE   CRITICAL   HIGH   MEDIUM   LOW                                                   │
│  66.4      D        1        3       4       5                                                   │
│                                                                                                  │
│    QUALITY GATE FAILED                                                                           │
│    • overall score 66.4 is below --fail-under 85.0                                               │
│    • 1 finding(s) at or above CRITICAL severity                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

Targets ────────────────────────────────────────────────────────────────────────────────────────────
Target                  Grade        Score     HTTP    TLS    DNS    Crit    High    Med    Low
────────────────────────────────────────────────────────────────────────────────────────────────────
example.com               D           66.4       70     78     52       1       3      4      5

example.com  D  66.4/100  ·  1.9s ──────────────────────────────────────────────────────────────────
  https://example.com/ · HTTP 200 · cert until 2026-12-08
  HTTP Headers 70  TLS 78  DNS / Email 52
             Finding                                                Observed
────────────────────────────────────────────────────────────────────────────────────────────────────
 CRITICAL    Dangling CNAME to a non-existent host (GitHub Pages)   status.example.com CNAME
             dns.cname.dangling                                     status-old.github.io → NXDOMAIN
 HIGH        SPF exceeds the 10-lookup limit (12)                   12 lookups: include:_spf.google.com; …
             dns.spf.lookups
 HIGH        Cookies are missing the Secure flag                     1/3 cookie(s) without Secure: cart
             http.cookies.secure
 HIGH        Deprecated TLSv1.0 is supported                         TLSv1.0: accepted
             tls.protocol.tls1_0
 MEDIUM      DMARC policy is monitor-only (p=none)                   v=DMARC1; p=none; …
             dns.dmarc.policy
```

A complete, browsable example is committed at
[`docs/samples/sample-report.html`](docs/samples/sample-report.html) (plus
[`.json`](docs/samples/sample-report.json), [`.sarif`](docs/samples/sample-report.sarif) and
[`.md`](docs/samples/sample-report.md)) — regenerate it with
`python scripts/generate_samples.py`.

---

## How it works

```text
                     ┌──────────────────────────────────────────────────────────┐
  targets            │              asyncio orchestrator (main.py)              │
  -d / -iL  ────────▶│  Semaphore(concurrency) · one shared httpx.AsyncClient   │
  positional         └───────────┬──────────────────┬──────────────────┬────────┘
                                 │                  │                  │
                   ┌─────────────▼──────┐ ┌─────────▼──────────┐ ┌─────▼──────────────┐
                   │ http_auditor.py    │ │ tls_auditor.py     │ │ dns_auditor.py     │
                   │ ─────────────────  │ │ ─────────────────  │ │ ─────────────────  │
                   │ redirect chain     │ │ x509 via           │ │ SPF · DMARC · CAA  │
                   │ HSTS · CSP · COOP  │ │  cryptography      │ │ DNSSEC · MTA-STS   │
                   │ cookie flags       │ │ expiry · SAN · key │ │ 10-lookup budget   │
                   │ security.txt       │ │ TLS 1.0/1.1 probe  │ │ dangling CNAMEs    │
                   └─────────┬──────────┘ └─────────┬──────────┘ └─────┬──────────────┘
                             │  findings (Severity + Status + weight)  │
                             └───────────────┬─────────────────────────┘
                                             ▼
                          ┌───────────────────────────────────────┐   data/
                          │ core/scorer.py                        │◀── dangling_cnames.json
                          │ weighted score · grade · remediation  │     (33 SaaS fingerprints)
                          └───────────────┬───────────────────────┘
                                          ▼
        ┌──────────────┬──────────────────┬──────────────────┬──────────────────┐
        │ rich console │ JSON             │ SARIF 2.1.0      │ Markdown / HTML  │
        │ (colour UI)  │ (full evidence)  │ (Code Scanning)  │ (PRs, tickets)   │
        └──────────────┴──────────────────┴──────────────────┴──────────────────┘
                                          ▼
                              exit 0 ✅ / exit 1 ❌ (--fail-under)
```

Every target runs its three auditors **concurrently**; independent targets run in
parallel behind a semaphore, and DNS lookups inside a target are issued together.
Protocol probes (TLS 1.0 → 1.3) also run concurrently, so a full target usually
completes in 1–3 seconds.

All findings flow through one model (`core/models.py`), so the terminal, JSON, SARIF,
Markdown and HTML outputs never disagree about a score or a fix.

---

## CLI reference

| Flag | Default | Description |
|:--|:--|:--|
| `-d`, `--domain DOMAIN` | — | Domain to audit. Repeat for several targets. |
| `-iL`, `--input-list FILE` | — | File with one domain per line (`-` reads stdin). `#` comments and blank lines are ignored. |
| `[DOMAIN …]` | — | Positional targets, equivalent to `-d`. |
| `--nameserver IP[:PORT]` | system resolver | Custom recursive resolver. Repeatable; accepts `1.1.1.1`, `1.1.1.1@5353`, `dns.google`, comma-separated lists. |
| `-c`, `--concurrency N` | `10` | Number of targets audited in parallel. |
| `--timeout SECONDS` | `10` | Per-request and per-DNS-query timeout. |
| `--user-agent STRING` | `secaudit/1.0 (+url)` | User-Agent used for HTTP probes. |
| `--ignore CHECK_ID` | — | Exclude a check (or prefix) from the score, e.g. `--ignore dns.mta_sts`. Repeatable. |
| `--fail-under SCORE` | none | CI gate: exit `1` when the overall **or any target** score is below `SCORE`. |
| `--fail-on-severity {critical,high,medium,low,none}` | none | CI gate: exit `1` when any finding at/above that severity exists. |
| `-oJ`, `--json FILE` | — | Write the JSON report (`-` = stdout). |
| `-oS`, `--sarif FILE` | — | Write a SARIF 2.1.0 log for GitHub Code Scanning. |
| `-oM`, `--markdown FILE` | — | Write the Markdown report. |
| `-oH`, `--html FILE` | — | Write a standalone HTML dashboard (no CDN/JS dependencies). |
| `--include-passed` | config (`true`) | Keep PASS findings in the JSON output. |
| `--config FILE` | `config/default.yaml` | YAML configuration (merged over the defaults). |
| `-v`, `--verbose` | off | Print evidence, references and remediation for every finding. |
| `-q`, `--quiet` | off | Suppress the terminal report (exports still run). |
| `--no-color` | off | Disable ANSI colours. |
| `--version` | — | Print the version and exit. |

**Exit codes:** `0` = gate passed, `1` = gate failed, `2` = usage/runtime error,
`130` = interrupted.

### Common recipes

```bash
# Only the things that actually break things, with fixes
secaudit -d example.com -v --fail-on-severity high

# Internal zone via a private resolver, no colour, JSON on stdout
secaudit -d intranet.corp --nameserver 10.0.0.53 -q -oJ - | jq '.summary'

# Weekly CI audit, ignore a noisy control, break the build below B-
secaudit -iL domains.txt -c 25 --ignore dns.mta_sts --ignore http.header.x_powered_by \
         --fail-under 80 -oS secaudit.sarif -oH audit.html
```

---

## What gets audited

### HTTP security headers & cookies (`auditors/http_auditor.py`)

| Control | What is verified | Weight |
|:--|:--|--:|
| `Strict-Transport-Security` | presence, numeric `max-age ≥ 31536000`, `includeSubDomains`, `preload`, `max-age=0` | 10 + 9 + 3 + 1.5 |
| `Content-Security-Policy` | enforced vs **report-only**, `default-src`, `unsafe-inline`, `unsafe-eval`, wildcard/`data:`/scheme-only sources, plaintext `http:`, `frame-ancestors`, `base-uri`, `object-src` | 26 |
| `X-Content-Type-Options` | `nosniff` present and exact | 6 |
| `X-Frame-Options` | `DENY`/`SAMEORIGIN`, deprecated `ALLOW-FROM`, CSP `frame-ancestors` supersession | 5 |
| `Referrer-Policy` | presence, unsafe values (`unsafe-url`, `no-referrer-when-downgrade`), unknown tokens | 6 |
| `Permissions-Policy` | presence, sensitive features delegated to `*`, legacy `Feature-Policy` | 5 |
| `Cross-Origin-Opener-Policy` | `same-origin` vs `unsafe-none`/missing | 4 |
| `Cross-Origin-Resource-Policy` | missing / `same-origin` / `same-site` | 2 |
| `Set-Cookie` (whole chain) | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure`, `__Host-`/`__Secure-` prefix contracts, >1 year lifetime | 20 |
| Technology disclosure | `Server` (version banner), `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Debug-Token`, `Via`, … | 6 |
| `/.well-known/security.txt` | RFC 9116: `Contact`, `Expires` (valid, in the future), `Canonical`, `text/plain`, plaintext contacts | 4 |

The auditor follows redirects **manually**, records every hop and collects
`Set-Cookie` headers from the whole chain (not just the final response).

### TLS & transport hygiene (`auditors/tls_auditor.py`)

| Control | What is verified | Weight |
|:--|:--|--:|
| Chain validation | leaf → trusted root, hostname match, full-chain errors surfaced as findings | 10 |
| Certificate expiry | expired / < 7 days / < 30 days countdown, issuer, serial, SAN list | 9 |
| Self-signed leaf | issuer == subject | 6 |
| SAN coverage | every audited hostname (and IP SANs) present | 4 |
| Key & signature | RSA ≥ 2048, EC ≥ P-256, MD5/SHA-1 signatures rejected | 4 |
| Protocol support | live probes for TLS 1.0 / 1.1 (RFC 8996), 1.2, 1.3 | 12 |
| Negotiated cipher | AEAD/forward secrecy, ≥ 128-bit, no RC4/3DES/NULL/EXPORT | 3 |
| HTTP → HTTPS | port 80 must redirect (301/308) to HTTPS, serve nothing, or be closed | 6 |

Certificates are parsed from DER with `cryptography`, so an invalid chain still
produces a full certificate report (issuer, SANs, expiry) instead of aborting.

### DNS & e-mail security (`auditors/dns_auditor.py`)

| Control | What is verified | Weight |
|:--|:--|--:|
| Resolution | A/AAAA/CNAME present | 10 |
| SPF (RFC 7208) | exactly one `v=spf1`, `+all`/`?all`/`~all`/`-all`, deprecated `ptr`, **recursive lookup budget** (includes/redirects counted up to depth 5) against 10 | 23 |
| DMARC (RFC 7489) | presence at `_dmarc.<domain>`, inheritance from the organisational domain, `p=none/quarantine/reject`, duplicate records, `rua`, `ruf`, `pct`, weaker `sp=` | 24.5 |
| CAA (RFC 8659) | issuance restrictions, `issuewild`, parent-domain inheritance, unknown critical tags, `iodef` | 7 |
| DNSSEC | `DNSKEY` + `DS` present, missing DS (island of trust), DS without DNSKEY (**bogus** → SERVFAIL) | 4 |
| Dangling CNAMEs | every hop matched against `data/dangling_cnames.json`, target resolution checked, optional HTTP probe for the provider's "unclaimed" page | 10 + 6 + 2 |
| MTA-STS / TLS-RPT | `_mta-sts` `v=STSv1`, `_smtp._tls` `v=TLSRPTv1` (informational) | 2 |

**Sub-domain takeover detection.** The fingerprint database covers 33 providers
(GitHub Pages, Amazon S3, Heroku, Azure, Shopify, Fastly, Netlify, Vercel, Surge,
Pantheon, Zendesk, Freshdesk, Unbounce, Readme.io, GCS, Firebase, DigitalOcean, …).
A CNAME is flagged **critical** when the target does not resolve *or* when the
provider answers with its known "unclaimed site" signature, and **high** when the
target resolves but belongs to a claimable provider namespace. Add your own
services by extending the JSON — no code changes required:

```json
{
  "service": "Acme Static Host",
  "provider": "Acme",
  "cname_suffixes": ["acme-cdn.net"],
  "claim_url": "https://console.acme.example/claim",
  "severity": "high",
  "unclaimed_signatures": ["This Acme site is not published"],
  "notes": "Re-claim the site name or delete the DNS record."
}
```

---

## Scoring & grading

Each check carries a **weight** inside its category. A check that passes credits the
full weight, a warning credits 40 %, a failure credits nothing:

```text
category_score = 100 × Σ(weightᵢ × factorᵢ) / Σ(weightᵢ)      factor: PASS 1.0 · WARN 0.4 · FAIL 0.0

overall_score  = Σ(category_score × category_weight) / Σ(category_weight)
                 HTTP Headers 45 %  ·  TLS 25 %  ·  DNS / E-mail 30 %
```

Because weights are normalised, a category is always in `0–100`, adding checks does
not silently reshape the grade, and a target that cannot be reached (weight 0 for a
category) is renormalised instead of dragging the score to zero.

| Score | 97+ | 93+ | 90+ | 87+ | 83+ | 80+ | 77+ | 73+ | 70+ | 67+ | 63+ | 60+ | < 60 |
|:--|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Grade** | A+ | A | A- | B+ | B | B- | C+ | C | C- | D+ | D | D- | F |

Severities are independent of scoring and drive the UI/CI gates:
`CRITICAL` (exploitable now — takeover, `+all`, expired cert) → `HIGH` → `MEDIUM` →
`LOW` → `INFO` → `PASS`.

**Quality gate.** `--fail-under N` fails when the *overall* score **or any single
target** falls below `N`; `--fail-on-severity critical` fails on the presence of a
critical finding regardless of score. Both can be combined:

```bash
secaudit -iL domains.txt --fail-under 85 --fail-on-severity critical -oS reports/audit.sarif
# → exit 1 with a reason list on stdout when either gate trips
```

Gross grading details are deliberately transparent: every point of the score maps to
a named check with a weight, and the JSON/Markdown reports show the per-category
breakdown plus every individual weighted finding.

---

## Remediation snippets

Every `FAIL` and `WARN` finding is rendered with the platform-appropriate fix. Examples
from `core/scorer.py`:

**HSTS** — `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`

**CSP (Nginx)**

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; \
style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; \
upgrade-insecure-requests" always;
```

**Cookies (Apache)**

```apache
Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
```

**DMARC (DNS)**

```dns
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; fo=1; rua=mailto:dmarc-reports@example.com"
```

**SPF (DNS)**

```dns
example.com.        TXT  "v=spf1 mx include:_spf.example-provider.com -all"
mail.example.com.   TXT  "v=spf1 include:_spf.example-provider.com -all"
```

The catalogue also covers `Permissions-Policy`, COOP/CORP, `security.txt`, TLS
protocols/ciphers/renewal, CAA, DNSSEC (DS records + registrar steps), MTA-STS and
dangling CNAME removal — 29 templates in total, each with a `reference` link.

---

## Report formats

| Format | Flag | Use it for |
|:--|:--|:--|
| JSON | `-oJ` | Automation, dashboards, diffing posture over time (full evidence + remediation) |
| SARIF 2.1.0 | `-oS` | GitHub Code Scanning / Security tab, Azure DevOps, IDE integrations |
| Markdown | `-oM` | PR comments, wikis, ticket attachments, `$GITHUB_STEP_SUMMARY` |
| HTML | `-oH` | A self-contained dashboard you can email or publish as an artifact |
| Terminal | (default) | Fast feedback while iterating, with `rich` severity badges |

### JSON

```json
{
  "schema_version": "1.0",
  "tool": { "name": "secaudit", "version": "1.0.1" },
  "summary": { "targets": 1, "overall_score": 66.44, "grade": "D",
               "counts": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 4, "LOW": 5, "PASS": 16 } },
  "gate": { "fail_under": 85.0, "fail_on_severity": "critical",
            "passed": false, "reasons": ["…"] },
  "results": [
    {
      "target": "example.com",
      "score": 66.44,
      "grade": "D",
      "category_scores": { "http_headers": 69.7, "tls": 77.6, "dns_email": 52.2 },
      "findings": [
        {
          "check_id": "dns.cname.dangling",
          "severity": "CRITICAL",
          "status": "fail",
          "evidence": "status.example.com CNAME status-old.github.io → NXDOMAIN",
          "remediation": { "summary": "…", "dns": "…", "nginx": null, "reference": "…" }
        }
      ],
      "sections": { "http_headers": { "data": { "headers": { } } }, "tls": { }, "dns_email": { } }
    }
  ]
}
```

### Markdown preview

```markdown
## Summary
| Target | Grade | Score | HTTP | TLS | DNS/Email | Critical | High | Medium | Low |
|:--|:--:|--:|--:|--:|--:|--:|--:|--:|--:|
| example.com | **D** | 66.4 | 69.7 | 77.6 | 52.2 | 1 | 3 | 4 | 5 |

#### CRITICAL · Dangling CNAME to a non-existent host (GitHub Pages)
`dns.cname.dangling` · DNS / Email · status `fail`
…
<details><summary>🔧 Remediation</summary>
**Cloudflare** → DNS → Records → delete or repoint the dangling CNAME
</details>
```

### HTML preview

The standalone dashboard bundles its own CSS and ~20 lines of JavaScript (severity
filter). No CDN, no external fonts, no telemetry — it works offline and inside
air-gapped artifacts.

Open [`docs/samples/sample-report.html`](docs/samples/sample-report.html) to browse
the generated example (score ring, grade badge, per-target cards, colour-coded
severity badges, collapsible evidence and remediation tabs for Nginx/Apache/
Cloudflare/DNS).

---

## CI/CD integration

### GitHub Actions

A ready-to-use workflow lives at
[`.github/workflows/domain-audit.yml`](.github/workflows/domain-audit.yml):

- runs **weekly** (Mondays 04:17 UTC) and on demand, with optional comma-separated
  domains as a `workflow_dispatch` input;
- lints and unit-tests the tool on every push and pull request;
- resolves the target list in a separate `preflight` job and **skips the audit with
  a notice** when no domains are configured, so a fresh clone is green out of the box;
- publishes SARIF to the **Security → Code scanning** tab;
- renders the Markdown report into the job summary;
- uploads all four report formats as a 30-day artifact;
- fails the job when `--fail-under` / `--fail-on-severity` trip.

**1 — Provide targets.** Copy the template and list the domains you own:

```bash
cp domains.example.txt domains.txt   # one domain per line; # comments allowed
```

`domains.txt` may also be passed ad-hoc from the *Run workflow* button
(`domains` input). Commit it if you want the push-triggered audit, or keep it
local and rely on the weekly schedule / dispatch input instead. Blank lines,
CRLF endings, inline `#` comments, full URLs and duplicates are normalised
automatically, so a hand-maintained list works as-is.

**2 — Tune the gate.** Instead of editing the workflow, set repository variables
(*Settings → Secrets and variables → Actions → Variables*):

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUDIT_FAIL_UNDER` | `85` | minimum overall score; `0` disables the score gate |
| `AUDIT_FAIL_ON_SEVERITY` | `critical` | `critical`, `high`, `medium`, `low` or `none` |

Workflow-dispatch inputs always win over the repository variables.

**3 — Read the result.** Exit code `0` = gate satisfied, `1` = gate tripped
(build fails, reports still uploaded), `2` = usage error. When no targets are
configured the run reports `⏭️ Domain audit skipped` in the job summary and the
workflow stays green.

```yaml
- name: Run audit
  run: |
    secaudit -iL domains.txt --nameserver 1.1.1.1 -c 15 \
      --fail-under 85 --fail-on-severity critical \
      -oJ reports/audit.json -oS reports/secaudit.sarif \
      -oM reports/audit.md -oH reports/audit.html
```

Required permission for the upload:

```yaml
permissions:
  contents: read
  security-events: write
```

### Any other CI

```yaml
# GitLab CI
security-headers:
  image: python:3.12-slim
  script:
    - pip install .
    - secaudit -iL domains.txt --fail-under 85 -oM gl-dependency-scanning.md -oS gl-sast-report.sarif
  artifacts:
    when: always
    paths: [gl-dependency-scanning.md, gl-sast-report.sarif]
  allow_failure: false
```

```groovy
// Jenkins
sh 'secaudit -d example.com --fail-under 85 -oH reports/audit.html'
archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
```

---

## SARIF & GitHub Code Scanning

`-oS` writes SARIF 2.1.0 with:

- one **rule per check id** (`http.hsts.missing`, `dns.dmarc.policy`, …) including
  `shortDescription`, `fullDescription`, Markdown `help` with the remediation
  snippets, `helpUri` and GitHub's `security-severity` property;
- one **result per FAIL/WARN finding** with `level` (`error` for critical/high,
  `warning` for medium, `note` for low), the affected URL as `artifactLocation`,
  and a stable `partialFingerprints` hash so alerts are de-duplicated across runs
  instead of re-opened every week;
- run-level `properties` with the overall score, grade and gate outcome.

Uploading it makes findings appear as normal code-scanning alerts, complete with the
fix snippets, and lets you set branch-protection rules like *"require code scanning
results"* to enforce a minimum posture before merging.

---

## Configuration

Defaults live in [`config/default.yaml`](config/default.yaml) and are merged with
whatever you pass via `--config`:

```yaml
scan:
  concurrency: 10
  timeout: 10.0
  max_redirects: 10
  verify_tls: true          # certificate validation for HTTP probes
  user_agent: "secaudit/1.0 (+https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor)"
  http_port: 80
  https_port: 443

scoring:
  category_weights:         # normalised, any positive numbers
    http_headers: 45
    tls: 25
    dns_email: 30
  fail_under: 85            # default gate (--fail-under overrides)
  fail_on_severity: high    # default gate (--fail-on-severity overrides)
  ignore_checks:            # drop noisy controls from the score
    - http.header.x_powered_by
    - dns.mta_sts

http:
  check_security_txt: true
  hsts_min_max_age: 31536000
  check_cookies: true

dns:
  nameservers: ["1.1.1.1", "8.8.8.8"]
  fingerprints_file: dangling_cnames.json
  spf_lookup_limit: 10
  probe_subdomains: [www, blog, status, dev]   # extra names checked for dangling CNAMEs

reporting:
  remediation_min_severity: HIGH   # show fixes by default for HIGH and above
  include_passed_in_json: true
```

> Config values are the defaults for the CLI flags — flags always win.

---

## Docker

```bash
docker build -t secaudit .

# quick single target (needs network access)
docker run --rm secaudit -d example.com

# bulk audit with reports persisted on the host
docker run --rm -v "$PWD/reports:/reports" secaudit \
  -iL /reports/domains.txt --fail-under 85 \
  -oJ /reports/audit.json -oS /reports/audit.sarif \
  -oM /reports/audit.md -oH /reports/audit.html

# keep a custom configuration and resolver
docker run --rm -v "$PWD/myconfig.yaml:/cfg.yaml:ro" secaudit \
  -d example.com --config /cfg.yaml --nameserver 10.0.0.53
```

The image is a slim multi-stage build (wheels compiled in the builder stage),
runs as UID `10001`, ships `ca-certificates` for certificate validation and
installs the package with its `secaudit` entry point.

---

## Project layout

```text
.
├── main.py                     # async CLI, rich terminal UI, exit codes
├── pyproject.toml              # setuptools build, console_scripts, ruff/pytest config
├── requirements.txt
├── Dockerfile                  # multi-stage, non-root runtime
├── .github/workflows/
│   └── domain-audit.yml        # preflight + scheduled audit + SARIF upload + artifacts
├── domains.example.txt         # target-list template (copy to domains.txt)
├── auditors/
│   ├── http_auditor.py         # headers, CSP, cookies, security.txt, redirect chain
│   ├── tls_auditor.py          # certificate, protocols, cipher, HTTPS redirect
│   └── dns_auditor.py          # SPF, DMARC, CAA, DNSSEC, dangling CNAMEs
├── core/
│   ├── models.py               # Finding / SectionResult / TargetReport / AuditReport
│   ├── scorer.py               # weighted scoring, grading, remediation catalogue
│   └── config.py               # YAML defaults, deep-merge, resource discovery
├── reporters/
│   └── exporter.py             # JSON, SARIF 2.1.0, Markdown, standalone HTML
├── data/
│   └── dangling_cnames.json    # 33 takeover fingerprints (suffixes + signatures)
├── config/
│   └── default.yaml            # documented defaults
├── docs/samples/               # generated example reports (html/json/md/sarif)
├── scripts/generate_samples.py # regenerates docs/samples via the real exporters
└── tests/                      # 175 tests: parsers, auditors, scorer, exporters, CLI, workflow
```

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest -q            # 175 tests, ~1 s, no network required (MockTransport + stub resolver)
ruff check .         # lint (E, F, W, I, UP, B, C4)
python scripts/generate_samples.py   # refresh docs/samples/*
```

The test suite covers the pure parsers, the HTTP auditor through
`httpx.MockTransport`, the TLS auditor against a self-signed local server, the DNS
auditor through a stubbed zone, the scoring math and gate semantics, all four
exporters (including HTML escaping of hostile evidence) and the CLI exit codes.
A static test also walks the auditor AST to guarantee that every remediation key a
finding can reference exists in the catalogue.

### Extending

- **New check**: add a finding in the relevant auditor with a `check_id`, `weight`,
  `severity` and `remediation_key`; register the template in `core/scorer.py`.
- **New provider fingerprint**: append to `data/dangling_cnames.json`.
- **New output format**: implement `to_*`/`write_*` in `reporters/exporter.py` and
  expose it through the `Exporter.export` dispatcher.

---

## Design notes & limitations

- **Black-box by design.** The auditor only sees what an external client sees: no
  agent, no credentials, no origin access. Behind a CDN you are auditing the edge —
  which is the correct security boundary for these controls, but it means origin
  misconfigurations that the CDN masks will not be reported.
- **DNSSEC is checked for *presence*** of `DNSKEY`/`DS` and chain completeness. Full
  cryptographic validation would require a validating resolver and an AD-bit aware
  transport; use `dig +dnssec` or your resolvers' dashboards for that final step.
- **SPF lookup counting** is a best-effort recursive evaluation (depth ≤ 5). Macros
  containing runtime variables (`%{d}`, `%{l}`) cannot be fully expanded offline.
- **Certificate transparency, CAA enforcement and DMARC reporting** are out of scope;
  the tool reports configuration, not provider enforcement.
- **Scan only domains you own or are authorised to test.** Every check is a handful
  of HTTP requests and DNS lookups, but scanning third parties may violate their
  terms of service. The tool sends a transparent `secaudit/1.0` User-Agent and does
  not attempt exploitation, brute force or fuzzing.
- **Scores are guidance, not compliance certification.** They map to OWASP Secure
  Headers, RFC 9116, RFC 7208, RFC 7489, RFC 8659 and RFC 8461 best practice, but no
  auditor replaces a threat model.

---

## Contributing

Issues and PRs are welcome — especially new dangling-CNAME fingerprints (with a
reference), additional remediation templates and RFC edge cases. Please run
`pytest` and `ruff check .` before opening a PR.

## License

[MIT](LICENSE) © 2026 Laith Farhat

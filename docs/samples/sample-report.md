# 🛡️ Security Headers & DNS Misconfiguration Audit

**Generated:** 2026-11-15 20:24 UTC  
**Tool:** `secaudit` v1.0.0  
**Targets:** 1  
**Overall score:** **66.4/100** (grade **D**)

❌ Quality gate **failed** — overall score 66.4 is below --fail-under 85.0; example.com: score 66.4 is below --fail-under 85.0; 1 finding(s) at or above CRITICAL severity.

> Quality gate threshold: `--fail-under 85`

**Findings:** 1 critical · 3 high · 4 medium · 5 low · 16 passed

## Summary

| Target | Grade | Score | HTTP | TLS | DNS/Email | Critical | High | Medium | Low |
|:--|:--:|--:|--:|--:|--:|--:|--:|--:|--:|
| example.com | **D** | 66.4 | 69.7 | 77.6 | 52.2 | 1 | 3 | 4 | 5 |

## example.com — grade D (66.4/100)

| Attribute | Value |
|:--|:--|
| Final URL | `https://example.com/` |
| HTTP status | 200 |
| Redirects | 1 hop(s): http://example.com/ → https://example.com/ |
| Certificate | C=US, O=Let's Encrypt, CN=R11 |
| Valid until | 2026-12-08T08:14:59+00:00 (22.5 days) |
| SANs | example.com, www.example.com, api.example.com |
| SPF | `v=spf1 include:_spf.google.com include:mail.zendesk.com ~all` |
| DMARC | `v=DMARC1; p=none; rua=mailto:dmarc@example.com` |
| Category scores | HTTP Headers: 69.7 · TLS: 77.6 · DNS / Email: 52.2 |

### Findings (13)

#### CRITICAL · Dangling CNAME to a non-existent host (GitHub Pages)

`dns.cname.dangling` · DNS / Email · status `fail`

status.example.com is a CNAME to status-old.github.io, which does not resolve (NXDOMAIN). Whoever registers that endpoint inherits your hostname — remove or repoint the record.

**Observed:** `status.example.com CNAME status-old.github.io → NXDOMAIN`

<details><summary>🔧 Remediation</summary>

A CNAME points at a third-party endpoint that no longer exists — an attacker can often claim it and serve content on your domain.  Remove or repoint the record, or re-claim the service.

**Cloudflare**

```text
DNS → Records → delete or repoint the dangling CNAME, then purge the edge cache.
```

**DNS**

```dns
example.com.   IN CNAME   <active-provider-endpoint>
# or delete the record entirely:
# dig +short example.com CNAME  # confirm the chain is gone
```

Reference: <https://owasp.org/www-community/attacks/Subdomain_takeover>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### HIGH · SPF exceeds the 10-lookup limit (12)

`dns.spf.lookups` · DNS / Email · status `fail`

RFC 7208 caps a policy evaluation at 10 DNS lookups; exceeding it returns permerror and receivers ignore the record, re-enabling spoofing.

**Observed:** `12 lookups: include:_spf.google.com; include:mail.zendesk.com; …`

<details><summary>🔧 Remediation</summary>

Publish exactly one SPF record per domain, end it with -all (hard fail), keep the DNS-lookup count at or below 10 and remove deprecated mechanisms such as ptr.

**DNS**

```dns
example.com.        TXT  "v=spf1 mx include:_spf.example-provider.com -all"
# count lookups first:  https://www.kitterman.com/spf/validate.html
# >10 lookups? flatten includes or split transactional mail onto a subdomain:
mail.example.com.   TXT  "v=spf1 include:_spf.example-provider.com -all"
```

Reference: <https://www.rfc-editor.org/rfc/rfc7208>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### HIGH · Cookies are missing the Secure flag

`http.cookies.secure` · HTTP Headers · status `fail`

Cookies without Secure are transmitted over plaintext HTTP and can be captured by any on-path attacker. Session cookies must be Secure.

**Observed:** `1/3 cookie(s) without Secure: cart`

<details><summary>🔧 Remediation</summary>

Every session cookie needs Secure + HttpOnly + SameSite.  Use the __Host- prefix (requires Secure, Path=/ and no Domain attribute) for authentication cookies.

**Nginx**

```nginx
# nginx ≥ 1.19.3 – rewrite flags on all proxied cookies
proxy_cookie_flags ~ secure httponly samesite=strict;
```

**Apache**

```apache
# mod_headers – append the flags if missing
Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
```

**Cloudflare**

```text
Cloudflare cannot rewrite Set-Cookie; fix it at the origin or in the application framework.
```

Reference: <https://owasp.org/www-community/controls/SecureCookieAttribute>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### HIGH · Deprecated TLSv1.0 is supported

`tls.protocol.tls1_0` · TLS · status `fail`

TLSv1.0 is deprecated by RFC 8996 and vulnerable to a long list of downgrade and padding-oracle attacks. Disable it and require TLS 1.2+.

**Observed:** `TLSv1.0: accepted`

<details><summary>🔧 Remediation</summary>

Disable TLS 1.0 and TLS 1.1 (deprecated by RFC 8996) and allow only TLS 1.2/1.3 with modern cipher suites.

**Nginx**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
```

**Apache**

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
```

**Cloudflare**

```text
SSL/TLS → Edge Certificates → Minimum TLS Version: TLS 1.2 (or TLS 1.3).
```

Reference: <https://www.rfc-editor.org/rfc/rfc8996>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### MEDIUM · DMARC policy is monitor-only (p=none)

`dns.dmarc.policy` · DNS / Email · status `warn`

p=none requests reports but tells receivers to deliver failing mail, so spoofing still reaches inboxes. Move to quarantine then reject.

**Observed:** `v=DMARC1; p=none; rua=mailto:dmarc@example.com`

<details><summary>🔧 Remediation</summary>

Publish a DMARC record with p=quarantine or p=reject and rua reporting so you can detect spoofing attempts and receive aggregate reports.

**Cloudflare**

```text
Cloudflare Email Security / DNS → add the TXT record at _dmarc.example.com. Keep Email Routing's own SPF/DKIM records intact.
```

**DNS**

```dns
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; fo=1; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensics@example.com"
# rollout: start with p=none, review rua reports for 2-4 weeks, then move to p=quarantine and finally p=reject
```

Reference: <https://www.rfc-editor.org/rfc/rfc7489>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### MEDIUM · CSP allows 'unsafe-inline' for scripts

`http.csp.unsafe_inline` · HTTP Headers · status `warn`

'unsafe-inline' re-enables inline <script> execution, which neutralises most of CSP's XSS protection. Replace inline handlers with nonces or hashes.

**Observed:** `script-src 'self' 'unsafe-inline' https://cdn.example.net`

<details><summary>🔧 Remediation</summary>

Deploy a restrictive Content-Security-Policy built from a nonce or hash based script-src, drop 'unsafe-inline'/'unsafe-eval', and lock down framing with frame-ancestors.  Roll it out with Content-Security-Policy-Report-Only first.

**Nginx**

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests" always;
```

**Apache**

```apache
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
</IfModule>
```

**Cloudflare**

```text
Cloudflare does not synthesise a CSP. Inject it with a Transform Rule (Modify Response Header → Set → Content-Security-Policy) or at your origin.
```

Reference: <https://owasp.org/www-project-secure-headers/#content-security-policy>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### MEDIUM · HSTS max-age is shorter than 31536000 seconds

`http.hsts.max_age_short` · HTTP Headers · status `warn`

A short HSTS lifetime leaves visitors unprotected between policy expiry and renewal. Use at least one year (31536000).

**Observed:** `max-age=86400 (1.0 days)`

<details><summary>🔧 Remediation</summary>

Send Strict-Transport-Security on every HTTPS response with a max-age of at least one year, includeSubDomains and (once you are confident) preload. HSTS closes the SSL-stripping window for returning visitors.

**Nginx**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

**Apache**

```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
```

**Cloudflare**

```text
SSL/TLS → Edge Certificates → HSTS: enable, Max-Age 12 months, Include subdomains = On, Preload = On, No-Sniff header = On.
```

Reference: <https://owasp.org/www-project-secure-headers/#strict-transport-security>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### MEDIUM · TLS certificate expires in 22.5 days

`tls.expiry` · TLS · status `warn`

Certificates must be renewed before they expire; automate renewal and alert at 30 days.

**Observed:** `notAfter=2026-12-08 (22.5 days remaining)`

<details><summary>🔧 Remediation</summary>

Renew the leaf certificate before it expires and monitor the remaining lifetime (alert at 30 days, page at 14).  Automate renewal with ACME.

**Nginx**

```nginx
# certbot
certbot renew --quiet --deploy-hook "nginx -s reload"
# cron: 0 3 * * * certbot renew --quiet --deploy-hook "systemctl reload nginx"
```

**Apache**

```apache
certbot renew --quiet --deploy-hook "systemctl reload apache2"
```

**Cloudflare**

```text
Cloudflare managed certificates renew automatically – verify Edge Certificates shows an active cert.
```

Reference: <https://letsencrypt.org/docs/renewal-reminder/>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### LOW · DNSSEC is not enabled

`dns.dnssec.missing` · DNS / Email · status `warn`

Unsigned zones are vulnerable to cache-poisoning and forged DNS answers on the resolution path.

**Observed:** `DNSKEY: none; DS: none`

<details><summary>🔧 Remediation</summary>

Enable DNSSEC so resolvers can cryptographically validate your zone: publish DNSKEY/RRSIG in the zone and the matching DS record at the registrar/parent.

**Cloudflare**

```text
DNS → Settings → DNSSEC → Enable DNSSEC, then add the DS record at your registrar.
```

**DNS**

```dns
# after enabling DNSSEC at the provider, publish the DS record at the parent:
example.com.  IN DS  <keytag> <algorithm> <digest-type> <digest>
# verify:  dig +dnssec DNSKEY example.com  /  dig +trace DS example.com
```

Reference: <https://www.rfc-editor.org/rfc/rfc4033>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### LOW · SPF policy soft-fails (~all)

`dns.spf.all` · DNS / Email · status `warn`

SoftFail lets receivers accept the message but mark it as suspicious; move to -all once all legitimate senders are listed.

**Observed:** `v=spf1 include:_spf.google.com include:mail.zendesk.com ~all`

<details><summary>🔧 Remediation</summary>

Publish exactly one SPF record per domain, end it with -all (hard fail), keep the DNS-lookup count at or below 10 and remove deprecated mechanisms such as ptr.

**DNS**

```dns
example.com.        TXT  "v=spf1 mx include:_spf.example-provider.com -all"
# count lookups first:  https://www.kitterman.com/spf/validate.html
# >10 lookups? flatten includes or split transactional mail onto a subdomain:
mail.example.com.   TXT  "v=spf1 include:_spf.example-provider.com -all"
```

Reference: <https://www.rfc-editor.org/rfc/rfc7208>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### LOW · Server header discloses software version

`http.header.server` · HTTP Headers · status `warn`

Version banners let attackers map the target to known CVEs; hide the token and patch promptly.

**Observed:** `Server: nginx/1.18.0`

<details><summary>🔧 Remediation</summary>

Remove version banners from Server, X-Powered-By and X-AspNet-Version.  Banner grabbing is the first step of most targeted exploitation playbooks.

**Nginx**

```nginx
# nginx.conf (http block)
server_tokens off;
more_clear_headers Server X-Powered-By X-AspNet-Version X-AspNetMvc-Version;  # headers-more module
# without headers-more:
proxy_hide_header X-Powered-By;
```

**Apache**

```apache
ServerTokens Prod
ServerSignature Off
<IfModule mod_headers.c>
    Header unset X-Powered-By
    Header unset X-AspNet-Version
    Header unset Server
</IfModule>
```

**Cloudflare**

```text
Cloudflare already strips/rewrites the Server header; add Transform Rules for X-Powered-By.
```

Reference: <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### LOW · HSTS includeSubDomains is missing

`http.hsts.include_subdomains` · HTTP Headers · status `warn`

includeSubDomains prevents attackers from downgrading any sub-domain, including forgotten staging hosts.

**Observed:** `max-age=86400`

<details><summary>🔧 Remediation</summary>

Send Strict-Transport-Security on every HTTPS response with a max-age of at least one year, includeSubDomains and (once you are confident) preload. HSTS closes the SSL-stripping window for returning visitors.

**Nginx**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

**Apache**

```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
```

**Cloudflare**

```text
SSL/TLS → Edge Certificates → HSTS: enable, Max-Age 12 months, Include subdomains = On, Preload = On, No-Sniff header = On.
```

Reference: <https://owasp.org/www-project-secure-headers/#strict-transport-security>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

#### LOW · Permissions-Policy header is missing

`http.permissions_policy.missing` · HTTP Headers · status `warn`

Without Permissions-Policy, embedded third-party frames may request camera, microphone, geolocation and other powerful features.

**Observed:** `Permissions-Policy: absent`

<details><summary>🔧 Remediation</summary>

Restrict powerful browser features with Permissions-Policy.  Deny everything you do not explicitly need and never grant camera/microphone/geolocation to '*'.

**Nginx**

```nginx
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
```

**Apache**

```apache
Header always set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
```

**Cloudflare**

```text
Transform Rule → Set response header Permissions-Policy with an explicit allow-list.
```

Reference: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy>

</details>

References: <https://owasp.org/www-project-secure-headers/>

---

<details><summary>✅ Checks that passed / informational (17)</summary>

- `dns.mta_sts.missing` — MTA-STS is not configured (`TXT _mta-sts.example.com: none`)
- `dns.caa.present` — CAA records restrict certificate issuance (`0 issue "letsencrypt.org"; 0 iodef "mailto:security@example.com"`)
- `dns.dmarc.present` — DMARC record is published (`v=DMARC1; p=none; rua=mailto:dmarc@example.com`)
- `dns.spf.present` — SPF record is published (`v=spf1 include:_spf.google.com include:mail.zendesk.com ~all`)
- `http.cookies.httponly` — All cookies carry the HttpOnly flag (`3 cookie(s) verified`)
- `http.coop.present` — Cross-Origin-Opener-Policy: same-origin is set (`same-origin`)
- `http.csp.present` — Content-Security-Policy is enforced (`default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.net`)
- `http.referrer_policy.valid` — Referrer-Policy restricts referrer leakage (`strict-origin-when-cross-origin`)
- `http.security_txt.valid` — security.txt is published and RFC 9116 compliant (`1 contact(s), expires 2027-06-01T00:00:00.000Z`)
- `http.x_content_type_options.nosniff` — X-Content-Type-Options: nosniff is set (`nosniff`)
- `http.x_frame_options.valid` — X-Frame-Options: SAMEORIGIN is set (`SAMEORIGIN`)
- `tls.certificate_san` — Certificate covers example.com (`SAN: example.com, www.example.com, api.example.com`)
- `tls.cipher` — Negotiated cipher suite is strong (`TLS_AES_256_GCM_SHA384 (256 bits, TLSv1.3)`)
- `tls.https_redirect` — Plaintext HTTP redirects to HTTPS (`HTTP 301 → https://example.com/`)
- `tls.protocol.tls13` — TLS 1.3 is enabled (`TLSv1.3: accepted`)
- `tls.protocol.tls1_1` — Deprecated TLSv1.1 is disabled (`TLSv1.1: rejected`)
- `tls.trust` — TLS certificate chain validates against the system trust store (`issuer: C=US, O=Let's Encrypt, CN=R11`)

</details>

---

<sub>Generated by [secaudit](https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor) — an OWASP Secure Headers, TLS and DNS/e-mail auditing tool.</sub>

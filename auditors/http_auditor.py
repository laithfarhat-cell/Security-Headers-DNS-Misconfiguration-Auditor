"""HTTP security-header, cookie and security.txt auditor.

The auditor follows the redirect chain manually so the full chain (and every
``Set-Cookie`` seen along the way) can be reported, then evaluates the final
HTTPS response against the OWASP Secure Headers Project guidance.

Public helpers (:func:`parse_hsts`, :func:`parse_csp`, :func:`parse_set_cookie`,
:func:`parse_security_txt`) are deliberately pure functions so they can be unit
tested without a network or an event loop.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import httpx

from core.models import Category, Finding, SectionResult, Severity, Status

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------
MAX_SECURITY_TXT_BYTES = 64 * 1024
MAX_EVIDENCE_CHARS = 300

#: Values that fail to protect users even though the header is present.
UNSAFE_REFERRER_POLICIES = {
    "unsafe-url",
    "no-referrer-when-downgrade",
    "origin-when-cross-origin",
}
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
}
DEPRECATED_REFERRER_POLICIES = {"never", "default", "origin-when-cross-origin"}

#: Features that must never be delegated to every origin.
SENSITIVE_PERMISSIONS = {
    "camera",
    "microphone",
    "geolocation",
    "display-capture",
    "screen-wake-lock",
    "usb",
    "serial",
    "hid",
    "bluetooth",
    "payment",
    "idle-detection",
}

#: Headers that leak stack/version information.
DISCLOSURE_HEADERS = {
    "x-powered-by": ("X-Powered-By", 2.0, Severity.LOW),
    "x-aspnet-version": ("X-AspNet-Version", 2.0, Severity.LOW),
    "x-aspnetmvc-version": ("X-AspNetMvc-Version", 2.0, Severity.LOW),
    "x-generator": ("X-Generator", 1.0, Severity.INFO),
    "x-drupal-cache": ("X-Drupal-Cache", 1.0, Severity.INFO),
    "x-debug-token": ("X-Debug-Token", 2.0, Severity.LOW),
    "x-backend-server": ("X-Backend-Server", 1.5, Severity.LOW),
    "via": ("Via", 1.0, Severity.INFO),
    "x-served-by": ("X-Served-By", 0.5, Severity.INFO),
    "x-cache": ("X-Cache", 0.5, Severity.INFO),
}

_VERSION_RE = re.compile(r"\d+\.\d+")
_SAFE_HEADER_NAME = re.compile(r"^[a-z0-9!$%&'*+\-.^_`|~]+$")


# --------------------------------------------------------------------------------------
# Target handling
# --------------------------------------------------------------------------------------
def normalise_target(target: str) -> tuple[str, str]:
    """Return ``(host, https_url)`` for a user supplied target.

    ``example.com``, ``https://example.com/app?x=1`` and ``HTTP://Example.COM:80``
    all yield a usable host plus a URL to start the audit from.
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = "https://" + raw
    url = httpx.URL(raw)
    host = url.host
    if not host:
        raise ValueError(f"could not parse a hostname from {target!r}")
    host = host.rstrip(".").lower()
    # Strip default ports from the displayed host.
    port = url.port
    if port in (80, 443):
        port = None
    # Keep an explicitly requested scheme, otherwise always start on HTTPS.
    scheme = "http" if url.scheme == "http" else "https"
    netloc = host if port is None else f"{host}:{port}"
    path = url.path or "/"
    query = f"?{url.query.decode()}" if url.query else ""
    return host, f"{scheme}://{netloc}{path}{query}"


def _shorten(value: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


# --------------------------------------------------------------------------------------
# Pure parsers
# --------------------------------------------------------------------------------------
def parse_hsts(*values: str) -> dict[str, Any]:
    """Parse one or more ``Strict-Transport-Security`` header values.

    Returns a dict with ``max_age`` (int or ``None``), ``include_subdomains``,
    ``preload`` and the raw ``directives`` mapping.
    """
    directives: dict[str, str] = {}
    for value in values:
        for chunk in str(value).split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            key, _, val = chunk.partition("=")
            directives[key.strip().lower()] = val.strip().strip('"')
    max_age: int | None = None
    if "max-age" in directives:
        raw = directives["max-age"]
        if re.fullmatch(r"\d+", raw):
            max_age = int(raw)
    return {
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in directives,
        "preload": "preload" in directives,
        "directives": directives,
        "raw": "; ".join(str(v) for v in values if v),
    }


def parse_csp(*values: str) -> dict[str, list[str]]:
    """Parse one or more CSP headers into ``{directive: [sources]}``.

    Multiple headers are merged (browsers enforce the intersection, but for
    auditing purposes the union of the directives is what matters).
    """
    parsed: dict[str, list[str]] = {}
    for value in values:
        for directive in str(value).split(";"):
            tokens = directive.split()
            if not tokens:
                continue
            name = tokens[0].strip().lower()
            if not _SAFE_HEADER_NAME.match(name):
                continue
            parsed.setdefault(name, []).extend(tokens[1:])
    return parsed


def parse_set_cookie(header: str) -> tuple[str | None, dict[str, Any]]:
    """Parse a ``Set-Cookie`` header into ``(name, attributes)``.

    Attribute names are lower-cased; flags are stored as ``True`` when they have
    no value (``Secure``) and as a string otherwise (``SameSite=Lax``).
    """
    if not header:
        return None, {}
    parts = str(header).split(";")
    name, _, first_value = parts[0].partition("=")
    name = name.strip()
    attributes: dict[str, Any] = {"value_present": bool(first_value)}
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        attributes[key] = value.strip().strip('"') if sep else True
    return (name or None), attributes


_SECURITY_TXT_FIELD = re.compile(r"^([A-Za-z0-9-]+)\s*:\s*(.*)$")


def parse_security_txt(text: str) -> dict[str, list[str]]:
    """Parse an RFC 9116 ``security.txt`` into ``{field: [values]}``.

    Handles comments (``#``), CRLF and line folding/continuations, and collects
    repeated fields such as multiple ``Contact`` or ``Acknowledgments`` entries.
    """
    fields: dict[str, list[str]] = {}
    last_key: str | None = None
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            last_key = None
            continue
        match = _SECURITY_TXT_FIELD.match(line)
        if match:
            key = match.group(1).lower()
            fields.setdefault(key, []).append(match.group(2).strip())
            last_key = key
        elif last_key and raw_line[:1] in (" ", "\t"):
            # RFC 5322 style continuation of the previous field.
            fields[last_key][-1] = (fields[last_key][-1] + " " + line).strip()
        else:
            last_key = None
    return {key: [v for v in values if v] for key, values in fields.items()}


def parse_expires(value: str) -> datetime | None:
    """Parse an RFC 9116 ``Expires`` timestamp (ISO 8601 / RFC 3339)."""
    if not value:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------------------
# Auditor
# --------------------------------------------------------------------------------------
@dataclass
class RedirectHop:
    url: str
    status: int
    location: str | None = None
    set_cookie: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "location": self.location,
            "set_cookie": len(self.set_cookie),
        }


class HttpAuditor:
    """Asynchronous HTTP security-header auditor."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        max_redirects: int = 10,
        hsts_min_max_age: int = 31_536_000,
        check_security_txt: bool = True,
        check_cookies: bool = True,
        user_agent: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.hsts_min_max_age = hsts_min_max_age
        self.check_security_txt = check_security_txt
        self.check_cookies = check_cookies
        self.user_agent = user_agent or "secaudit/1.0"

    # -- public API ----------------------------------------------------------------
    async def audit(self, target: str, client: httpx.AsyncClient | None = None) -> SectionResult:
        """Audit ``target`` and return the HTTP section result."""
        started = time.perf_counter()
        section = SectionResult(category=Category.HTTP)
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
                follow_redirects=False,
            )
        try:
            host, start_url = normalise_target(target)
            section.data["host"] = host
            section.data["start_url"] = start_url

            response, chain, error = await self._fetch(client, start_url)
            section.data["redirect_chain"] = [hop.to_dict() for hop in chain]
            section.data["final_url"] = str(response.url) if response is not None else None
            section.data["status_code"] = response.status_code if response is not None else None
            section.data["https"] = bool(response is not None and response.url.scheme == "https")

            if response is None:
                section.error = error or "request failed"
                section.add(
                    self._finding(
                        "http.unreachable",
                        "Target is not reachable over HTTPS",
                        Status.FAIL,
                        Severity.HIGH,
                        10.0,
                        "No HTTP response could be retrieved from the target, so its "
                        "security posture could not be evaluated.",
                        evidence=section.error,
                        remediation_key="http.unreachable",
                        context={"target": host},
                    )
                )
                return self._finish(section, started)

            if chain and len(chain) > 1:
                section.data["redirects"] = len(chain) - 1
            if error:
                section.data["redirect_error"] = error
                section.add(
                    self._finding(
                        "http.redirect_chain",
                        "Redirect chain is broken",
                        Status.WARN,
                        Severity.MEDIUM,
                        3.0,
                        "The redirect chain could not be followed to completion. Infinite "
                        "redirect loops and over-long chains break clients, CDN caching and "
                        "the HTTPS upgrade path.",
                        evidence=error,
                        remediation_key="http.unreachable",
                        context={"target": host},
                    )
                )

            headers = response.headers
            section.data["headers"] = {
                key: headers.get_list(key)
                for key in sorted({k.lower() for k in headers.keys()})
                if key.lower() not in {"set-cookie"}
            }
            section.data["server"] = headers.get("server")
            section.data["powered_by"] = headers.get("x-powered-by")

            # Cookies are collected across the whole redirect chain.
            cookies = self._collect_cookies(chain, response)
            section.data["cookies"] = [
                {"name": name, "attributes": attrs} for name, attrs in sorted(cookies.items())
            ]

            host_for_context = {"target": host}
            checks: list[Callable[[], None]] = [
                lambda: self._check_hsts(section, response, host_for_context),
                lambda: self._check_csp(section, response),
                lambda: self._check_x_content_type_options(section, response),
                lambda: self._check_x_frame_options(section, response),
                lambda: self._check_referrer_policy(section, response),
                lambda: self._check_permissions_policy(section, response),
                lambda: self._check_cross_origin(section, response),
                lambda: self._check_tech_disclosure(section, response),
            ]
            if self.check_cookies:
                checks.append(lambda: self._check_cookies(section, cookies, host_for_context))
            for check in checks:
                try:
                    check()
                except Exception as exc:  # pragma: no cover - defensive
                    log.exception("HTTP check crashed: %s", exc)
                    section.data.setdefault("check_errors", []).append(str(exc))

            if self.check_security_txt:
                try:
                    await self._check_security_txt(section, response, client, host_for_context)
                except Exception as exc:  # pragma: no cover - defensive
                    log.exception("security.txt check crashed: %s", exc)
                    section.data.setdefault("check_errors", []).append(str(exc))
            return self._finish(section, started)
        finally:
            if owns_client:
                await client.aclose()

    # -- networking ----------------------------------------------------------------
    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[httpx.Response | None, list[RedirectHop], str | None]:
        """GET ``url`` following redirects manually, returning the final response."""
        chain: list[RedirectHop] = []
        current = url
        seen: set[str] = set()
        response: httpx.Response | None = None
        for _ in range(self.max_redirects + 1):
            if current in seen:
                return response, chain, "redirect loop detected"
            seen.add(current)
            try:
                request = client.build_request(
                    "GET",
                    current,
                    headers={
                        "User-Agent": self.user_agent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Encoding": "identity",
                    },
                    timeout=self.timeout,
                )
                response = await client.send(request, follow_redirects=False, stream=True)
            except httpx.HTTPError as exc:
                return None, chain, f"{type(exc).__name__}: {exc}"
            except Exception as exc:  # pragma: no cover - defensive
                return None, chain, f"{type(exc).__name__}: {exc}"

            try:
                hop = RedirectHop(
                    url=str(response.url),
                    status=response.status_code,
                    location=response.headers.get("location"),
                    set_cookie=response.headers.get_list("set-cookie"),
                )
                chain.append(hop)
                if response.is_redirect and hop.location:
                    current = urljoin(str(response.url), hop.location)
                    continue
                if response.is_redirect and not hop.location:
                    return response, chain, "redirect response without a Location header"
                return response, chain, None
            finally:
                await response.aclose()
        return response, chain, f"too many redirects (>{self.max_redirects})"

    async def _fetch_text(
        self, client: httpx.AsyncClient, url: str, limit: int = MAX_SECURITY_TXT_BYTES
    ) -> tuple[int | None, str, dict[str, str], str | None]:
        """Fetch a small text document, returning ``(status, body, headers, error)``."""
        try:
            request = client.build_request(
                "GET",
                url,
                headers={"User-Agent": self.user_agent, "Accept": "text/plain, */*"},
                timeout=self.timeout,
            )
            response = await client.send(request, follow_redirects=True, stream=True)
        except httpx.HTTPError as exc:
            return None, "", {}, f"{type(exc).__name__}: {exc}"
        try:
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= limit:
                    break
            body = b"".join(chunks)[:limit].decode("utf-8", errors="replace")
            return response.status_code, body, dict(response.headers), None
        except httpx.HTTPError as exc:  # pragma: no cover - network flake
            return response.status_code, "", dict(response.headers), str(exc)
        finally:
            await response.aclose()

    # -- helpers -------------------------------------------------------------------
    @staticmethod
    def _collect_cookies(
        chain: Sequence[RedirectHop], response: httpx.Response | None
    ) -> dict[str, dict[str, Any]]:
        """Merge cookies seen on every hop (last definition wins per name)."""
        cookies: dict[str, dict[str, Any]] = {}
        raw_headers: list[str] = []
        for hop in chain:
            raw_headers.extend(hop.set_cookie)
        if response is not None:
            raw_headers.extend(response.headers.get_list("set-cookie"))
        for raw in raw_headers:
            name, attrs = parse_set_cookie(raw)
            if not name:
                continue
            cookies[name] = attrs
        return cookies

    @staticmethod
    def _finish(section: SectionResult, started: float) -> SectionResult:
        section.duration_ms = (time.perf_counter() - started) * 1000
        return section

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
        references: Iterable[str] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            category=Category.HTTP,
            severity=severity,
            status=status,
            weight=weight,
            description=description,
            evidence=_shorten(evidence) if evidence else None,
            remediation_key=remediation_key,
            context=context or {},
            references=list(references or []),
        )

    # -- individual checks ---------------------------------------------------------
    def _check_hsts(
        self, section: SectionResult, response: httpx.Response, context: dict[str, Any]
    ) -> None:
        values = response.headers.get_list("strict-transport-security")
        if not values:
            section.add(
                self._finding(
                    "http.hsts.missing",
                    "Strict-Transport-Security header is missing",
                    Status.FAIL,
                    Severity.HIGH,
                    10.0,
                    "Without HSTS a network attacker can strip TLS and serve the site over "
                    "plaintext HTTP (SSL stripping) to returning visitors.",
                    evidence="Strict-Transport-Security: absent",
                    remediation_key="http.hsts",
                    context=context,
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )
            return

        hsts = parse_hsts(*values)
        raw = _shorten(hsts["raw"])
        section.data["hsts"] = hsts["directives"]

        max_age = hsts["max_age"]
        if max_age is None:
            section.add(
                self._finding(
                    "http.hsts.invalid",
                    "HSTS header has no valid max-age directive",
                    Status.FAIL,
                    Severity.HIGH,
                    9.0,
                    "A Strict-Transport-Security header without a numeric max-age is ignored "
                    "by browsers and therefore provides no protection.",
                    evidence=raw,
                    remediation_key="http.hsts",
                    context=context,
                )
            )
        elif max_age == 0:
            section.add(
                self._finding(
                    "http.hsts.max_age_zero",
                    "HSTS is explicitly disabled (max-age=0)",
                    Status.FAIL,
                    Severity.HIGH,
                    9.0,
                    "max-age=0 tells browsers to forget the HSTS policy, re-opening the "
                    "SSL-stripping window.",
                    evidence=raw,
                    remediation_key="http.hsts",
                    context=context,
                )
            )
        elif max_age < self.hsts_min_max_age:
            section.add(
                self._finding(
                    "http.hsts.max_age_short",
                    f"HSTS max-age is shorter than {self.hsts_min_max_age} seconds",
                    Status.WARN,
                    Severity.MEDIUM,
                    9.0,
                    "A short HSTS lifetime leaves visitors unprotected between policy "
                    "expiry and renewal. Use at least one year (31536000).",
                    evidence=f"max-age={max_age} ({max_age / 86400:.1f} days)",
                    remediation_key="http.hsts",
                    context=context,
                )
            )
        else:
            section.add(
                self._finding(
                    "http.hsts.max_age",
                    "HSTS max-age is at least one year",
                    Status.PASS,
                    Severity.PASS,
                    9.0,
                    f"max-age={max_age} seconds keeps returning visitors on HTTPS.",
                    evidence=f"max-age={max_age}",
                )
            )

        section.add(
            self._finding(
                "http.hsts.include_subdomains",
                "HSTS includeSubDomains" + (" is set" if hsts["include_subdomains"] else " is missing"),
                Status.PASS if hsts["include_subdomains"] else Status.WARN,
                Severity.PASS if hsts["include_subdomains"] else Severity.LOW,
                3.0,
                "includeSubDomains prevents attackers from downgrading any sub-domain, "
                "including forgotten staging hosts.",
                evidence=raw,
                remediation_key=None if hsts["include_subdomains"] else "http.hsts",
                context=context,
            )
        )

        if not hsts["preload"]:
            section.add(
                self._finding(
                    "http.hsts.preload",
                    "HSTS preload directive is missing",
                    Status.WARN,
                    Severity.INFO,
                    1.5,
                    "Preload lets browsers refuse plaintext HTTP before the first visit. "
                    "Only submit to the preload list once includeSubDomains is confirmed.",
                    evidence=raw,
                    remediation_key="http.hsts",
                    context=context,
                    references=["https://hstspreload.org/"],
                )
            )
        else:
            section.add(
                self._finding(
                    "http.hsts.preload",
                    "HSTS preload directive is present",
                    Status.PASS,
                    Severity.PASS,
                    1.5,
                    "The domain is eligible for the browser HSTS preload list.",
                    evidence=raw,
                )
            )

    def _check_csp(self, section: SectionResult, response: httpx.Response) -> None:
        enforced = response.headers.get_list("content-security-policy")
        report_only = response.headers.get_list("content-security-policy-report-only")

        if not enforced:
            if report_only:
                section.add(
                    self._finding(
                        "http.csp.report_only",
                        "Content-Security-Policy is only report-only (not enforced)",
                        Status.FAIL,
                        Severity.MEDIUM,
                        10.0,
                        "Content-Security-Policy-Report-Only never blocks anything; it only "
                        "collects violation reports. Enforce the policy once reports are clean.",
                        evidence=_shorten(report_only[0]),
                        remediation_key="http.csp",
                    )
                )
            else:
                section.add(
                    self._finding(
                        "http.csp.missing",
                        "Content-Security-Policy header is missing",
                        Status.FAIL,
                        Severity.HIGH,
                        10.0,
                        "Without CSP the browser executes any injected script, making XSS "
                        "and data exfiltration trivial. CSP is the primary defence-in-depth "
                        "control against script injection.",
                        evidence="Content-Security-Policy: absent",
                        remediation_key="http.csp",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )
            return

        directives = parse_csp(*enforced)
        section.data["csp"] = dict(directives)
        raw = _shorten("; ".join(enforced))
        section.add(
            self._finding(
                "http.csp.present",
                "Content-Security-Policy is enforced",
                Status.PASS,
                Severity.PASS,
                10.0,
                "An enforced CSP limits which sources the browser may load resources from.",
                evidence=raw,
            )
        )

        script_src = directives.get("script-src") or directives.get("default-src") or []
        default_src = directives.get("default-src") or []
        joined_script = " ".join(script_src).lower()

        if "'unsafe-inline'" in joined_script:
            relaxed = any(token.startswith("'nonce-") or token.startswith("'sha") for token in script_src)
            section.add(
                self._finding(
                    "http.csp.unsafe_inline",
                    "CSP allows 'unsafe-inline' for scripts",
                    Status.WARN if not relaxed else Status.INFO,
                    Severity.MEDIUM if not relaxed else Severity.LOW,
                    3.0,
                    "'unsafe-inline' re-enables inline <script> execution, which neutralises "
                    "most of CSP's XSS protection. Replace inline handlers with nonces or hashes.",
                    evidence=_shorten(" ".join(script_src)),
                    remediation_key="http.csp",
                )
            )

        if "'unsafe-eval'" in joined_script:
            section.add(
                self._finding(
                    "http.csp.unsafe_eval",
                    "CSP allows 'unsafe-eval'",
                    Status.WARN,
                    Severity.HIGH,
                    3.0,
                    "'unsafe-eval' permits eval()/new Function() and turns DOM-XSS sinks into "
                    "code execution primitives.",
                    evidence=_shorten(" ".join(script_src)),
                    remediation_key="http.csp",
                )
            )

        wildcard_sources = [
            token
            for token in script_src
            if token in {"*", "https:", "http:", "data:", "blob:"}
        ]
        if wildcard_sources:
            section.add(
                self._finding(
                    "http.csp.wildcard",
                    "CSP script sources contain over-broad wildcards",
                    Status.WARN,
                    Severity.HIGH,
                    3.0,
                    f"Wildcard sources ({', '.join(sorted(set(wildcard_sources)))}) let any "
                    "host serve scripts, defeating the allow-list. Enumerate trusted origins "
                    "or use nonces/hashes.",
                    evidence=_shorten(" ".join(script_src)),
                    remediation_key="http.csp",
                )
            )
        else:
            section.add(
                self._finding(
                    "http.csp.wildcard",
                    "CSP script sources are not over-broad",
                    Status.PASS,
                    Severity.PASS,
                    3.0,
                    "No bare wildcard, scheme-only or data: script sources were found.",
                    evidence=_shorten(" ".join(script_src)) or "no script-src/default-src",
                )
            )

        if "http:" in " ".join(sum(directives.values(), [])).lower():
            section.add(
                self._finding(
                    "http.csp.insecure_sources",
                    "CSP allows plaintext HTTP sources",
                    Status.WARN,
                    Severity.MEDIUM,
                    2.0,
                    "http: sources can be tampered with by an active network attacker; use "
                    "https: origins together with upgrade-insecure-requests.",
                    evidence=_shorten(" ".join(enforced)),
                    remediation_key="http.csp",
                )
            )

        if "default-src" in directives:
            section.add(
                self._finding(
                    "http.csp.default_src",
                    "CSP defines default-src",
                    Status.PASS,
                    Severity.PASS,
                    3.0,
                    "default-src provides a fallback for directives that are not listed.",
                    evidence=_shorten(" ".join(default_src)),
                )
            )
        else:
            section.add(
                self._finding(
                    "http.csp.default_src",
                    "CSP has no default-src fallback",
                    Status.WARN,
                    Severity.MEDIUM,
                    3.0,
                    "Without default-src, unspecified directives (img-src, connect-src, "
                    "font-src, frame-src, …) fall back to unrestricted.",
                    evidence=raw,
                    remediation_key="http.csp",
                )
            )

        has_frame_ancestors = "frame-ancestors" in directives
        has_xfo = bool(response.headers.get("x-frame-options"))
        section.add(
            self._finding(
                "http.csp.frame_ancestors",
                "CSP frame-ancestors" + (" is set" if has_frame_ancestors else " is missing"),
                Status.PASS if has_frame_ancestors else (Status.INFO if has_xfo else Status.WARN),
                Severity.PASS if has_frame_ancestors else Severity.LOW,
                2.0,
                "frame-ancestors is the modern clickjacking defence and supersedes "
                "X-Frame-Options for modern browsers.",
                evidence=(
                    "frame-ancestors " + " ".join(directives.get("frame-ancestors", []))
                    if has_frame_ancestors
                    else raw
                ),
                remediation_key=None if has_frame_ancestors else "http.csp",
            )
        )

        if "base-uri" not in directives:
            section.add(
                self._finding(
                    "http.csp.base_uri",
                    "CSP does not restrict base-uri",
                    Status.WARN,
                    Severity.LOW,
                    1.0,
                    "Without base-uri an injected <base> tag can redirect every relative URL "
                    "on the page to an attacker-controlled host.",
                    evidence=raw,
                    remediation_key="http.csp",
                )
            )

        if "object-src" not in directives and "default-src" not in directives:
            section.add(
                self._finding(
                    "http.csp.object_src",
                    "CSP does not restrict object-src",
                    Status.WARN,
                    Severity.LOW,
                    1.0,
                    "Legacy plugins (Flash/Java) loaded through <object>/<embed> can execute "
                    "code; restrict object-src to 'none'.",
                    evidence=raw,
                    remediation_key="http.csp",
                )
            )

    def _check_x_content_type_options(
        self, section: SectionResult, response: httpx.Response
    ) -> None:
        values = [v.strip().lower() for v in response.headers.get_list("x-content-type-options")]
        if not values:
            section.add(
                self._finding(
                    "http.x_content_type_options.missing",
                    "X-Content-Type-Options header is missing",
                    Status.FAIL,
                    Severity.MEDIUM,
                    6.0,
                    "Without nosniff, browsers may MIME-sniff a response and execute a "
                    "user-uploaded file as HTML/JavaScript.",
                    evidence="X-Content-Type-Options: absent",
                    remediation_key="http.x_content_type_options",
                )
            )
        elif "nosniff" in values:
            section.add(
                self._finding(
                    "http.x_content_type_options.nosniff",
                    "X-Content-Type-Options: nosniff is set",
                    Status.PASS,
                    Severity.PASS,
                    6.0,
                    "MIME sniffing is disabled, preventing content-type confusion attacks.",
                    evidence=", ".join(values),
                )
            )
        else:
            section.add(
                self._finding(
                    "http.x_content_type_options.invalid",
                    "X-Content-Type-Options has an unexpected value",
                    Status.WARN,
                    Severity.MEDIUM,
                    6.0,
                    "Only 'nosniff' is meaningful; other values are ignored by browsers.",
                    evidence=", ".join(values),
                    remediation_key="http.x_content_type_options",
                )
            )

    def _check_x_frame_options(self, section: SectionResult, response: httpx.Response) -> None:
        values = [v.strip().lower() for v in response.headers.get_list("x-frame-options")]
        csp_frame_ancestors = "frame-ancestors" in parse_csp(
            *response.headers.get_list("content-security-policy")
        )

        if not values:
            if csp_frame_ancestors:
                section.add(
                    self._finding(
                        "http.x_frame_options.missing",
                        "X-Frame-Options is missing but CSP frame-ancestors is enforced",
                        Status.PASS,
                        Severity.PASS,
                        5.0,
                        "Modern browsers honour frame-ancestors; the legacy header is not "
                        "required when CSP is present.",
                        evidence="frame-ancestors present",
                    )
                )
            else:
                section.add(
                    self._finding(
                        "http.x_frame_options.missing",
                        "Clickjacking protection is missing (X-Frame-Options / frame-ancestors)",
                        Status.FAIL,
                        Severity.MEDIUM,
                        5.0,
                        "Neither X-Frame-Options nor CSP frame-ancestors is present, so the "
                        "site can be embedded in an attacker's page and clickjacked.",
                        evidence="X-Frame-Options: absent; frame-ancestors: absent",
                        remediation_key="http.x_frame_options",
                    )
                )
            return

        value = values[0]
        if value in {"deny", "sameorigin"}:
            section.add(
                self._finding(
                    "http.x_frame_options.valid",
                    f"X-Frame-Options: {value.upper()} is set",
                    Status.PASS,
                    Severity.PASS,
                    5.0,
                    "Framing by third-party origins is blocked.",
                    evidence=", ".join(values),
                )
            )
        elif value.startswith("allow-from"):
            section.add(
                self._finding(
                    "http.x_frame_options.allow_from",
                    "X-Frame-Options uses the deprecated ALLOW-FROM directive",
                    Status.WARN,
                    Severity.LOW,
                    5.0,
                    "ALLOW-FROM is not supported by modern browsers; use CSP frame-ancestors "
                    "with an explicit allow-list instead.",
                    evidence=", ".join(values),
                    remediation_key="http.x_frame_options",
                )
            )
        else:
            section.add(
                self._finding(
                    "http.x_frame_options.invalid",
                    "X-Frame-Options has an invalid or conflicting value",
                    Status.WARN,
                    Severity.MEDIUM,
                    5.0,
                    "Values other than DENY/SAMEORIGIN are ignored, leaving the page frameable.",
                    evidence=", ".join(values),
                    remediation_key="http.x_frame_options",
                )
            )

    def _check_referrer_policy(self, section: SectionResult, response: httpx.Response) -> None:
        values = [v.strip().lower() for v in response.headers.get_list("referrer-policy")]
        if not values:
            section.add(
                self._finding(
                    "http.referrer_policy.missing",
                    "Referrer-Policy header is missing",
                    Status.WARN,
                    Severity.LOW,
                    6.0,
                    "Without an explicit policy browsers default to no-referrer-when-downgrade, "
                    "leaking full URLs (including tokens in query strings) to third parties.",
                    evidence="Referrer-Policy: absent",
                    remediation_key="http.referrer_policy",
                )
            )
            return

        tokens = [token for value in values for token in re.split(r"[,\s]+", value) if token]
        unsafe = sorted({token for token in tokens if token in UNSAFE_REFERRER_POLICIES})
        safe = [token for token in tokens if token in SAFE_REFERRER_POLICIES]
        section.data["referrer_policy"] = tokens

        if unsafe:
            section.add(
                self._finding(
                    "http.referrer_policy.unsafe",
                    "Referrer-Policy leaks full URLs",
                    Status.WARN,
                    Severity.MEDIUM,
                    6.0,
                    f"The policy allows full referrer leakage ({', '.join(unsafe)}). "
                    "Use strict-origin-when-cross-origin or no-referrer.",
                    evidence=", ".join(values),
                    remediation_key="http.referrer_policy",
                )
            )
        elif len(safe) < len(tokens):
            section.add(
                self._finding(
                    "http.referrer_policy.deprecated",
                    "Referrer-Policy contains deprecated or unknown values",
                    Status.WARN,
                    Severity.LOW,
                    6.0,
                    "Only the current Referrer-Policy tokens are reliably honoured; "
                    "unrecognised tokens fall back to the default behaviour.",
                    evidence=", ".join(values),
                    remediation_key="http.referrer_policy",
                )
            )
        else:
            section.add(
                self._finding(
                    "http.referrer_policy.valid",
                    "Referrer-Policy restricts referrer leakage",
                    Status.PASS,
                    Severity.PASS,
                    6.0,
                    "Cross-origin requests only receive the origin, not the full path.",
                    evidence=", ".join(values),
                )
            )

    def _check_permissions_policy(
        self, section: SectionResult, response: httpx.Response
    ) -> None:
        values = response.headers.get_list("permissions-policy")
        legacy = response.headers.get_list("feature-policy")
        if not values:
            section.add(
                self._finding(
                    "http.permissions_policy.missing",
                    "Permissions-Policy header is missing",
                    Status.WARN,
                    Severity.LOW,
                    5.0,
                    "Without Permissions-Policy, embedded third-party frames may request "
                    "camera, microphone, geolocation and other powerful features.",
                    evidence=(
                        "Permissions-Policy: absent"
                        + (" (legacy Feature-Policy present)" if legacy else "")
                    ),
                    remediation_key="http.permissions_policy",
                )
            )
            return

        parsed: dict[str, str] = {}
        for value in values:
            for chunk in str(value).split(","):
                if "=" not in chunk:
                    continue
                key, _, allowlist = chunk.partition("=")
                parsed[key.strip().lower()] = allowlist.strip()

        section.data["permissions_policy"] = parsed
        delegated = sorted(
            feature
            for feature, allowlist in parsed.items()
            if feature in SENSITIVE_PERMISSIONS and allowlist.strip() in {"*", '"*"'}
        )
        if delegated:
            section.add(
                self._finding(
                    "http.permissions_policy.wildcard",
                    "Permissions-Policy delegates sensitive features to every origin",
                    Status.WARN,
                    Severity.MEDIUM,
                    5.0,
                    f"These features are allowed for any origin: {', '.join(delegated)}. "
                    "Restrict them to specific origins or deny them with ().",
                    evidence=", ".join(values),
                    remediation_key="http.permissions_policy",
                )
            )
        else:
            section.add(
                self._finding(
                    "http.permissions_policy.present",
                    "Permissions-Policy restricts powerful browser features",
                    Status.PASS,
                    Severity.PASS,
                    5.0,
                    "No sensitive feature is delegated to a wildcard origin.",
                    evidence=_shorten(", ".join(values)),
                )
            )

    def _check_cross_origin(self, section: SectionResult, response: httpx.Response) -> None:
        coop = (response.headers.get("cross-origin-opener-policy") or "").strip().lower()
        if not coop:
            section.add(
                self._finding(
                    "http.coop.missing",
                    "Cross-Origin-Opener-Policy header is missing",
                    Status.WARN,
                    Severity.LOW,
                    4.0,
                    "Without COOP a cross-origin window can obtain a reference to your "
                    "browsing context, enabling XS-Leak and cross-window scripting attacks.",
                    evidence="Cross-Origin-Opener-Policy: absent",
                    remediation_key="http.coop",
                )
            )
        elif coop.startswith("same-origin"):
            section.add(
                self._finding(
                    "http.coop.present",
                    f"Cross-Origin-Opener-Policy: {coop} is set",
                    Status.PASS,
                    Severity.PASS,
                    4.0,
                    "The browsing context is isolated from cross-origin openers.",
                    evidence=coop,
                )
            )
        else:
            section.add(
                self._finding(
                    "http.coop.weak",
                    f"Cross-Origin-Opener-Policy is weak ({coop})",
                    Status.WARN,
                    Severity.LOW,
                    4.0,
                    "unsafe-none (the default) provides no isolation; use same-origin or "
                    "same-origin-allow-popups.",
                    evidence=coop,
                    remediation_key="http.coop",
                )
            )

        corp = (response.headers.get("cross-origin-resource-policy") or "").strip().lower()
        if not corp:
            section.add(
                self._finding(
                    "http.corps.missing",
                    "Cross-Origin-Resource-Policy header is missing",
                    Status.WARN,
                    Severity.LOW,
                    2.0,
                    "CORP prevents other sites from embedding your responses (Spectre-class "
                    "data leaks, cross-origin image probing).",
                    evidence="Cross-Origin-Resource-Policy: absent",
                    remediation_key="http.corps",
                )
            )
        elif corp in {"same-origin", "same-site", "cross-origin"}:
            section.add(
                self._finding(
                    "http.corps.present",
                    f"Cross-Origin-Resource-Policy: {corp} is set",
                    Status.PASS,
                    Severity.PASS,
                    2.0,
                    "Cross-origin embedding of this response is controlled.",
                    evidence=corp,
                )
            )

    def _check_tech_disclosure(
        self, section: SectionResult, response: httpx.Response
    ) -> None:
        server = response.headers.get("server")
        if not server:
            section.add(
                self._finding(
                    "http.header.server",
                    "Server banner is suppressed",
                    Status.PASS,
                    Severity.PASS,
                    2.0,
                    "No Server header is returned, reducing fingerprinting surface.",
                    evidence="Server: absent",
                )
            )
        elif _VERSION_RE.search(server):
            section.add(
                self._finding(
                    "http.header.server",
                    "Server header discloses software version",
                    Status.WARN,
                    Severity.LOW,
                    2.0,
                    "Version banners let attackers map the target to known CVEs; hide the "
                    "token and patch promptly.",
                    evidence=f"Server: {server}",
                    remediation_key="http.tech_disclosure",
                )
            )
        else:
            section.add(
                self._finding(
                    "http.header.server",
                    "Server header is present without a version",
                    Status.INFO,
                    Severity.INFO,
                    2.0,
                    "A product token is still useful for fingerprinting; consider suppressing it.",
                    evidence=f"Server: {server}",
                    remediation_key="http.tech_disclosure",
                )
            )

        for header, (display, weight, severity) in DISCLOSURE_HEADERS.items():
            value = response.headers.get(header)
            if not value:
                continue
            is_version = bool(_VERSION_RE.search(value))
            section.add(
                self._finding(
                    f"http.header.{header.replace('-', '_')}",
                    f"{display} header discloses implementation details",
                    Status.WARN if is_version else Status.INFO,
                    severity if is_version else Severity.INFO,
                    weight,
                    f"The {display} header speeds up targeted exploitation and should be "
                    "removed at the edge or in the application server.",
                    evidence=f"{display}: {value}",
                    remediation_key="http.tech_disclosure",
                )
            )

        section.add(
            self._finding(
                "http.header.x_xss_protection",
                "Legacy X-XSS-Protection header",
                Status.INFO,
                Severity.INFO,
                0.5,
                "X-XSS-Protection is deprecated and can introduce XSS in old browsers. "
                "Rely on CSP instead and remove the header.",
                evidence=f"X-XSS-Protection: {response.headers.get('x-xss-protection')}",
                remediation_key="http.tech_disclosure",
            )
            if response.headers.get("x-xss-protection")
            else self._finding(
                "http.header.x_xss_protection",
                "No legacy X-XSS-Protection header",
                Status.PASS,
                Severity.PASS,
                0.5,
                "The deprecated XSS auditor header is not sent.",
                evidence="X-XSS-Protection: absent",
            )
        )

    def _check_cookies(
        self,
        section: SectionResult,
        cookies: dict[str, dict[str, Any]],
        context: dict[str, Any],
    ) -> None:
        if not cookies:
            section.add(
                self._finding(
                    "http.cookies.none",
                    "No cookies were set by the audited responses",
                    Status.PASS,
                    Severity.PASS,
                    1.0,
                    "Cookie hardening checks were not applicable because no Set-Cookie "
                    "headers were observed.",
                    evidence="Set-Cookie: absent",
                )
            )
            return

        names = sorted(cookies)
        missing_secure = [n for n in names if "secure" not in cookies[n]]
        missing_httponly = [n for n in names if "httponly" not in cookies[n]]
        missing_samesite = [n for n in names if "samesite" not in cookies[n]]
        samesite_none_without_secure = [
            n
            for n in names
            if str(cookies[n].get("samesite", "")).lower() == "none" and "secure" not in cookies[n]
        ]
        invalid_samesite = [
            n
            for n in names
            if "samesite" in cookies[n]
            and str(cookies[n]["samesite"]).lower() not in {"strict", "lax", "none"}
        ]

        section.add(
            self._finding(
                "http.cookies.secure",
                "Cookies are missing the Secure flag"
                if missing_secure
                else "All cookies carry the Secure flag",
                Status.FAIL if missing_secure else Status.PASS,
                Severity.HIGH if missing_secure else Severity.PASS,
                8.0,
                "Cookies without Secure are transmitted over plaintext HTTP and can be "
                "captured by any on-path attacker. Session cookies must be Secure.",
                evidence=(
                    f"{len(missing_secure)}/{len(names)} cookie(s) without Secure: "
                    + ", ".join(missing_secure)
                    if missing_secure
                    else f"{len(names)} cookie(s) verified"
                ),
                remediation_key="http.cookies" if missing_secure else None,
                context={**context, "header": "Secure"},
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            )
        )

        section.add(
            self._finding(
                "http.cookies.httponly",
                "Cookies are missing the HttpOnly flag"
                if missing_httponly
                else "All cookies carry the HttpOnly flag",
                Status.WARN if missing_httponly else Status.PASS,
                Severity.MEDIUM if missing_httponly else Severity.PASS,
                5.0,
                "HttpOnly stops JavaScript from reading the cookie, blunting session "
                "hijacking after an XSS. Non-authentication cookies may legitimately omit it.",
                evidence=(
                    f"{len(missing_httponly)}/{len(names)} cookie(s) without HttpOnly: "
                    + ", ".join(missing_httponly)
                    if missing_httponly
                    else f"{len(names)} cookie(s) verified"
                ),
                remediation_key="http.cookies" if missing_httponly else None,
                context={**context, "header": "HttpOnly"},
            )
        )

        if samesite_none_without_secure:
            section.add(
                self._finding(
                    "http.cookies.samesite_none_insecure",
                    "SameSite=None cookie is missing Secure",
                    Status.FAIL,
                    Severity.HIGH,
                    5.0,
                    "Browsers reject SameSite=None without Secure, so the cookie is dropped "
                    "and cross-site flows break; when accepted it is exposed to interception.",
                    evidence=", ".join(samesite_none_without_secure),
                    remediation_key="http.cookies",
                    context={**context, "header": "SameSite"},
                )
            )

        if missing_samesite:
            section.add(
                self._finding(
                    "http.cookies.samesite",
                    "Cookies do not set SameSite",
                    Status.WARN,
                    Severity.MEDIUM,
                    5.0,
                    "Without SameSite browsers apply Lax-by-default, which is inconsistent "
                    "across clients. Set SameSite=Lax (or Strict for session cookies) explicitly.",
                    evidence=(
                        f"{len(missing_samesite)}/{len(names)} cookie(s) without SameSite: "
                        + ", ".join(missing_samesite)
                    ),
                    remediation_key="http.cookies",
                    context={**context, "header": "SameSite"},
                )
            )
        elif not samesite_none_without_secure:
            section.add(
                self._finding(
                    "http.cookies.samesite",
                    "All cookies declare an explicit SameSite policy",
                    Status.PASS,
                    Severity.PASS,
                    5.0,
                    "Cross-site cookie sending is explicitly controlled.",
                    evidence=f"{len(names)} cookie(s) verified",
                )
            )

        if invalid_samesite:
            section.add(
                self._finding(
                    "http.cookies.samesite_invalid",
                    "Cookies use an invalid SameSite value",
                    Status.WARN,
                    Severity.LOW,
                    2.0,
                    "Invalid SameSite values cause browsers to fall back to default behaviour.",
                    evidence=", ".join(
                        f"{n}={cookies[n]['samesite']}" for n in invalid_samesite
                    ),
                    remediation_key="http.cookies",
                )
            )

        prefix_violations: list[str] = []
        for name in names:
            attrs = cookies[name]
            if name.startswith("__Host-"):
                if "secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs:
                    prefix_violations.append(f"{name} (__Host- requires Secure, Path=/, no Domain)")
            elif name.startswith("__Secure-") and "secure" not in attrs:
                prefix_violations.append(f"{name} (__Secure- requires Secure)")
        if prefix_violations:
            section.add(
                self._finding(
                    "http.cookies.prefix",
                    "Cookie name prefix contract is violated",
                    Status.WARN,
                    Severity.MEDIUM,
                    3.0,
                    "Browsers reject __Host-/__Secure- cookies that do not meet the prefix "
                    "requirements, silently breaking authentication.",
                    evidence="; ".join(prefix_violations),
                    remediation_key="http.cookies",
                )
            )

        long_lived = [
            n
            for n in names
            if str(cookies[n].get("max-age", "")).isdigit()
            and int(str(cookies[n]["max-age"])) > 31_536_000
        ]
        if long_lived:
            section.add(
                self._finding(
                    "http.cookies.long_lived",
                    "Cookies are valid for longer than one year",
                    Status.INFO,
                    Severity.INFO,
                    1.0,
                    "Long-lived cookies extend the blast radius of a stolen token; rotate "
                    "session identifiers server-side.",
                    evidence=", ".join(long_lived),
                )
            )

    async def _check_security_txt(
        self,
        section: SectionResult,
        response: httpx.Response,
        client: httpx.AsyncClient,
        context: dict[str, Any],
    ) -> None:
        origin = f"{response.url.scheme}://{response.url.netloc.decode()}"
        url = urljoin(origin + "/", ".well-known/security.txt")
        status, body, headers, error = await self._fetch_text(client, url)

        section.data["security_txt"] = {
            "url": url,
            "status": status,
            "content_type": headers.get("content-type"),
            "present": bool(status and status == 200 and body.strip()),
            "error": error,
        }

        if error:
            section.add(
                self._finding(
                    "http.security_txt.error",
                    "security.txt could not be retrieved",
                    Status.INFO,
                    Severity.INFO,
                    4.0,
                    "The request for /.well-known/security.txt failed, so the RFC 9116 "
                    "compliance of the site could not be verified.",
                    evidence=error,
                    remediation_key="http.security_txt",
                    context=context,
                )
            )
            return

        if status != 200 or not body.strip():
            section.add(
                self._finding(
                    "http.security_txt.missing",
                    "security.txt is missing (RFC 9116)",
                    Status.WARN,
                    Severity.LOW,
                    4.0,
                    "A published security.txt tells researchers where to report "
                    "vulnerabilities and reduces the risk of unsolicited disclosure.",
                    evidence=f"GET {url} → HTTP {status}",
                    remediation_key="http.security_txt",
                    context=context,
                    references=["https://www.rfc-editor.org/rfc/rfc9116"],
                )
            )
            return

        fields = parse_security_txt(body)
        section.data["security_txt"]["fields"] = fields
        contacts = fields.get("contact", [])
        expires_raw = (fields.get("expires") or [None])[0]
        expires = parse_expires(expires_raw) if expires_raw else None

        problems: list[str] = []
        if not contacts:
            problems.append("Contact field is missing")
        if not expires_raw:
            problems.append("Expires field is missing")
        elif expires is None:
            problems.append(f"Expires is not a valid ISO 8601 timestamp ({expires_raw})")
        elif expires < datetime.now(timezone.utc):
            problems.append(f"Expires is in the past ({expires.date()})")
        insecure_contacts = [c for c in contacts if c.lower().startswith("http://")]
        if insecure_contacts:
            problems.append(f"Contact uses plaintext HTTP ({insecure_contacts[0]})")
        if "canonical" not in fields:
            problems.append("Canonical URI is missing")

        content_type = (headers.get("content-type") or "").lower()
        if content_type and "text/plain" not in content_type:
            problems.append(f"Content-Type is {content_type}, expected text/plain")

        if problems:
            severe = any(
                p.startswith(("Contact", "Expires is", "Expires field")) for p in problems
            )
            section.add(
                self._finding(
                    "http.security_txt.invalid",
                    "security.txt is present but not RFC 9116 compliant",
                    Status.WARN,
                    Severity.MEDIUM if severe else Severity.LOW,
                    4.0,
                    "A malformed security.txt may be ignored by researchers: " + "; ".join(problems),
                    evidence=_shorten(body.replace("\n", " | ")),
                    remediation_key="http.security_txt",
                    context=context,
                )
            )
        else:
            section.add(
                self._finding(
                    "http.security_txt.valid",
                    "security.txt is published and RFC 9116 compliant",
                    Status.PASS,
                    Severity.PASS,
                    4.0,
                    f"A valid security.txt is served with {len(contacts)} contact(s) and a "
                    f"future Expires field ({expires.date() if expires else 'n/a'}).",
                    evidence=f"{len(contacts)} contact(s), expires {expires_raw}",
                )
            )

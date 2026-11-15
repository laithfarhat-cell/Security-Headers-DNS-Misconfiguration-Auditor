"""HTTP auditor tests driven by httpx.MockTransport (no real network)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from auditors.http_auditor import HttpAuditor
from core.models import Category, SectionResult, Status
from core.scorer import Scorer

SECURITY_TXT = (
    "Contact: mailto:security@example.com\n"
    "Expires: 2027-01-01T00:00:00.000Z\n"
    "Canonical: https://example.com/.well-known/security.txt\n"
)

HARDENED_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": (
        "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(self)",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


def _handler(headers: dict[str, str], *, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/security.txt":
            return httpx.Response(
                200, headers={"content-type": "text/plain"}, text=SECURITY_TXT
            )
        return httpx.Response(status, headers=headers, text="<html>ok</html>")

    return handler


async def _audit(target: str, handler: Callable[[httpx.Request], httpx.Response]) -> SectionResult:
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
        return await HttpAuditor().audit(target, client)


def _statuses(section: SectionResult) -> dict[str, Status]:
    return {finding.check_id: finding.status for finding in section.findings}


class TestHardenedSite:
    async def test_no_failures(self) -> None:
        section = await _audit("example.com", _handler(HARDENED_HEADERS))
        failures = [f for f in section.findings if f.status is Status.FAIL]
        assert failures == [], [(f.check_id, f.title) for f in failures]
        assert section.error is None

    async def test_scores_high(self) -> None:
        section = await _audit("example.com", _handler(HARDENED_HEADERS))
        report_scorer = Scorer()
        score, _, _ = report_scorer.score_findings(section.findings)
        assert score >= 95, score

    async def test_core_headers_pass(self) -> None:
        section = await _audit("example.com", _handler(HARDENED_HEADERS))
        statuses = _statuses(section)
        assert statuses["http.hsts.max_age"] is Status.PASS
        assert statuses["http.hsts.include_subdomains"] is Status.PASS
        assert statuses["http.csp.present"] is Status.PASS
        assert statuses["http.csp.frame_ancestors"] is Status.PASS
        assert statuses["http.cookies.none"] is Status.PASS
        assert statuses["http.security_txt.valid"] is Status.PASS


class TestInsecureSite:
    async def test_missing_headers_are_flagged(self) -> None:
        section = await _audit("example.com", _handler({}))
        statuses = _statuses(section)
        for check_id in (
            "http.hsts.missing",
            "http.csp.missing",
            "http.x_content_type_options.missing",
            "http.x_frame_options.missing",
        ):
            assert statuses[check_id] is Status.FAIL, check_id
        # Isolation headers are hardening controls rather than exploit primitives.
        assert statuses["http.referrer_policy.missing"] is Status.WARN
        assert statuses["http.coop.missing"] is Status.WARN

    async def test_missing_security_txt_warns(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/security.txt":
                return httpx.Response(404)
            return httpx.Response(200, text="ok")

        section = await _audit("example.com", handler)
        assert _statuses(section)["http.security_txt.missing"] is Status.WARN

    async def test_unreachable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        section = await _audit("example.com", handler)
        assert section.error is not None
        assert _statuses(section)["http.unreachable"] is Status.FAIL


class TestRedirects:
    async def test_chain_is_tracked(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host == "www.example.com":
                if request.url.path == "/.well-known/security.txt":
                    return httpx.Response(200, text=SECURITY_TXT)
                return httpx.Response(200, headers=HARDENED_HEADERS, text="final")
            if request.url.path == "/":
                return httpx.Response(301, headers={"location": "https://example.com/home"})
            if request.url.path == "/home":
                return httpx.Response(302, headers={"location": "https://www.example.com/"})
            return httpx.Response(404)

        section = await _audit("example.com", handler)
        chain = section.data["redirect_chain"]
        assert [hop["status"] for hop in chain] == [301, 302, 200]
        assert section.data["final_url"] == "https://www.example.com/"

    async def test_redirect_loop_is_reported(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "https://example.com/"})

        section = await _audit("example.com", handler)
        assert "redirect loop" in (section.data.get("redirect_error") or "")
        assert _statuses(section)["http.redirect_chain"] is Status.WARN


class TestCookies:
    async def test_insecure_cookie_flags(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/security.txt":
                return httpx.Response(404)
            return httpx.Response(
                200,
                headers={"set-cookie": "session=abc; Path=/; SameSite=None"},
                text="ok",
            )

        section = await _audit("example.com", handler)
        statuses = _statuses(section)
        assert statuses["http.cookies.secure"] is Status.FAIL
        assert statuses["http.cookies.httponly"] is Status.WARN
        assert statuses["http.cookies.samesite_none_insecure"] is Status.FAIL

    async def test_host_prefix_violation(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/security.txt":
                return httpx.Response(404)
            return httpx.Response(
                200,
                headers={
                    "set-cookie": "__Host-id=1; Secure; HttpOnly; SameSite=Strict; Domain=.example.com"
                },
                text="ok",
            )

        section = await _audit("example.com", handler)
        assert _statuses(section)["http.cookies.prefix"] is Status.WARN

    async def test_cookie_from_redirect_hop_is_collected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "www.example.com":
                return httpx.Response(
                    200, headers={"set-cookie": "session=2; Secure; HttpOnly; SameSite=Lax"}
                )
            return httpx.Response(
                301,
                headers={"location": "https://www.example.com/", "set-cookie": "hop=1; Secure"},
            )

        section = await _audit("example.com", handler)
        names = {cookie["name"] for cookie in section.data["cookies"]}
        assert names == {"hop", "session"}


class TestCsp:
    async def test_report_only_is_a_failure(self) -> None:
        headers = dict(HARDENED_HEADERS)
        headers.pop("content-security-policy")
        headers["content-security-policy-report-only"] = "default-src 'self'"
        section = await _audit("example.com", _handler(headers))
        assert _statuses(section)["http.csp.report_only"] is Status.FAIL

    async def test_unsafe_directives(self) -> None:
        headers = dict(HARDENED_HEADERS)
        headers["content-security-policy"] = (
            "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' *"
        )
        section = await _audit("example.com", _handler(headers))
        statuses = _statuses(section)
        assert statuses["http.csp.unsafe_inline"] is Status.WARN
        assert statuses["http.csp.unsafe_eval"] is Status.WARN
        assert statuses["http.csp.wildcard"] is Status.WARN


class TestHsts:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("max-age=31536000; includeSubDomains; preload", Status.PASS),
            ("max-age=600; includeSubDomains", Status.WARN),
            ("includeSubDomains", Status.FAIL),
            ("max-age=0", Status.FAIL),
        ],
    )
    async def test_max_age(self, value: str, expected: Status) -> None:
        headers = dict(HARDENED_HEADERS)
        headers["strict-transport-security"] = value
        section = await _audit("example.com", _handler(headers))
        statuses = _statuses(section)
        key = (
            "http.hsts.max_age"
            if expected is Status.PASS
            else "http.hsts.max_age_zero"
            if value == "max-age=0"
            else "http.hsts.invalid"
            if "max-age" not in value
            else "http.hsts.max_age_short"
        )
        assert statuses[key] is expected


class TestSecurityTxt:
    async def test_expired_security_txt(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/security.txt":
                return httpx.Response(
                    200,
                    headers={"content-type": "text/plain"},
                    text="Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00Z\n",
                )
            return httpx.Response(200, headers=HARDENED_HEADERS, text="ok")

        section = await _audit("example.com", handler)
        statuses = _statuses(section)
        assert statuses["http.security_txt.invalid"] is Status.WARN

    async def test_canonical_and_contacts(self) -> None:
        section = await _audit("example.com", _handler(HARDENED_HEADERS))
        fields = section.data["security_txt"]["fields"]
        assert fields["contact"] == ["mailto:security@example.com"]
        assert section.findings[0].category is Category.HTTP

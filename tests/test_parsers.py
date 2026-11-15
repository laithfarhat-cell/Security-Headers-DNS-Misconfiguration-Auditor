"""Unit tests for the pure parsing helpers (no network, no event loop)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from auditors.dns_auditor import normalise_domain, organisational_domain, parse_dmarc, parse_spf
from auditors.http_auditor import (
    normalise_target,
    parse_csp,
    parse_expires,
    parse_hsts,
    parse_security_txt,
    parse_set_cookie,
)
from core.scorer import score_to_grade


class TestHsts:
    def test_full_policy(self) -> None:
        parsed = parse_hsts("max-age=63072000; includeSubDomains; preload")
        assert parsed["max_age"] == 63_072_000
        assert parsed["include_subdomains"] is True
        assert parsed["preload"] is True

    def test_case_insensitive_and_quoted(self) -> None:
        parsed = parse_hsts('MAX-AGE="31536000"; IncludeSubdomains')
        assert parsed["max_age"] == 31_536_000
        assert parsed["include_subdomains"] is True
        assert parsed["preload"] is False

    @pytest.mark.parametrize("value", ["", "max-age=abc", "includeSubDomains", "max-age=-1"])
    def test_invalid_max_age_is_none(self, value: str) -> None:
        assert parse_hsts(value)["max_age"] is None

    def test_multiple_headers_merge(self) -> None:
        parsed = parse_hsts("max-age=100", "includeSubDomains")
        assert parsed["max_age"] == 100
        assert parsed["include_subdomains"] is True


class TestCsp:
    def test_parses_directives(self) -> None:
        parsed = parse_csp(
            "default-src 'self'; script-src 'self' https://cdn.example.com 'nonce-abc'; "
            "frame-ancestors 'none'"
        )
        assert parsed["default-src"] == ["'self'"]
        assert "https://cdn.example.com" in parsed["script-src"]
        assert parsed["frame-ancestors"] == ["'none'"]

    def test_merges_multiple_headers(self) -> None:
        parsed = parse_csp("default-src 'self'", "img-src *")
        assert parsed["default-src"] == ["'self'"]
        assert parsed["img-src"] == ["*"]

    def test_ignores_garbage(self) -> None:
        parsed = parse_csp(";;;   ; script-src 'self'")
        assert parsed == {"script-src": ["'self'"]}


class TestCookies:
    def test_flags(self) -> None:
        name, attrs = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
        assert name == "sid"
        assert attrs["secure"] is True
        assert attrs["httponly"] is True
        assert attrs["samesite"] == "Strict"
        assert attrs["path"] == "/"

    def test_no_attributes(self) -> None:
        name, attrs = parse_set_cookie("tracker=1")
        assert name == "tracker"
        assert "secure" not in attrs

    def test_quoted_value_and_empty(self) -> None:
        name, attrs = parse_set_cookie('a="hello world"; Domain=.example.com')
        assert name == "a"
        assert attrs["domain"] == ".example.com"
        assert parse_set_cookie("")[0] is None


class TestSecurityTxt:
    TEXT = (
        "# Our security policy\n"
        "Contact: mailto:security@example.com\n"
        "Contact: https://example.com/report\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Preferred-Languages: en, fr\n"
        "Canonical: https://example.com/.well-known/security.txt\n"
        "Policy: https://example.com/policy\n"
        "  with-continuation\n"
    )

    def test_fields(self) -> None:
        fields = parse_security_txt(self.TEXT)
        assert fields["contact"] == ["mailto:security@example.com", "https://example.com/report"]
        assert fields["expires"] == ["2027-01-01T00:00:00.000Z"]
        assert "with-continuation" in fields["policy"][0]

    def test_expires_parsing(self) -> None:
        assert parse_expires("2027-01-01T00:00:00Z") == datetime(
            2027, 1, 1, tzinfo=timezone.utc
        )
        assert parse_expires("2027-01-01T00:00:00+02:00") is not None
        assert parse_expires("not-a-date") is None
        assert parse_expires("") is None


class TestTargets:
    @pytest.mark.parametrize(
        ("raw", "host", "url"),
        [
            ("example.com", "example.com", "https://example.com/"),
            ("https://example.com/path?a=1", "example.com", "https://example.com/path?a=1"),
            ("http://example.com", "example.com", "http://example.com/"),
            ("Example.COM.", "example.com", "https://example.com/"),
            ("example.com:8443", "example.com", "https://example.com:8443/"),
        ],
    )
    def test_normalise_target(self, raw: str, host: str, url: str) -> None:
        assert normalise_target(raw) == (host, url)

    def test_normalise_target_rejects_garbage(self) -> None:
        with pytest.raises(ValueError):
            normalise_target("   ")

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("https://App.Example.COM/x", "app.example.com"),
            ("example.com:8443", "example.com"),
            ("sub.example.co.uk.", "sub.example.co.uk"),
        ],
    )
    def test_normalise_domain(self, raw: str, expected: str) -> None:
        assert normalise_domain(raw) == expected

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("example.com", "example.com"),
            ("mail.example.com", "example.com"),
            ("a.b.example.co.uk", "example.co.uk"),
            ("localhost", "localhost"),
        ],
    )
    def test_organisational_domain(self, host: str, expected: str) -> None:
        assert organisational_domain(host) == expected


class TestSpfDmarc:
    def test_spf_mechanisms(self) -> None:
        parsed = parse_spf("v=spf1 mx include:_spf.google.com ~all")
        assert parsed["valid"] is True
        assert parsed["all"] == "~"
        names = [mechanism["mechanism"] for mechanism in parsed["mechanisms"]]
        assert names == ["mx", "include", "all"]

    def test_spf_redirect(self) -> None:
        parsed = parse_spf("v=spf1 redirect=_spf.example.com")
        assert parsed["redirect"] == "_spf.example.com"

    def test_spf_invalid(self) -> None:
        assert parse_spf("hello world")["valid"] is False

    def test_dmarc(self) -> None:
        tags = parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100")
        assert tags is not None
        assert tags["p"] == "reject"
        assert tags["rua"] == "mailto:dmarc@example.com"
        assert tags["pct"] == "100"

    def test_dmarc_invalid(self) -> None:
        assert parse_dmarc("p=reject") is None
        assert parse_dmarc("") is None


class TestGrades:
    @pytest.mark.parametrize(
        ("score", "grade"),
        [
            (100, "A+"),
            (97, "A+"),
            (96.9, "A"),
            (93, "A"),
            (90, "A-"),
            (85, "B"),
            (80, "B-"),
            (75, "C"),
            (65, "D"),
            (59.9, "F"),
            (0, "F"),
        ],
    )
    def test_score_to_grade(self, score: float, grade: str) -> None:
        assert score_to_grade(score) == grade

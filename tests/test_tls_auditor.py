"""TLS auditor tests against a local, self-signed HTTPS server."""

from __future__ import annotations

import pytest

from auditors.tls_auditor import TlsAuditor, _hostname_matches
from core.models import Status


def _statuses(section):  # type: ignore[no-untyped-def]
    return {finding.check_id: finding.status for finding in section.findings}


class TestHostnameMatching:
    @pytest.mark.parametrize(
        ("host", "pattern", "expected"),
        [
            ("example.com", "example.com", True),
            ("www.example.com", "*.example.com", True),
            ("a.b.example.com", "*.example.com", False),
            ("example.com", "*.example.com", False),
            ("evil-example.com", "*.example.com", False),
            ("example.com", "other.com", False),
        ],
    )
    def test_wildcards(self, host: str, pattern: str, expected: bool) -> None:
        assert _hostname_matches(host, pattern) is expected


@pytest.mark.asyncio
async def test_self_signed_endpoint(tls_server) -> None:
    host, port = tls_server
    section = await TlsAuditor(https_port=port, timeout=5).audit(f"{host}:{port}")
    statuses = _statuses(section)

    assert section.error is None
    assert statuses["tls.trust"] is Status.FAIL
    assert statuses["tls.self_signed"] is Status.FAIL
    assert statuses["tls.certificate_san"] is Status.PASS
    assert statuses["tls.protocol.tls1_0"] is Status.PASS
    assert statuses["tls.protocol.tls1_1"] is Status.PASS
    assert statuses["tls.protocol.tls12"] is Status.PASS
    assert statuses["tls.https_redirect"] is Status.PASS  # nothing listens on port 80

    certificate = section.data["certificate"]
    assert certificate["subject"].startswith("CN=localhost") or "localhost" in certificate["subject"]
    assert certificate["key_type"] == "RSA"
    assert certificate["key_size"] >= 2048
    assert "127.0.0.1" in certificate["san"]
    assert certificate["days_remaining"] > 0
    assert section.data["protocols"]["TLSv1.2"] is True


@pytest.mark.asyncio
async def test_unreachable_port() -> None:
    section = await TlsAuditor(https_port=1, timeout=2).audit("127.0.0.1:1")
    assert section.error is not None
    assert _statuses(section)["tls.unreachable"] is Status.FAIL


def test_expired_certificate_is_critical() -> None:
    """Feed a synthetic expired certificate through the audit code path."""
    from auditors.tls_auditor import CertificateInfo

    info = CertificateInfo(
        subject="CN=localhost",
        issuer="CN=localhost",
        not_before=None,
        not_after=None,
        days_remaining=-3.0,
        san=["localhost"],
        key_type="RSA",
        key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
    )
    from core.models import Category, SectionResult

    fresh = SectionResult(category=Category.TLS)
    TlsAuditor()._check_certificate(fresh, info, "localhost")
    statuses = {f.check_id: f.status for f in fresh.findings}
    assert statuses["tls.expiry"] is Status.FAIL
    assert any(f.severity.value == "CRITICAL" for f in fresh.findings)

"""TLS & transport hygiene auditor.

Checks performed:

* certificate validity window (expiry countdown), issuer chain, SAN coverage,
  key strength and signature algorithm;
* deprecated protocol support (TLS 1.0 / 1.1) and the negotiated cipher;
* automatic HTTP → HTTPS redirection on port 80.

The certificate is parsed with ``cryptography`` from the DER blob returned by the
handshake, so the audit works even when the chain does not validate (that case is
reported as its own critical finding rather than aborting the scan).
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from core.models import Category, Finding, SectionResult, Severity, Status

log = logging.getLogger(__name__)

#: Signature OIDs that are considered broken (MD5/SHA-1 based).
WEAK_SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
}

#: Cipher name fragments that indicate a broken suite.
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES_", "NULL", "EXPORT", "MD5", "anon")

EXPIRY_CRITICAL_DAYS = 7
EXPIRY_WARNING_DAYS = 30
MAX_CERT_LIFETIME_DAYS = 398  # CA/Browser Forum limit


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: float | None = None
    san: list[str] = field(default_factory=list)
    key_type: str = ""
    key_size: int | None = None
    signature_algorithm: str = ""
    is_self_signed: bool = False
    is_ca: bool = False
    verified: bool = False
    verification_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_remaining": round(self.days_remaining, 2) if self.days_remaining is not None else None,
            "san": self.san,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "signature_algorithm": self.signature_algorithm,
            "is_self_signed": self.is_self_signed,
            "is_ca": self.is_ca,
            "verified": self.verified,
            "verification_error": self.verification_error,
        }


@dataclass
class HandshakeInfo:
    version: str | None = None
    cipher_name: str | None = None
    cipher_bits: int | None = None
    cipher_protocol: str | None = None
    der: bytes | None = None
    verification_error: str | None = None
    connected_host: str | None = None


def _hostname_matches(host: str, pattern: str) -> bool:
    """RFC 6125 style matching including one-label wildcards."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.count(".") == suffix.count(".") + 1 and host.endswith("." + suffix)
    if "*" in pattern:
        return fnmatch.fnmatchcase(host, pattern)
    return host == pattern


def _sni_name(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):  # pragma: no cover - exotic hostnames
        return host


def _ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _utc(when: datetime | None) -> datetime | None:
    if when is None:
        return None
    if when.tzinfo is None:
        return when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


class TlsAuditor:
    """Asynchronous TLS / transport auditor."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        https_port: int = 443,
        http_port: int = 80,
        user_agent: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.timeout = timeout
        self.https_port = https_port
        self.http_port = http_port
        self.user_agent = user_agent or "secaudit/1.0"
        self.verify_tls = verify_tls

    # -- public API ----------------------------------------------------------------
    async def audit(self, target: str, client: httpx.AsyncClient | None = None) -> SectionResult:
        started = time.perf_counter()
        section = SectionResult(category=Category.TLS)
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
                follow_redirects=False,
            )
        try:
            host, url = self._split_target(target)
            port = url.port if url.port and url.port not in (80, 443) else self.https_port
            section.data["host"] = host
            section.data["port"] = port

            handshake, certificate = await self._inspect_certificate(host, port)
            section.data["certificate"] = certificate.to_dict()
            if handshake.version:
                section.data["negotiated"] = {
                    "version": handshake.version,
                    "cipher": handshake.cipher_name,
                    "bits": handshake.cipher_bits,
                }

            if handshake.der is None:
                section.error = certificate.verification_error or "TLS handshake failed"
                section.add(
                    self._finding(
                        "tls.unreachable",
                        "TLS endpoint is not reachable",
                        Status.FAIL,
                        Severity.HIGH,
                        10.0,
                        "No TLS session could be established on the target port, so HTTPS "
                        "cannot be evaluated. Check DNS, the listener and the firewall.",
                        evidence=section.error,
                        remediation_key="tls.unreachable",
                        context={"target": host},
                    )
                )
                return self._finish(section, started)

            self._check_certificate(section, certificate, host)
            protocols = dict.fromkeys(("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"), False)
            if handshake.version:
                protocols[handshake.version] = True
            probe_results = await asyncio.gather(
                *(
                    self._probe_protocol(host, port, version)
                    for version in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
                ),
                return_exceptions=True,
            )
            for version, supported in zip(
                ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"), probe_results, strict=True
            ):
                if isinstance(supported, BaseException):
                    log.debug("probe for %s raised %s", version, supported)
                    continue
                protocols[version] = protocols[version] or bool(supported)
            section.data["protocols"] = protocols
            section.data["cipher"] = {
                "name": handshake.cipher_name,
                "bits": handshake.cipher_bits,
                "protocol": handshake.cipher_protocol,
            }
            self._check_protocols(section, protocols, handshake)
            self._check_https_redirect(section, await self._check_redirect(client, host), host)
            return self._finish(section, started)
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("TLS audit crashed: %s", exc)
            section.error = f"{type(exc).__name__}: {exc}"
            section.add(
                self._finding(
                    "tls.error",
                    "TLS audit failed unexpectedly",
                    Status.FAIL,
                    Severity.MEDIUM,
                    10.0,
                    "The TLS auditor raised an exception; the target's transport security "
                    "could not be determined.",
                    evidence=section.error,
                    remediation_key="tls.unreachable",
                )
            )
            return self._finish(section, started)
        finally:
            if owns_client:
                await client.aclose()

    # -- target parsing ------------------------------------------------------------
    @staticmethod
    def _split_target(target: str) -> tuple[str, httpx.URL]:
        raw = (target or "").strip()
        if not raw:
            raise ValueError("empty target")
        if "://" not in raw and raw.count(":") == 1 and raw.rsplit(":", 1)[-1].isdigit():
            # host:port without a scheme
            host, _, port = raw.partition(":")
            url = httpx.URL(f"https://{host}:{port}")
        else:
            if "://" not in raw:
                raw = "https://" + raw
            url = httpx.URL(raw)
        host = (url.host or "").rstrip(".").lower()
        if not host:
            raise ValueError(f"could not parse a hostname from {target!r}")
        return host, url

    # -- network primitives --------------------------------------------------------
    async def _handshake(self, host: str, port: int, verify: bool) -> HandshakeInfo:
        info = HandshakeInfo()
        context = _ssl_context(verify)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=context,
                    server_hostname=_sni_name(host),
                    ssl_handshake_timeout=self.timeout,
                ),
                timeout=self.timeout + 2,
            )
        except ssl.SSLCertVerificationError as exc:
            info.verification_error = f"{exc.verify_message} (code {exc.verify_code})"
            return info
        except ssl.SSLError as exc:
            info.verification_error = f"SSLError: {exc.reason or exc}"
            return info
        except (socket.gaierror, OSError) as exc:
            info.verification_error = f"{type(exc).__name__}: {exc}"
            return info
        except asyncio.TimeoutError:
            info.verification_error = f"TLS handshake timed out after {self.timeout}s"
            return info
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                info.version = ssl_object.version()
                cipher = ssl_object.cipher()
                if cipher:
                    info.cipher_name, info.cipher_protocol, info.cipher_bits = cipher
                info.der = ssl_object.getpeercert(binary_form=True)
                info.connected_host = host
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ssl.SSLError, OSError):  # pragma: no cover - shutdown race
                pass
        return info

    async def _probe_protocol(self, host: str, port: int, version: str) -> bool:
        """Return ``True`` when the server completes a handshake for ``version``."""
        mapping = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = mapping[version]
            context.maximum_version = mapping[version]
        except (ValueError, ssl.SSLError):  # pragma: no cover - old OpenSSL
            return False
        if version in {"TLSv1.0", "TLSv1.1"}:
            try:
                # Legacy suites are compiled out at the default security level.
                context.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:  # pragma: no cover
                pass
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=context,
                    server_hostname=_sni_name(host),
                    ssl_handshake_timeout=min(self.timeout, 8.0),
                ),
                timeout=min(self.timeout, 8.0) + 1,
            )
        except (ssl.SSLError, OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, OSError):  # pragma: no cover
            pass
        return True

    async def _inspect_certificate(
        self, host: str, port: int
    ) -> tuple[HandshakeInfo, CertificateInfo]:
        handshake = await self._handshake(host, port, verify=True)
        certificate = CertificateInfo()
        if handshake.der is None:
            # Retry without verification so the certificate can still be analysed.
            unverified = await self._handshake(host, port, verify=False)
            certificate.verification_error = (
                handshake.verification_error or unverified.verification_error
            )
            if unverified.der is not None:
                certificate.verified = False
                handshake = unverified
            else:
                return handshake, certificate
        else:
            certificate.verified = True

        certificate.verification_error = handshake.verification_error or certificate.verification_error
        if handshake.der:
            self._parse_certificate(handshake.der, certificate)
        return handshake, certificate

    @staticmethod
    def _parse_certificate(der: bytes, info: CertificateInfo) -> None:
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError as exc:  # pragma: no cover - defensive
            log.warning("could not parse certificate: %s", exc)
            return

        try:
            info.subject = cert.subject.rfc4514_string()
            info.issuer = cert.issuer.rfc4514_string()
            info.serial = format(cert.serial_number, "x")
            info.not_before = _utc(
                getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            )
            info.not_after = _utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
            if info.not_after:
                info.days_remaining = (
                    info.not_after - datetime.now(timezone.utc)
                ).total_seconds() / 86400.0
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                names = list(san.value.get_values_for_type(x509.DNSName))
                # IP-based SANs matter when auditing a bare address.
                names += [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
                info.san = names
            except x509.ExtensionNotFound:
                info.san = []

            info.is_self_signed = cert.issuer == cert.subject
            try:
                basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                info.is_ca = bool(basic.value.ca)
            except x509.ExtensionNotFound:
                info.is_ca = False

            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                info.key_type = "RSA"
                info.key_size = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                info.key_type = "EC"
                info.key_size = public_key.curve.key_size
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                info.key_type = "EdDSA"
                info.key_size = 256 if isinstance(public_key, ed25519.Ed25519PublicKey) else 448
            elif isinstance(public_key, dsa.DSAPublicKey):
                info.key_type = "DSA"
                info.key_size = public_key.key_size
            else:  # pragma: no cover - exotic key types
                info.key_type = type(public_key).__name__

            oid = cert.signature_algorithm_oid.dotted_string
            info.signature_algorithm = WEAK_SIGNATURE_OIDS.get(oid) or getattr(
                cert.signature_algorithm_oid, "_name", oid
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("certificate introspection failed: %s", exc)

    async def _check_redirect(self, client: httpx.AsyncClient, host: str) -> dict[str, Any]:
        """Fetch ``http://host/`` without following redirects."""
        http_port = self.http_port
        authority = host if http_port == 80 else f"{host}:{http_port}"
        url = f"http://{authority}/"
        result: dict[str, Any] = {"url": url, "status": None, "location": None, "error": None}
        try:
            request = client.build_request(
                "GET",
                url,
                headers={"User-Agent": self.user_agent, "Accept": "*/*"},
                timeout=self.timeout,
            )
            response = await client.send(request, follow_redirects=False, stream=True)
            try:
                result["status"] = response.status_code
                result["location"] = response.headers.get("location")
                result["server"] = response.headers.get("server")
            finally:
                await response.aclose()
        except httpx.HTTPError as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # pragma: no cover - defensive
            result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    # -- checks --------------------------------------------------------------------
    def _check_certificate(
        self, section: SectionResult, cert: CertificateInfo, host: str
    ) -> None:
        context = {"target": host}

        if cert.verification_error:
            section.add(
                self._finding(
                    "tls.trust",
                    "TLS certificate chain does not validate",
                    Status.FAIL,
                    Severity.CRITICAL,
                    10.0,
                    "Browsers will show a full-page interstitial and refuse to load the site. "
                    "This is typically an expired certificate, a missing intermediate, a "
                    "hostname mismatch or a self-signed certificate.",
                    evidence=cert.verification_error,
                    remediation_key="tls.trust",
                    context=context,
                    references=["https://www.ssllabs.com/ssltest/"],
                )
            )
        else:
            section.add(
                self._finding(
                    "tls.trust",
                    "TLS certificate chain validates against the system trust store",
                    Status.PASS,
                    Severity.PASS,
                    10.0,
                    "The leaf certificate chains to a trusted root and the hostname matches.",
                    evidence=f"issuer: {cert.issuer or 'unknown'}",
                )
            )

        if cert.days_remaining is None:
            return

        days = cert.days_remaining
        expiry = cert.not_after.date().isoformat() if cert.not_after else "unknown"
        if days < 0:
            section.add(
                self._finding(
                    "tls.expiry",
                    "TLS certificate has expired",
                    Status.FAIL,
                    Severity.CRITICAL,
                    9.0,
                    "An expired certificate blocks every visitor and any API client that "
                    "validates TLS.",
                    evidence=f"expired {abs(days):.1f} day(s) ago (notAfter={expiry})",
                    remediation_key="tls.expiry",
                    context=context,
                )
            )
        elif days < EXPIRY_CRITICAL_DAYS:
            section.add(
                self._finding(
                    "tls.expiry",
                    f"TLS certificate expires in {days:.1f} days",
                    Status.FAIL,
                    Severity.HIGH,
                    9.0,
                    "Renewal is imminent: an expired certificate takes the site down for every "
                    "client that validates TLS.",
                    evidence=f"notAfter={expiry} ({days:.1f} days remaining)",
                    remediation_key="tls.expiry",
                    context=context,
                )
            )
        elif days < EXPIRY_WARNING_DAYS:
            section.add(
                self._finding(
                    "tls.expiry",
                    f"TLS certificate expires in {days:.1f} days",
                    Status.WARN,
                    Severity.MEDIUM,
                    9.0,
                    "Certificates must be renewed before they expire; automate renewal and "
                    "alert at 30 days.",
                    evidence=f"notAfter={expiry} ({days:.1f} days remaining)",
                    remediation_key="tls.expiry",
                    context=context,
                )
            )
        else:
            section.add(
                self._finding(
                    "tls.expiry",
                    "TLS certificate is valid for the next 30+ days",
                    Status.PASS,
                    Severity.PASS,
                    9.0,
                    "The certificate has a comfortable validity window remaining.",
                    evidence=f"notAfter={expiry} ({days:.1f} days remaining)",
                )
            )

        if cert.not_before and cert.not_after:
            lifetime = (cert.not_after - cert.not_before).days
            if lifetime > MAX_CERT_LIFETIME_DAYS:
                section.add(
                    self._finding(
                        "tls.certificate_lifetime",
                        f"Certificate lifetime is {lifetime} days",
                        Status.WARN,
                        Severity.LOW,
                        1.0,
                        "Public CAs may not issue certificates valid for more than 398 days; "
                        "long-lived certificates delay key rotation.",
                        evidence=f"{cert.not_before.date()} → {cert.not_after.date()}",
                        remediation_key="tls.expiry",
                    )
                )

        if cert.is_self_signed:
            section.add(
                self._finding(
                    "tls.self_signed",
                    "TLS certificate is self-signed",
                    Status.FAIL,
                    Severity.CRITICAL,
                    6.0,
                    "Self-signed certificates are trusted by no client; they provide "
                    "encryption but no authentication.",
                    evidence=cert.subject,
                    remediation_key="tls.trust",
                    context=context,
                )
            )

        # -- SAN coverage -----------------------------------------------------------
        if not cert.san:
            section.add(
                self._finding(
                    "tls.certificate_san",
                    "Certificate has no Subject Alternative Names",
                    Status.WARN,
                    Severity.HIGH,
                    4.0,
                    "Modern clients validate the hostname against the SAN extension only; "
                    "the legacy Common Name is ignored.",
                    evidence=f"subject: {cert.subject}",
                    remediation_key="tls.certificate_san",
                    context=context,
                )
            )
        elif not any(_hostname_matches(host, name) for name in cert.san):
            section.add(
                self._finding(
                    "tls.certificate_san",
                    "Certificate SANs do not cover the audited hostname",
                    Status.FAIL,
                    Severity.HIGH,
                    4.0,
                    f"The certificate is valid for {', '.join(cert.san[:8])} but not for "
                    f"{host}; clients will reject the connection.",
                    evidence=f"SAN: {', '.join(cert.san)}",
                    remediation_key="tls.certificate_san",
                    context=context,
                )
            )
        else:
            section.add(
                self._finding(
                    "tls.certificate_san",
                    f"Certificate covers {host}",
                    Status.PASS,
                    Severity.PASS,
                    4.0,
                    "The hostname is present in the certificate's SAN extension.",
                    evidence=f"SAN: {', '.join(cert.san[:8])}"
                    + (f" (+{len(cert.san) - 8} more)" if len(cert.san) > 8 else ""),
                )
            )

        # -- key / signature --------------------------------------------------------
        weak_key = (
            (cert.key_type == "RSA" and (cert.key_size or 0) < 2048)
            or (cert.key_type == "EC" and (cert.key_size or 0) < 256)
            or (cert.key_type == "DSA")
        )
        weak_signature = cert.signature_algorithm in WEAK_SIGNATURE_OIDS.values()
        if weak_key or weak_signature:
            problems = []
            if weak_key:
                problems.append(f"{cert.key_type} {cert.key_size}-bit key")
            if weak_signature:
                problems.append(f"{cert.signature_algorithm} signature")
            section.add(
                self._finding(
                    "tls.certificate_key",
                    "Certificate uses a weak key or signature algorithm",
                    Status.FAIL,
                    Severity.HIGH,
                    4.0,
                    "Weak keys and legacy hashes (" + ", ".join(problems) + ") are "
                    "considered broken: use RSA ≥ 2048/3072 or EC P-256 with SHA-256.",
                    evidence=", ".join(problems),
                    remediation_key="tls.certificate_key",
                    context=context,
                )
            )
        else:
            section.add(
                self._finding(
                    "tls.certificate_key",
                    "Certificate key and signature algorithm are modern",
                    Status.PASS,
                    Severity.PASS,
                    4.0,
                    f"{cert.key_type} {cert.key_size or ''} with {cert.signature_algorithm}.",
                    evidence=f"{cert.key_type} {cert.key_size} / {cert.signature_algorithm}",
                )
            )

    def _check_protocols(
        self, section: SectionResult, protocols: dict[str, bool], handshake: HandshakeInfo
    ) -> None:
        for version in ("TLSv1.0", "TLSv1.1"):
            supported = protocols.get(version, False)
            section.add(
                self._finding(
                    f"tls.protocol.{version.replace('v', '').replace('.', '_').lower()}",
                    f"Deprecated {version} is {'supported' if supported else 'disabled'}",
                    Status.FAIL if supported else Status.PASS,
                    Severity.HIGH if supported else Severity.PASS,
                    4.0,
                    f"{version} is deprecated by RFC 8996 and vulnerable to a long list of "
                    "downgrade and padding-oracle attacks. Disable it and require TLS 1.2+.",
                    evidence=f"{version}: {'accepted' if supported else 'rejected'}",
                    remediation_key="tls.protocol" if supported else None,
                )
            )

        tls12 = protocols.get("TLSv1.2", False)
        tls13 = protocols.get("TLSv1.3", False)
        section.add(
            self._finding(
                "tls.protocol.tls12",
                f"TLS 1.2 is {'supported' if tls12 else 'not supported'}",
                Status.PASS if tls12 else Status.FAIL,
                Severity.PASS if tls12 else Severity.MEDIUM,
                2.0,
                "TLS 1.2 is the compatibility baseline for modern clients.",
                evidence=f"TLSv1.2: {'accepted' if tls12 else 'rejected'}",
                remediation_key=None if tls12 else "tls.protocol",
            )
        )
        section.add(
            self._finding(
                "tls.protocol.tls13",
                f"TLS 1.3 is {'enabled' if tls13 else 'not enabled'}",
                Status.PASS if tls13 else Status.WARN,
                Severity.PASS if tls13 else Severity.LOW,
                2.0,
                "TLS 1.3 removes legacy crypto, enables 0-RTT resumption control and is "
                "faster; enable it on every modern edge.",
                evidence=f"TLSv1.3: {'accepted' if tls13 else 'rejected'}",
                remediation_key=None if tls13 else "tls.protocol",
            )
        )

        cipher_name = handshake.cipher_name or ""
        weak = [marker for marker in WEAK_CIPHER_MARKERS if marker.lower() in cipher_name.lower()]
        if handshake.cipher_bits is not None and handshake.cipher_bits < 128:
            weak.append(f"{handshake.cipher_bits}-bit")
        if weak:
            section.add(
                self._finding(
                    "tls.cipher",
                    "Negotiated cipher suite is weak",
                    Status.FAIL,
                    Severity.HIGH,
                    3.0,
                    "The negotiated suite (" + cipher_name + ") is not considered secure; "
                    "restrict the server to AEAD suites with forward secrecy.",
                    evidence=f"{cipher_name} ({handshake.cipher_bits} bits, {handshake.cipher_protocol})",
                    remediation_key="tls.cipher",
                )
            )
        elif cipher_name:
            section.add(
                self._finding(
                    "tls.cipher",
                    "Negotiated cipher suite is strong",
                    Status.PASS,
                    Severity.PASS,
                    3.0,
                    "The handshake selected an AEAD / forward-secret suite with adequate strength.",
                    evidence=f"{cipher_name} ({handshake.cipher_bits} bits, {handshake.cipher_protocol})",
                )
            )

    def _check_https_redirect(
        self, section: SectionResult, redirect: dict[str, Any], host: str
    ) -> None:
        section.data["https_redirect"] = redirect
        status = redirect.get("status")
        location = (redirect.get("location") or "").strip()
        error = redirect.get("error")

        if error:
            section.add(
                self._finding(
                    "tls.https_redirect",
                    "No plaintext HTTP service on port 80",
                    Status.PASS,
                    Severity.PASS,
                    6.0,
                    "Port 80 refused the connection, so plaintext traffic cannot be served "
                    "at all — an acceptable alternative to an explicit redirect.",
                    evidence=error,
                )
            )
            return

        if status is not None and 300 <= status < 400 and location.lower().startswith("https://"):
            section.add(
                self._finding(
                    "tls.https_redirect",
                    "Plaintext HTTP redirects to HTTPS",
                    Status.PASS,
                    Severity.PASS,
                    6.0,
                    f"Port 80 answers HTTP {status} with a redirect to {location}, so "
                    "visitors are upgraded automatically.",
                    evidence=f"HTTP {status} → {location}",
                )
            )
        elif status is not None and 300 <= status < 400:
            section.add(
                self._finding(
                    "tls.https_redirect",
                    "HTTP redirects to a non-HTTPS location",
                    Status.FAIL,
                    Severity.MEDIUM,
                    6.0,
                    "The port 80 redirect target is not HTTPS, so plaintext traffic is not "
                    "upgraded.",
                    evidence=f"HTTP {status} → {location}",
                    remediation_key="tls.https_redirect",
                    context={"target": host},
                )
            )
        elif status is not None and 200 <= status < 300:
            section.add(
                self._finding(
                    "tls.https_redirect",
                    "Content is served over plaintext HTTP",
                    Status.FAIL,
                    Severity.HIGH,
                    6.0,
                    "Port 80 returns HTTP " + str(status) + " without redirecting to HTTPS. "
                    "Any plaintext response can be read and modified on-path.",
                    evidence=f"GET http://{host}/ → HTTP {status}",
                    remediation_key="tls.https_redirect",
                    context={"target": host},
                )
            )
        else:
            section.add(
                self._finding(
                    "tls.https_redirect",
                    "Port 80 returned an unexpected response",
                    Status.WARN,
                    Severity.LOW,
                    6.0,
                    "The plaintext endpoint answered with an unexpected status; confirm it "
                    "redirects (or refuses) rather than serving content.",
                    evidence=f"HTTP {status}",
                    remediation_key="tls.https_redirect",
                    context={"target": host},
                )
            )

    # -- helpers -------------------------------------------------------------------
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
        references: list[str] | None = None,
    ) -> Finding:
        if evidence:
            evidence = " ".join(str(evidence).split())
            if len(evidence) > 300:
                evidence = evidence[:299] + "…"
        return Finding(
            check_id=check_id,
            title=title,
            category=Category.TLS,
            severity=severity,
            status=status,
            weight=weight,
            description=description,
            evidence=evidence,
            remediation_key=remediation_key,
            context=context or {},
            references=references or [],
        )

    @staticmethod
    def _finish(section: SectionResult, started: float) -> SectionResult:
        section.duration_ms = (time.perf_counter() - started) * 1000
        return section

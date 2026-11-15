"""DNS auditor tests using a stubbed resolver (no network access required)."""

from __future__ import annotations

from typing import Any

from auditors.dns_auditor import DnsAnswer, DnsAuditor
from core.models import Status

HOST = "example.test"


class StubDns(DnsAuditor):
    """DnsAuditor with a canned zone."""

    def __init__(
        self, records: dict[tuple[str, str], Any], *, default_error: str = "NXDOMAIN", **kwargs: Any
    ) -> None:
        kwargs.setdefault("probe_http", False)
        kwargs.setdefault("fingerprints_path", None)
        super().__init__(**kwargs)
        self.default_error = default_error
        self.records = {
            (name.lower().rstrip("."), rdtype.upper()): value
            for (name, rdtype), value in records.items()
        }

    async def _query(self, name: str, rdtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rdtype.upper())
        value = self.records.get(key)
        answer = DnsAnswer(name=key[0], rdtype=key[1])
        if value is None:
            answer.error = self.default_error
        elif isinstance(value, str):
            answer.error = value
        else:
            answer.values = list(value)
        return answer


def statuses(section) -> dict[str, Status]:  # type: ignore[no-untyped-def]
    return {finding.check_id: finding.status for finding in section.findings}


def healthy_zone() -> dict[tuple[str, str], Any]:
    return {
        (HOST, "A"): ["203.0.113.10"],
        (HOST, "AAAA"): ["2001:db8::10"],
        (HOST, "NS"): ["ns1.example.test", "ns2.example.test"],
        (HOST, "MX"): ["10 mx1.example.test"],
        (HOST, "TXT"): [
            "v=spf1 mx include:_spf.example.test -all",
            "google-site-verification=abc",
        ],
        ("_spf.example.test", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"],
        (f"_dmarc.{HOST}", "TXT"): [
            "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.test; pct=100"
        ],
        (HOST, "CAA"): [
            '0 issue "letsencrypt.org"',
            '0 issuewild ";"',
            '0 iodef "mailto:security@example.test"',
        ],
        (HOST, "DNSKEY"): ["flags=257 algorithm=13 key_tag=12345"],
        (HOST, "DS"): ["key_tag=12345 algorithm=13 digest_type=2"],
        ("_mta-sts.example.test", "TXT"): ["v=STSv1; id=20260101000000"],
        ("_smtp._tls.example.test", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@example.test"],
    }


class TestHealthyZone:
    async def test_all_major_controls_pass(self) -> None:
        section = await StubDns(healthy_zone()).audit(HOST)
        result = statuses(section)
        assert section.error is None
        assert result["dns.resolve"] is Status.PASS
        assert result["dns.spf.present"] is Status.PASS
        assert result["dns.spf.all"] is Status.PASS
        assert result["dns.spf.lookups"] is Status.PASS
        assert result["dns.dmarc.present"] is Status.PASS
        assert result["dns.dmarc.policy"] is Status.PASS
        assert result["dns.dmarc.rua"] is Status.PASS
        assert result["dns.caa.present"] is Status.PASS
        assert result["dns.dnssec.enabled"] is Status.PASS
        assert result["dns.cname.chain"] is Status.PASS
        assert not [f for f in section.findings if f.status is Status.FAIL]

    async def test_records_are_exposed(self) -> None:
        section = await StubDns(healthy_zone()).audit(HOST)
        assert section.data["records"]["a"]["values"] == ["203.0.113.10"]
        assert section.data["spf"]["lookup_count"] == 2  # mx + include
        assert section.data["dmarc"]["tags"]["p"] == "reject"


class TestSpfProblems:
    async def test_permissive_all(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "TXT")] = ["v=spf1 +all"]
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.spf.all"] is Status.FAIL

    async def test_neutral_all(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "TXT")] = ["v=spf1 ?all"]
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.spf.all"] is Status.WARN

    async def test_missing_spf(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "TXT")] = ["google-site-verification=abc"]
        section = await StubDns(zone).audit(HOST)
        assert statuses(section)["dns.spf.missing"] is Status.FAIL

    async def test_multiple_records(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "TXT")] = ["v=spf1 -all", "v=spf1 include:other.test ~all"]
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.spf.multiple"] is Status.FAIL

    async def test_lookup_budget_exceeded(self) -> None:
        zone = healthy_zone()
        includes = " ".join(f"include:spf{i}.example.test" for i in range(12))
        zone[(HOST, "TXT")] = [f"v=spf1 {includes} -all"]
        for index in range(12):
            zone[(f"spf{index}.example.test", "TXT")] = [f"v=spf1 include:nested{index}.test -all"]
            zone[(f"nested{index}.test", "TXT")] = ["v=spf1 ip4:198.51.100.1 -all"]
        section = await StubDns(zone).audit(HOST)
        assert statuses(section)["dns.spf.lookups"] is Status.FAIL
        assert section.data["spf"]["lookup_count"] > 10

    async def test_deprecated_ptr(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "TXT")] = ["v=spf1 ptr mx -all"]
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.spf.ptr"] is Status.WARN


class TestDmarcProblems:
    async def test_missing_dmarc(self) -> None:
        zone = healthy_zone()
        zone[(f"_dmarc.{HOST}", "TXT")] = None
        section = await StubDns(zone).audit(HOST)
        assert statuses(section)["dns.dmarc.missing"] is Status.FAIL

    async def test_policy_none(self) -> None:
        zone = healthy_zone()
        zone[(f"_dmarc.{HOST}", "TXT")] = ["v=DMARC1; p=none"]
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.dmarc.policy"] is Status.WARN
        assert result["dns.dmarc.rua"] is Status.WARN

    async def test_inherited_from_organisational_domain(self) -> None:
        zone = healthy_zone()
        zone.pop((f"_dmarc.{HOST}", "TXT"))
        zone[(f"_dmarc.{HOST}", "TXT")] = None
        zone[("_dmarc.example.test", "TXT")] = [
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.test"
        ]
        zone[("sub.example.test", "A")] = ["203.0.113.11"]
        section = await StubDns(zone).audit("sub.example.test")
        result = statuses(section)
        assert result["dns.dmarc.present"] is Status.PASS
        assert section.data["dmarc"]["inherited"] is True


class TestCaaAndDnssec:
    async def test_missing_caa(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "CAA")] = None
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.caa.missing"] is Status.WARN

    async def test_caa_inherits_from_parent(self) -> None:
        zone = healthy_zone()
        zone[("example.test", "CAA")] = ['0 issue "pki.goog"']
        zone[("_dmarc.example.test", "TXT")] = ["v=DMARC1; p=reject"]
        zone[("www.example.test", "A")] = ["203.0.113.12"]
        section = await StubDns(zone).audit("www.example.test")
        assert statuses(section)["dns.caa.present"] is Status.PASS
        assert "inherited" in section.data["caa"]["source"]

    async def test_dnssec_chain_broken(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "DS")] = None
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.dnssec.missing_ds"] is Status.WARN

    async def test_dnssec_bogus(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "DNSKEY")] = None
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.dnssec.bogus"] is Status.FAIL

    async def test_dnssec_absent(self) -> None:
        zone = healthy_zone()
        zone[(HOST, "DNSKEY")] = None
        zone[(HOST, "DS")] = None
        result = statuses(await StubDns(zone).audit(HOST))
        assert result["dns.dnssec.missing"] is Status.WARN


class TestCnameTakeover:
    async def test_dangling_cname_is_critical(self) -> None:
        zone = healthy_zone()
        zone[("blog.example.test", "CNAME")] = ["old-site.github.io"]
        zone[("blog.example.test", "A")] = "NXDOMAIN"
        zone[("old-site.github.io", "A")] = "NXDOMAIN"
        section = await StubDns(zone).audit("blog.example.test")
        dangling = [f for f in section.findings if f.check_id == "dns.cname.dangling"]
        assert dangling, [f.check_id for f in section.findings]
        assert dangling[0].status is Status.FAIL
        assert dangling[0].severity.value == "CRITICAL"
        assert "GitHub Pages" in dangling[0].title
        assert section.data["cname_chain"][0]["service"] == "GitHub Pages"

    async def test_resolving_third_party_is_a_warning(self) -> None:
        zone = healthy_zone()
        zone[("docs.example.test", "CNAME")] = ["docs.example.readme.io"]
        zone[("docs.example.readme.io", "A")] = ["203.0.113.50"]
        section = await StubDns(zone).audit("docs.example.test")
        findings = {f.check_id: f for f in section.findings}
        assert findings["dns.cname.claimable"].status is Status.WARN
        assert findings["dns.cname.claimable"].severity.value in {"HIGH", "MEDIUM"}

    async def test_generic_dead_cname(self) -> None:
        zone = healthy_zone()
        zone[("api.example.test", "CNAME")] = ["gone.internal.example.test"]
        zone[("gone.internal.example.test", "A")] = "NXDOMAIN"
        section = await StubDns(zone).audit("api.example.test")
        dangling = [f for f in section.findings if f.check_id == "dns.cname.dangling"]
        assert dangling and dangling[0].severity.value == "CRITICAL"
        assert "non-existent" in dangling[0].title

    async def test_no_cname(self) -> None:
        section = await StubDns(healthy_zone()).audit(HOST)
        assert statuses(section)["dns.cname.chain"] is Status.PASS


class TestFailureModes:
    async def test_transport_failure(self) -> None:
        section = await StubDns({}, default_error="timeout").audit(HOST)
        assert section.error is not None
        assert statuses(section)["dns.unreachable"] is Status.FAIL

    async def test_nxdomain_is_a_resolution_finding(self) -> None:
        zone = {(HOST, "A"): "NXDOMAIN", (HOST, "TXT"): "NXDOMAIN"}
        section = await StubDns(zone).audit(HOST)
        assert section.error is None
        assert statuses(section)["dns.resolve"] is Status.FAIL

    async def test_fingerprint_db_is_loaded(self) -> None:
        auditor = StubDns(healthy_zone())
        assert len(auditor.fingerprints) >= 20
        assert auditor.match_fingerprint("x.github.io")["service"] == "GitHub Pages"
        assert auditor.match_fingerprint("evil-github.io") is None
        assert auditor.match_fingerprint("s3.amazonaws.com")["service"] == "Amazon S3"

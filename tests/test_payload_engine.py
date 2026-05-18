"""Tests for AdaptivePayloadEngine."""

import pytest
from shadow.payloads.fingerprint import TargetProfile
from shadow.payloads.engine import AdaptivePayloadEngine, Payload


def make_profile(db="generic", framework="unknown", waf="none", filtered=None):
    return TargetProfile(
        target="https://example.com",
        db_type=db,
        framework=framework,
        waf_vendor=waf,
        filtered_chars=set(filtered or []),
    )


class TestAdaptivePayloadEngine:
    @pytest.fixture
    def engine(self):
        return AdaptivePayloadEngine()

    def test_generate_returns_list_of_payloads(self, engine):
        profile = make_profile()
        payloads = engine.generate(profile, "sqli")
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        assert all(isinstance(p, Payload) for p in payloads)

    def test_mysql_profile_generates_mysql_payloads(self, engine):
        profile = make_profile(db="MySQL")
        payloads = engine.generate(profile, "sqli")
        raws = [p.raw for p in payloads]
        assert any("SLEEP" in r for r in raws)

    def test_postgresql_profile_generates_pg_payloads(self, engine):
        profile = make_profile(db="PostgreSQL")
        payloads = engine.generate(profile, "sqli")
        raws = [p.raw for p in payloads]
        assert any("pg_sleep" in r.lower() for r in raws)

    def test_xss_payloads_contain_script_tags(self, engine):
        profile = make_profile()
        payloads = engine.generate(profile, "xss")
        raws = [p.raw for p in payloads]
        assert any("script" in r.lower() or "onerror" in r.lower() for r in raws)

    def test_ssti_jinja2_payloads(self, engine):
        profile = make_profile(framework="Jinja2")
        payloads = engine.generate(profile, "ssti")
        raws = [p.raw for p in payloads]
        assert any("{{" in r for r in raws)

    def test_filtered_chars_trigger_encoding(self, engine):
        profile = make_profile(filtered=["'"])
        payloads = engine.generate(profile, "sqli")
        encodings = [p.encoding for p in payloads]
        assert "url_encode" in encodings

    def test_cloudflare_waf_triggers_bypasses(self, engine):
        profile = make_profile(waf="Cloudflare")
        payloads = engine.generate(profile, "sqli")
        bypass_methods = [p.bypass_method for p in payloads]
        assert any(b != "none" for b in bypass_methods)

    def test_no_waf_no_bypass(self, engine):
        profile = make_profile(waf="none")
        payloads = engine.generate(profile, "sqli")
        bypass_methods = [p.bypass_method for p in payloads]
        assert all(b == "none" for b in bypass_methods)

    def test_generate_variants_returns_different_payloads(self, engine):
        original = Payload(raw="' OR 1=1--", vuln_class="sqli")
        variants = engine.generate_variants(original, {"anomaly": "timing_spike"})
        assert len(variants) > 0
        assert all(v.raw != original.raw or v.encoding != original.encoding for v in variants)

    def test_url_encoding_applied(self, engine):
        profile = make_profile(filtered=["'"])
        payloads = engine.generate(profile, "sqli")
        url_encoded = [p for p in payloads if p.encoding == "url_encode"]
        assert len(url_encoded) > 0
        assert any("%" in p.raw for p in url_encoded)

    def test_comment_bypass_replaces_spaces(self, engine):
        profile = make_profile(waf="ModSecurity")
        payloads = engine.generate(profile, "sqli")
        comment_payloads = [p for p in payloads if p.bypass_method == "comment"]
        assert len(comment_payloads) > 0
        assert any("/**/" in p.raw for p in comment_payloads)

    def test_ssrf_payloads_contain_metadata_url(self, engine):
        profile = make_profile()
        payloads = engine.generate(profile, "ssrf")
        raws = [p.raw for p in payloads]
        assert any("169.254.169.254" in r for r in raws)

"""Tests for TargetFingerprinter."""

import pytest
from shadow.payloads.fingerprint import TargetFingerprinter, TargetProfile


class TestTargetFingerprinter:
    @pytest.fixture
    def fp(self):
        return TargetFingerprinter()

    def test_profile_returns_target_profile(self, fp):
        profile = fp.profile("https://example.com")
        assert isinstance(profile, TargetProfile)
        assert profile.target == "https://example.com"

    def test_detects_laravel_from_cookie(self, fp):
        headers = {"Set-Cookie": "laravel_session=abc123"}
        profile = fp.profile("https://x.com", response_headers=headers)
        assert profile.framework == "Laravel"

    def test_detects_django_from_cookie(self, fp):
        headers = {"Set-Cookie": "csrftoken=xyz"}
        profile = fp.profile("https://x.com", response_headers=headers)
        assert profile.framework == "Django"

    def test_detects_aspnet_from_header(self, fp):
        headers = {"X-Powered-By": "ASP.NET"}
        profile = fp.profile("https://x.com", response_headers=headers)
        assert profile.framework == "ASP.NET"

    def test_detects_mysql_from_error(self, fp):
        errors = ["You have an error in your SQL syntax near 'admin'"]
        profile = fp.profile("https://x.com", error_messages=errors)
        assert profile.db_type == "MySQL"

    def test_detects_postgresql_from_error(self, fp):
        errors = ["syntax error at or near 'SELECT'"]
        profile = fp.profile("https://x.com", error_messages=errors)
        assert profile.db_type == "PostgreSQL"

    def test_detects_cloudflare_waf(self, fp):
        headers = {"CF-Ray": "abc123", "Server": "cloudflare"}
        profile = fp.profile("https://x.com", response_headers=headers)
        assert profile.waf_vendor == "Cloudflare"

    def test_no_waf_detected(self, fp):
        headers = {"Server": "nginx"}
        profile = fp.profile("https://x.com", response_headers=headers)
        assert profile.waf_vendor == "none"

    def test_timing_baseline_calculated(self, fp):
        profile = fp.profile("https://x.com", timing_samples=[100.0, 200.0, 150.0])
        assert profile.timing_baseline_ms == 150.0

    def test_timing_baseline_zero_when_no_samples(self, fp):
        profile = fp.profile("https://x.com")
        assert profile.timing_baseline_ms == 0.0

    def test_error_verbosity_verbose_when_errors(self, fp):
        profile = fp.profile("https://x.com", error_messages=["SQL error"])
        assert profile.error_verbosity == "verbose"

    def test_error_verbosity_silent_when_no_errors(self, fp):
        profile = fp.profile("https://x.com")
        assert profile.error_verbosity == "silent"

    def test_tech_stack_populated(self, fp):
        headers = {"Set-Cookie": "laravel_session=abc", "CF-Ray": "xyz"}
        errors = ["You have an error in your SQL syntax"]
        profile = fp.profile("https://x.com", response_headers=headers, error_messages=errors)
        assert "Laravel" in profile.tech_stack
        assert "MySQL" in profile.tech_stack
        assert any("WAF" in s for s in profile.tech_stack)

    def test_unknown_framework_when_no_signatures(self, fp):
        profile = fp.profile("https://x.com", response_headers={"Server": "nginx"})
        assert profile.framework == "unknown"

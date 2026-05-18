"""Tests for PayloadMutator."""

import pytest
from shadow.payloads.mutator import PayloadMutator


class TestPayloadMutator:
    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_url_encode(self, mutator):
        result = mutator.url_encode("' OR 1=1--")
        assert "%" in result
        assert "'" not in result

    def test_double_url_encode(self, mutator):
        result = mutator.double_url_encode("' OR 1=1--")
        assert "%25" in result or "%2" in result

    def test_html_entity_encode(self, mutator):
        result = mutator.html_entity_encode("<script>alert(1)</script>")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "<" not in result

    def test_comment_injection(self, mutator):
        result = mutator.comment_inject("SELECT * FROM users")
        assert "/**/" in result
        assert " " not in result

    def test_case_variation(self, mutator):
        result = mutator.case_vary("select")
        assert result != "select"
        assert result.lower() == "select"

    def test_whitespace_substitution(self, mutator):
        result = mutator.whitespace_sub("SELECT * FROM users")
        assert "\t" in result

    def test_null_byte_injection(self, mutator):
        result = mutator.null_byte("admin")
        assert "%00" in result

    def test_unicode_encode(self, mutator):
        result = mutator.unicode_encode("'")
        assert "\\u" in result

    def test_mutate_all_returns_list(self, mutator):
        results = mutator.mutate_all("' OR 1=1--")
        assert isinstance(results, list)
        assert len(results) > 1
        assert all(isinstance(r, str) for r in results)

    def test_mutate_all_includes_original(self, mutator):
        original = "' OR 1=1--"
        results = mutator.mutate_all(original)
        assert original in results

    def test_waf_bypass_variants(self, mutator):
        results = mutator.waf_bypass_variants("SELECT", waf_vendor="ModSecurity")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_waf_bypass_cloudflare(self, mutator):
        results = mutator.waf_bypass_variants("' OR 1=1--", waf_vendor="Cloudflare")
        assert any("%" in r for r in results)

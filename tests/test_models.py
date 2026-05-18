import pytest
from shadow.core.models import (
    Finding, FindingStatus, Evidence, Severity, ScopeEntry, Scope, Engagement
)


class TestFinding:
    def test_creation_minimal(self):
        f = Finding(title="SQLi in login", vuln_class="sqli", target="https://x.com/login")
        assert f.title == "SQLi in login"
        assert f.status == FindingStatus.DRAFT
        assert f.severity == Severity.INFO

    def test_has_evidence_false_when_empty(self):
        f = Finding(title="X", vuln_class="xss", target="https://x.com")
        assert not f.has_evidence()

    def test_has_evidence_with_request(self):
        e = Evidence(request="GET / HTTP/1.1\r\n\r\n")
        f = Finding(title="X", vuln_class="xss", target="https://x.com", evidence=e)
        assert f.has_evidence()

    def test_has_evidence_with_oob_hit(self):
        f = Finding(title="Blind SQLi", vuln_class="sqli", target="https://x.com", oob_hit="shadow-test.interactsh.com")
        assert f.has_evidence()

    def test_to_dict_serializes_enums(self):
        f = Finding(title="SQLi", vuln_class="sqli", target="https://x.com", parameter="q")
        d = f.to_dict()
        assert d["status"] == "draft"
        assert d["severity"] == "info"
        assert d["parameter"] == "q"

    def test_created_at_is_set(self):
        f = Finding(title="X", vuln_class="xss", target="https://x.com")
        assert f.created_at is not None


class TestScopeEntry:
    def test_exact_match(self):
        s = ScopeEntry(domain="example.com")
        assert s.matches("example.com")
        assert s.matches("https://example.com/path")

    def test_subdomain_match(self):
        s = ScopeEntry(domain="example.com", include_subdomains=True)
        assert s.matches("sub.example.com")

    def test_no_match(self):
        s = ScopeEntry(domain="example.com")
        assert not s.matches("other.com")
        assert not s.matches("notexample.com")

    def test_wildcard_match(self):
        s = ScopeEntry(domain="example.com", wildcard=True)
        assert s.matches("anything.example.com")


class TestScope:
    def test_matches_any_entry(self):
        scope = Scope(entries=[ScopeEntry(domain="a.com"), ScopeEntry(domain="b.com")])
        assert scope.matches("a.com")
        assert scope.matches("b.com")
        assert not scope.matches("c.com")

    def test_empty_scope_matches_nothing(self):
        scope = Scope()
        assert not scope.matches("example.com")


class TestEngagement:
    def test_creation(self):
        e = Engagement(platform="hackerone", program="tesla", workspace_path="/tmp/tesla")
        assert e.platform == "hackerone"
        assert e.program == "tesla"
        assert len(e.scope.entries) == 0

import os, tempfile
import pytest
from shadow.core.models import Finding, Evidence, Scope, ScopeEntry
from shadow.core.store import FindingStore
from shadow.agents.chain import ChainAgent


def make_store(tmpdir):
    return FindingStore(tmpdir)


def make_finding(title, vuln_class, target, cvss_score=None):
    f = Finding(
        title=title,
        vuln_class=vuln_class,
        target=target,
        reproduction_steps=["step"],
        impact="test impact",
        evidence=Evidence(request="GET /", response="200 OK"),
    )
    f.cvss_score = cvss_score
    return f


class TestChainAgent:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as d:
            yield FindingStore(d)

    def test_build_chain_not_found(self, store):
        agent = ChainAgent(store)
        result = agent.build_chain("F999")
        assert "error" in result

    def test_build_chain_single_finding(self, store):
        f = make_finding("SQLi", "sqli", "https://example.com/login", cvss_score=8.0)
        store.save(f)
        agent = ChainAgent(store)
        result = agent.build_chain(f.id)
        assert result["chain_length"] >= 1
        assert result["root_finding"] == f.id

    def test_build_chain_groups_by_domain(self, store):
        f1 = make_finding("XSS", "xss", "https://example.com/search", cvss_score=5.0)
        f2 = make_finding("SQLi", "sqli", "https://example.com/login", cvss_score=8.0)
        f3 = make_finding("Other", "sqli", "https://other.com/login", cvss_score=7.0)
        store.save(f1)
        store.save(f2)
        store.save(f3)
        agent = ChainAgent(store)
        result = agent.build_chain(f1.id)
        chain_ids = [c["id"] for c in result["chain"]]
        assert f1.id in chain_ids
        assert f2.id in chain_ids
        assert f3.id not in chain_ids  # different domain

    def test_chain_ordered_by_exploit_order(self, store):
        f1 = make_finding("XSS", "xss", "https://example.com/", cvss_score=5.0)
        f2 = make_finding("RCE", "rce", "https://example.com/", cvss_score=9.5)
        store.save(f1)
        store.save(f2)
        agent = ChainAgent(store)
        result = agent.build_chain(f1.id)
        chain = result["chain"]
        # XSS (order 3) should come before RCE (order 6)
        xss_step = next(c["step"] for c in chain if c["vuln_class"] == "xss")
        rce_step = next(c["step"] for c in chain if c["vuln_class"] == "rce")
        assert xss_step < rce_step

    def test_combined_severity_increases(self, store):
        f1 = make_finding("XSS", "xss", "https://example.com/", cvss_score=5.0)
        f2 = make_finding("SQLi", "sqli", "https://example.com/", cvss_score=8.0)
        store.save(f1)
        store.save(f2)
        agent = ChainAgent(store)
        result = agent.build_chain(f1.id)
        assert result["combined_cvss"] > 8.0  # higher than individual max

    def test_create_chain_finding(self, store):
        f1 = make_finding("XSS", "xss", "https://example.com/", cvss_score=5.0)
        f2 = make_finding("RCE", "rce", "https://example.com/", cvss_score=9.5)
        store.save(f1)
        store.save(f2)
        agent = ChainAgent(store)
        chain_result = agent.build_chain(f1.id)
        chain_finding = agent.create_chain_finding(chain_result)
        assert chain_finding.vuln_class == "chain"
        assert len(chain_finding.chain_parents) >= 1
        assert "Exploit Chain" in chain_finding.title

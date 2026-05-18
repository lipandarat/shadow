"""Tests for ReportAgent."""

import os, tempfile
import pytest
from shadow.core.models import (
    Finding, Evidence, Engagement, Scope, ScopeEntry,
    FindingStatus, Severity
)
from shadow.core.store import FindingStore
from shadow.agents.report import ReportAgent


def make_engagement(base_dir):
    workspace = os.path.join(base_dir, "test-eng")
    os.makedirs(os.path.join(workspace, "findings"), exist_ok=True)
    scope = Scope(entries=[ScopeEntry(domain="example.com")])
    return Engagement(
        platform="hackerone",
        program="tesla",
        workspace_path=workspace,
        scope=scope,
    )


def make_validated_finding(title="SQLi", vuln_class="sqli", target="https://example.com/login"):
    f = Finding(
        title=title,
        vuln_class=vuln_class,
        target=target,
        parameter="username",
        reproduction_steps=["Send payload", "Observe response"],
        impact="Authentication bypass",
        fix="Use parameterized queries",
        evidence=Evidence(
            request="POST /login HTTP/1.1\r\nHost: example.com",
            response="HTTP/1.1 200 OK\r\n\r\nWelcome admin",
        ),
        status=FindingStatus.VALIDATED,
        severity=Severity.HIGH,
        cvss_score=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    )
    return f


class TestReportAgent:
    @pytest.fixture
    def setup(self):
        with tempfile.TemporaryDirectory() as d:
            eng = make_engagement(d)
            store = FindingStore(eng.workspace_path)
            agent = ReportAgent(eng, store)
            yield agent, eng, store

    def test_generate_creates_report_file(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        assert os.path.exists(path)
        assert path.endswith(".md")

    def test_report_contains_finding_title(self, setup):
        agent, eng, store = setup
        f = make_validated_finding(title="Critical SQLi")
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "Critical SQLi" in content

    def test_report_contains_program_name(self, setup):
        agent, eng, store = setup
        path = agent.generate()
        content = open(path).read()
        assert "tesla" in content

    def test_report_contains_severity(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "high" in content.lower()

    def test_report_contains_cvss(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "8.6" in content

    def test_report_contains_reproduction_steps(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "Send payload" in content

    def test_report_contains_evidence(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "POST /login" in content

    def test_report_contains_fix(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "parameterized queries" in content

    def test_report_empty_when_no_validated_findings(self, setup):
        agent, eng, store = setup
        # Save a DRAFT finding — should not appear in report
        f = make_validated_finding()
        f.status = FindingStatus.DRAFT
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "No validated findings" in content

    def test_report_custom_output_path(self, setup):
        agent, eng, store = setup
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp:
            custom_path = tmp.name
        try:
            path = agent.generate(output_path=custom_path)
            assert path == custom_path
            assert os.path.exists(custom_path)
        finally:
            os.unlink(custom_path)

    def test_report_summary_table(self, setup):
        agent, eng, store = setup
        f = make_validated_finding()
        store.save(f)
        path = agent.generate()
        content = open(path).read()
        assert "## Summary" in content
        assert "| ID |" in content

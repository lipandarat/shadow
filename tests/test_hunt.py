"""Tests for HuntAgent."""

import os
import tempfile
import pytest
from unittest.mock import MagicMock
from shadow.core.models import Finding, Evidence, Engagement, Scope, ScopeEntry
from shadow.core.store import FindingStore
from shadow.core.toolcheck import ToolChecker
from shadow.core.opsec import OpsecGuard
from shadow.core.session import SessionManager
from shadow.core.audit import AuditLogger
from shadow.agents.hunt import HuntAgent


def make_engagement(base_dir):
    workspace = os.path.join(base_dir, "test-eng")
    os.makedirs(os.path.join(workspace, "findings"), exist_ok=True)
    with open(os.path.join(workspace, "brain.md"), "w") as f:
        f.write("# Test\n")
    scope = Scope(entries=[ScopeEntry(domain="example.com")])
    return Engagement(
        platform="hackerone",
        program="test",
        workspace_path=workspace,
        scope=scope,
    )


def valid_finding():
    return Finding(
        title="SQL Injection in /login",
        vuln_class="sqli",
        target="https://example.com/login",
        parameter="username",
        reproduction_steps=["Send payload", "Observe response"],
        impact="Authentication bypass — attacker gains admin access",
        evidence=Evidence(
            request="POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin'--",
            response="HTTP/1.1 200 OK\r\n\r\nWelcome admin",
        ),
        description="SQL injection confirmed via manual testing.",
    )


class TestHuntAgent:
    @pytest.fixture
    def setup(self):
        with tempfile.TemporaryDirectory() as d:
            eng = make_engagement(d)
            store = FindingStore(eng.workspace_path)
            toolcheck = MagicMock(spec=ToolChecker)
            toolcheck.available_tools.return_value = {}
            opsec = OpsecGuard(delay_range=(0, 0))
            session = SessionManager(eng.workspace_path)
            audit = AuditLogger(eng.workspace_path)
            agent = HuntAgent(eng, store, toolcheck=toolcheck, opsec=opsec, session=session, audit=audit)
            yield agent, eng, store

    def test_process_candidate_saves_valid_finding(self, setup):
        agent, eng, store = setup
        f = valid_finding()
        result = agent.process_candidate(f)
        assert result["status"] == "saved"
        assert result["finding_id"] is not None
        assert store.load(result["finding_id"]) is not None

    def test_process_candidate_rejects_out_of_scope(self, setup):
        agent, eng, store = setup
        f = valid_finding()
        f.target = "https://evil.com/login"
        result = agent.process_candidate(f)
        assert result["status"] == "rejected"
        assert result["reason"] == "out_of_scope"

    def test_process_candidate_rejects_duplicate(self, setup):
        agent, eng, store = setup
        f1 = valid_finding()
        agent.process_candidate(f1)
        f2 = valid_finding()  # same params = same fingerprint
        result = agent.process_candidate(f2)
        assert result["status"] == "rejected"
        assert result["reason"] == "duplicate"

    def test_process_candidate_rejects_gate_failure(self, setup):
        agent, eng, store = setup
        f = valid_finding()
        f.evidence = None
        f.oob_hit = None
        f.reproduction_steps = []
        result = agent.process_candidate(f)
        assert result["status"] == "rejected"
        assert result["reason"] == "gate_failed"
        assert len(result["failures"]) > 0

    def test_process_candidate_assigns_cvss(self, setup):
        agent, eng, store = setup
        f = valid_finding()
        result = agent.process_candidate(f)
        assert result["status"] == "saved"
        assert result["cvss_score"] is not None
        assert result["cvss_score"] > 0

    def test_run_out_of_scope_returns_error(self, setup):
        agent, eng, store = setup
        result = agent.run("https://evil.com")
        assert "error" in result

    def test_run_in_scope_returns_complete(self, setup):
        agent, eng, store = setup
        result = agent.run("https://example.com")
        assert result["status"] == "complete"

    def test_run_resume_skips_done_step(self, setup):
        agent, eng, store = setup
        agent.run("https://example.com", vuln_class="sqli")
        result = agent.run("https://example.com", vuln_class="sqli", resume=True)
        assert result["status"] == "already_done"

    def test_audit_log_written(self, setup):
        agent, eng, store = setup
        agent.run("https://example.com")
        events = AuditLogger(eng.workspace_path).read_all()
        event_names = [e["event"] for e in events]
        assert "hunt_start" in event_names
        assert "hunt_complete" in event_names

"""Tests for ReconAgent — uses mocks to avoid real tool execution."""

import json
import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from shadow.core.models import Engagement, Scope, ScopeEntry
from shadow.core.toolcheck import ToolChecker
from shadow.core.opsec import OpsecGuard
from shadow.core.audit import AuditLogger
from shadow.agents.recon import ReconAgent


def make_engagement(base_dir: str) -> Engagement:
    workspace = os.path.join(base_dir, "test-engagement")
    os.makedirs(os.path.join(workspace, "findings"), exist_ok=True)
    open(os.path.join(workspace, "endpoints.jsonl"), "w").close()
    open(os.path.join(workspace, "brain.md"), "w").close()
    scope = Scope(entries=[ScopeEntry(domain="example.com")])
    return Engagement(
        platform="hackerone",
        program="test",
        workspace_path=workspace,
        scope=scope,
    )


class TestReconAgent:
    @pytest.fixture
    def workspace(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    @pytest.fixture
    def engagement(self, workspace):
        return make_engagement(workspace)

    def _make_agent(self, engagement, tools_available=None):
        toolcheck = MagicMock(spec=ToolChecker)
        toolcheck.available_tools.return_value = tools_available or {}
        opsec = OpsecGuard(delay_range=(0, 0))
        audit = AuditLogger(engagement.workspace_path)
        return ReconAgent(engagement, toolcheck=toolcheck, opsec=opsec, audit=audit)

    def test_discover_endpoints_scope_check(self, engagement):
        agent = self._make_agent(engagement)
        from shadow.core.scope import ScopeViolation
        with pytest.raises(ScopeViolation):
            agent.discover_endpoints("https://evil.com")

    def test_discover_endpoints_no_tools(self, engagement):
        agent = self._make_agent(engagement, tools_available={})
        endpoints = agent.discover_endpoints("https://example.com")
        assert isinstance(endpoints, list)

    def test_discover_endpoints_with_subfinder(self, engagement):
        agent = self._make_agent(engagement, tools_available={"subfinder": True, "httpx": False})
        with patch.object(agent, "_run_subfinder", return_value=["https://sub.example.com"]):
            endpoints = agent.discover_endpoints("https://example.com")
        assert "https://sub.example.com" in endpoints

    def test_discover_endpoints_filters_out_of_scope(self, engagement):
        agent = self._make_agent(engagement, tools_available={"gau": True})
        with patch.object(agent, "_run_gau", return_value=[
            "https://example.com/path",
            "https://evil.com/path",
        ]):
            endpoints = agent.discover_endpoints("https://example.com")
        assert "https://example.com/path" in endpoints
        assert "https://evil.com/path" not in endpoints

    def test_append_and_load_endpoints(self, engagement):
        agent = self._make_agent(engagement)
        agent.append_endpoints(["https://example.com/a", "https://example.com/b"])
        loaded = agent.load_endpoints()
        assert "https://example.com/a" in loaded
        assert "https://example.com/b" in loaded

    def test_load_endpoints_empty_when_no_file(self, workspace):
        eng = make_engagement(workspace)
        os.remove(os.path.join(eng.workspace_path, "endpoints.jsonl"))
        agent = self._make_agent(eng)
        assert agent.load_endpoints() == []

    def test_audit_log_written(self, engagement):
        agent = self._make_agent(engagement, tools_available={})
        agent.discover_endpoints("https://example.com")
        events = AuditLogger(engagement.workspace_path).read_all()
        event_names = [e["event"] for e in events]
        assert "recon_start" in event_names
        assert "recon_complete" in event_names

    def test_run_subfinder_handles_exception(self, engagement):
        agent = self._make_agent(engagement)
        with patch("subprocess.run", side_effect=Exception("tool not found")):
            result = agent._run_subfinder("example.com")
        assert result == []

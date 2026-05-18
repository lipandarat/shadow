import os, tempfile
import pytest
from unittest.mock import MagicMock
from shadow.core.models import Finding, Evidence
from shadow.core.store import FindingStore
from shadow.core.dedup import FingerprintEngine
from shadow.agents.dupcheck import DupcheckAgent


def make_finding(title="SQLi", vuln_class="sqli", target="https://x.com/login", param="user"):
    return Finding(
        title=title,
        vuln_class=vuln_class,
        target=target,
        parameter=param,
        reproduction_steps=["step"],
        impact="auth bypass",
        evidence=Evidence(request="POST /login", response="200 OK"),
    )


class TestDupcheckAgent:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as d:
            yield FindingStore(d)

    def test_check_returns_dict(self, store):
        agent = DupcheckAgent(store)
        result = agent.check(make_finding())
        assert isinstance(result, dict)
        assert "is_duplicate" in result
        assert "fingerprint" in result
        assert "local_match" in result

    def test_unique_finding(self, store):
        agent = DupcheckAgent(store)
        result = agent.check(make_finding())
        assert result["is_duplicate"] is False
        assert result["local_match"] is None

    def test_detects_local_duplicate(self, store):
        f1 = make_finding()
        f1.fingerprint = FingerprintEngine.compute(f1)
        store.save(f1)
        agent = DupcheckAgent(store)
        f2 = make_finding()  # same params
        result = agent.check(f2)
        assert result["is_duplicate"] is True
        assert result["local_match"] == f1.id

    def test_platform_check_called_when_no_local_dup(self, store):
        mock_platform = MagicMock()
        mock_platform.search_hacktivity.return_value = None
        agent = DupcheckAgent(store, platform_client=mock_platform)
        agent.check(make_finding())
        mock_platform.search_hacktivity.assert_called_once()

    def test_platform_check_skipped_when_local_dup(self, store):
        f1 = make_finding()
        f1.fingerprint = FingerprintEngine.compute(f1)
        store.save(f1)
        mock_platform = MagicMock()
        agent = DupcheckAgent(store, platform_client=mock_platform)
        agent.check(make_finding())
        mock_platform.search_hacktivity.assert_not_called()

    def test_platform_exception_handled(self, store):
        mock_platform = MagicMock()
        mock_platform.search_hacktivity.side_effect = Exception("API error")
        agent = DupcheckAgent(store, platform_client=mock_platform)
        result = agent.check(make_finding())
        assert result["is_duplicate"] is False  # exception = not duplicate

    def test_format_output_unique(self, store):
        agent = DupcheckAgent(store)
        result = agent.check(make_finding())
        output = agent.format_output(result)
        assert "UNIQUE" in output

    def test_format_output_duplicate(self, store):
        f1 = make_finding()
        f1.fingerprint = FingerprintEngine.compute(f1)
        store.save(f1)
        agent = DupcheckAgent(store)
        result = agent.check(make_finding())
        output = agent.format_output(result)
        assert "DUPLICATE" in output

"""Tests for OPSEC guard — use time mocking to avoid slow tests."""

import time
import pytest
from unittest.mock import patch, MagicMock
from shadow.core.opsec import OpsecGuard, USER_AGENTS


class TestOpsecGuard:
    def test_before_request_returns_headers(self):
        guard = OpsecGuard(delay_range=(0, 0))
        with patch("time.sleep"):
            headers = guard.before_request("https://example.com")
        assert "User-Agent" in headers
        assert headers["User-Agent"] in USER_AGENTS

    def test_user_agent_rotates(self):
        guard = OpsecGuard(delay_range=(0, 0))
        agents = [guard.get_user_agent() for _ in range(len(USER_AGENTS) + 1)]
        # Should cycle through all agents
        assert len(set(agents)) == len(USER_AGENTS)

    def test_user_agents_are_realistic(self):
        guard = OpsecGuard()
        for ua in USER_AGENTS:
            assert "Mozilla" in ua

    def test_requests_last_minute_counts(self):
        guard = OpsecGuard(delay_range=(0, 0))
        with patch("time.sleep"):
            guard.before_request()
            guard.before_request()
        assert guard.requests_last_minute() == 2

    def test_rate_limit_triggers_sleep(self):
        guard = OpsecGuard(delay_range=(0, 0), max_rpm=2)
        sleep_calls = []

        def fake_sleep(t):
            sleep_calls.append(t)

        with patch("time.sleep", side_effect=fake_sleep):
            guard.before_request()  # 1
            guard.before_request()  # 2
            guard.before_request()  # 3 — should trigger rate limit sleep

        # At least one sleep call should be >= 5.0 (rate limit sleep)
        assert any(t >= 5.0 for t in sleep_calls)

    def test_audit_logger_called_on_rate_limit(self):
        mock_audit = MagicMock()
        guard = OpsecGuard(delay_range=(0, 0), max_rpm=1, audit_logger=mock_audit)

        with patch("time.sleep"):
            guard.before_request("https://example.com")  # 1
            guard.before_request("https://example.com")  # 2 — triggers rate limit

        mock_audit.log.assert_called_with(
            "opsec_rate_limit",
            target="https://example.com",
            wait_seconds=pytest.approx(mock_audit.log.call_args[1]["wait_seconds"], abs=15),
        )

    def test_headers_contain_required_fields(self):
        guard = OpsecGuard(delay_range=(0, 0))
        with patch("time.sleep"):
            headers = guard.before_request()
        assert "Accept" in headers
        assert "Accept-Language" in headers
        assert "Connection" in headers

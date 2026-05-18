"""Tests for InteractshCollector."""

import pytest
from unittest.mock import patch, MagicMock
from shadow.oob.interactsh import InteractshCollector
from shadow.oob.collector import OOBHit


class TestInteractshCollector:
    @pytest.fixture
    def collector(self):
        return InteractshCollector("eng-abc123")

    def test_get_canary_format(self, collector):
        canary = collector.get_canary("F001")
        assert "interactsh.com" in canary
        assert "f001" in canary.lower()

    def test_get_canary_unique_per_finding(self, collector):
        c1 = collector.get_canary("F001")
        c2 = collector.get_canary("F002")
        assert c1 != c2

    def test_check_hit_returns_none_initially(self, collector):
        assert collector.check_hit("F001") is None

    def test_is_available_returns_bool(self):
        result = InteractshCollector.is_available()
        assert isinstance(result, bool)

    def test_start_does_nothing_when_not_available(self, collector):
        with patch.object(InteractshCollector, "is_available", return_value=False):
            collector.start()
        assert not collector.is_running()

    def test_start_sets_running_when_available(self, collector):
        with patch.object(InteractshCollector, "is_available", return_value=True):
            with patch.object(collector, "_poll_loop"):
                import threading
                with patch("threading.Thread") as mock_thread:
                    mock_thread.return_value.start = MagicMock()
                    collector.start()
        assert collector.is_running()

    def test_stop_clears_running(self, collector):
        collector._running = True
        collector.stop()
        assert not collector.is_running()

    def test_process_hit_stores_hit(self, collector):
        data = {
            "correlation-id": "shadow-eng-abc1-f001",
            "protocol": "dns",
            "remote-address": "1.2.3.4",
        }
        collector._process_hit(data)
        hit = collector.check_hit("F001")
        assert hit is not None
        assert hit.hit_type == "dns"
        assert hit.remote_ip == "1.2.3.4"

    def test_extract_finding_ids(self, collector):
        ids = collector._extract_finding_ids("shadow-eng-abc1-f001")
        assert "F001" in ids

    def test_custom_domain(self):
        c = InteractshCollector("eng-test", domain="custom.oob.example.com")
        canary = c.get_canary("F001")
        assert "custom.oob.example.com" in canary

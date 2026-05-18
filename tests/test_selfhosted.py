"""Tests for SelfHostedCollector."""

import time
import urllib.request
import pytest
from shadow.oob.selfhosted import SelfHostedCollector
from shadow.oob.collector import OOBHit


class TestSelfHostedCollector:
    @pytest.fixture
    def collector(self):
        c = SelfHostedCollector("eng-test", port=0)
        yield c
        if c.is_running():
            c.stop()

    def test_get_canary_format(self, collector):
        canary = collector.get_canary("F001")
        assert canary.startswith("http://127.0.0.1")
        assert "f001" in canary.lower()

    def test_get_canary_unique_per_finding(self, collector):
        c1 = collector.get_canary("F001")
        c2 = collector.get_canary("F002")
        assert c1 != c2

    def test_check_hit_returns_none_initially(self, collector):
        assert collector.check_hit("F001") is None

    def test_start_sets_running(self, collector):
        collector.start()
        assert collector.is_running()

    def test_stop_clears_running(self, collector):
        collector.start()
        collector.stop()
        assert not collector.is_running()

    def test_http_hit_recorded(self, collector):
        collector.start()
        cid = collector.canary_id("F001")
        url = f"http://127.0.0.1:{collector._actual_port}/{cid}"
        urllib.request.urlopen(url, timeout=5)
        time.sleep(0.1)
        hit = collector.check_hit("F001")
        assert hit is not None
        assert hit.hit_type == "http"

    def test_port_auto_assigned(self, collector):
        collector.start()
        assert collector._actual_port > 0

    def test_canary_url_uses_actual_port(self, collector):
        collector.start()
        canary = collector.get_canary("F001")
        assert str(collector._actual_port) in canary

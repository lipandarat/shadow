"""Tests for OOB collector interface and implementations."""

import pytest
from shadow.oob.collector import OOBCollector, OOBHit


class ConcreteCollector(OOBCollector):
    """Minimal concrete implementation for testing the abstract base."""
    def __init__(self, engagement_id):
        super().__init__(engagement_id)
        self._hits = {}

    def get_canary(self, finding_id: str) -> str:
        cid = self.canary_id(finding_id)
        return f"http://oob.test/{cid}"

    def check_hit(self, finding_id: str):
        return self._hits.get(finding_id)

    def inject_hit(self, finding_id: str, hit: OOBHit):
        self._hits[finding_id] = hit


class TestOOBCollector:
    @pytest.fixture
    def collector(self):
        return ConcreteCollector("eng-abc123")

    def test_get_canary_returns_string(self, collector):
        canary = collector.get_canary("F001")
        assert isinstance(canary, str)
        assert len(canary) > 0

    def test_canary_contains_finding_id(self, collector):
        canary = collector.get_canary("F001")
        assert "f001" in canary.lower()

    def test_canary_unique_per_finding(self, collector):
        c1 = collector.get_canary("F001")
        c2 = collector.get_canary("F002")
        assert c1 != c2

    def test_check_hit_returns_none_when_no_hit(self, collector):
        assert collector.check_hit("F001") is None

    def test_check_hit_returns_oob_hit(self, collector):
        hit = OOBHit(finding_id="F001", hit_type="dns", remote_ip="1.2.3.4")
        collector.inject_hit("F001", hit)
        result = collector.check_hit("F001")
        assert result is not None
        assert result.finding_id == "F001"
        assert result.hit_type == "dns"

    def test_start_sets_running(self, collector):
        collector.start()
        assert collector.is_running()

    def test_stop_clears_running(self, collector):
        collector.start()
        collector.stop()
        assert not collector.is_running()

    def test_not_running_by_default(self, collector):
        assert not collector.is_running()

    def test_canary_id_format(self, collector):
        cid = collector.canary_id("F001")
        assert cid.startswith("shadow-")
        assert "f001" in cid.lower()

    def test_oob_hit_has_timestamp(self):
        hit = OOBHit(finding_id="F001")
        assert hit.timestamp is not None
        assert "T" in hit.timestamp  # ISO format

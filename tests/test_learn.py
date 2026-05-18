"""Tests for LearningEngine and LearnAgent."""

import os, tempfile
import pytest
from shadow.core.brain import Brain
from shadow.core.learn import LearningEngine
from shadow.agents.learn import LearnAgent


class TestLearningEngine:
    @pytest.fixture
    def brain(self):
        with tempfile.TemporaryDirectory() as d:
            brain_path = os.path.join(d, "brain.md")
            with open(brain_path, "w") as f:
                f.write("# Test\n")
            yield Brain(d)

    def test_record_adds_entry(self, brain):
        engine = LearningEngine(brain)
        engine.record("F001", "accepted", bounty=500, vuln_type="sqli", program="tesla")
        assert len(engine._entries) == 1
        assert engine._entries[0].status == "accepted"

    def test_record_writes_to_brain(self, brain):
        engine = LearningEngine(brain)
        engine.record("F001", "accepted", bounty=500, vuln_type="sqli")
        content = brain.read()
        assert "F001" in content
        assert "ACCEPTED" in content
        assert "500" in content

    def test_get_priority_areas_returns_accepted_vuln_types(self, brain):
        engine = LearningEngine(brain)
        engine.record("F001", "accepted", vuln_type="sqli", program="tesla")
        engine.record("F002", "accepted", vuln_type="sqli", program="tesla")
        engine.record("F003", "accepted", vuln_type="xss", program="tesla")
        engine.record("F004", "duplicate", vuln_type="sqli", program="tesla")
        areas = engine.get_priority_areas(program="tesla")
        assert areas[0] == "sqli"
        assert "xss" in areas

    def test_get_priority_areas_filters_by_program(self, brain):
        engine = LearningEngine(brain)
        engine.record("F001", "accepted", vuln_type="sqli", program="tesla")
        engine.record("F002", "accepted", vuln_type="xss", program="other")
        areas = engine.get_priority_areas(program="tesla")
        assert "sqli" in areas
        assert "xss" not in areas

    def test_get_stats(self, brain):
        engine = LearningEngine(brain)
        engine.record("F001", "accepted", bounty=500, vuln_type="sqli")
        engine.record("F002", "duplicate", vuln_type="xss")
        engine.record("F003", "accepted", bounty=200, vuln_type="ssrf")
        stats = engine.get_stats()
        assert stats["total"] == 3
        assert stats["accepted"] == 2
        assert stats["duplicates"] == 1
        assert stats["total_bounty"] == 700
        assert stats["acceptance_rate"] == round(2/3, 2)

    def test_get_stats_empty(self, brain):
        engine = LearningEngine(brain)
        stats = engine.get_stats()
        assert stats["total"] == 0
        assert stats["acceptance_rate"] == 0.0


class TestLearnAgent:
    @pytest.fixture
    def brain(self):
        with tempfile.TemporaryDirectory() as d:
            brain_path = os.path.join(d, "brain.md")
            with open(brain_path, "w") as f:
                f.write("# Test\n")
            yield Brain(d)

    def test_learn_returns_dict(self, brain):
        agent = LearnAgent(brain)
        result = agent.learn("F001", "accepted", bounty=500, vuln_type="sqli")
        assert result["recorded"] is True
        assert result["finding_id"] == "F001"
        assert result["status"] == "accepted"

    def test_priority_areas_after_learning(self, brain):
        agent = LearnAgent(brain)
        agent.learn("F001", "accepted", vuln_type="sqli", program="tesla")
        agent.learn("F002", "accepted", vuln_type="sqli", program="tesla")
        areas = agent.priority_areas(program="tesla")
        assert "sqli" in areas

    def test_format_output(self, brain):
        agent = LearnAgent(brain)
        result = agent.learn("F001", "accepted", bounty=500)
        output = agent.format_output(result)
        assert "F001" in output
        assert "accepted" in output
        assert "500" in output

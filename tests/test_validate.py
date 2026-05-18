"""Tests for the 9-question validation gate."""

import os, tempfile
import pytest
from shadow.core.models import Finding, Evidence, Scope, ScopeEntry
from shadow.core.validate import ValidationGate, GateResult
from shadow.core.brain import Brain


class TestValidationGate:
    def _valid_finding(self) -> Finding:
        """A finding that passes all 9 questions."""
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

    def test_valid_finding_passes_all(self):
        f = self._valid_finding()
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        result = ValidationGate.run(f, scope)
        assert result.passed
        assert result.reasons == []

    def test_q1_fails_without_reproduction_steps(self):
        f = self._valid_finding()
        f.reproduction_steps = []
        result = ValidationGate.run(f)
        assert not result.passed
        assert any("Q1" in r for r in result.reasons)

    def test_q2_fails_out_of_scope(self):
        f = self._valid_finding()
        scope = Scope(entries=[ScopeEntry(domain="other.com")])
        result = ValidationGate.run(f, scope)
        assert not result.passed
        assert any("Q2" in r for r in result.reasons)

    def test_q2_skipped_when_no_scope(self):
        f = self._valid_finding()
        result = ValidationGate.run(f, scope=None)
        assert result.question_results[2] is True

    def test_q3_fails_without_evidence(self):
        f = self._valid_finding()
        f.evidence = None
        f.oob_hit = None
        result = ValidationGate.run(f)
        assert not result.passed
        assert any("Q3" in r for r in result.reasons)

    def test_q3_passes_with_oob_hit(self):
        f = self._valid_finding()
        f.evidence = None
        f.oob_hit = "shadow-test.interactsh.com"
        result = ValidationGate.run(f)
        # Q3 and Q8 should pass with OOB hit
        assert result.question_results[3] is True
        assert result.question_results[8] is True

    def test_q5_fails_known_false_positive(self):
        f = self._valid_finding()
        f.title = "X-Powered-By Header Disclosure"
        f.description = "x-powered-by header is exposed"
        result = ValidationGate.run(f)
        assert not result.passed
        assert any("Q5" in r for r in result.reasons)

    def test_q7_fails_without_impact(self):
        f = self._valid_finding()
        f.impact = None
        result = ValidationGate.run(f)
        assert not result.passed
        assert any("Q7" in r for r in result.reasons)

    def test_q7_fails_informational_impact(self):
        f = self._valid_finding()
        f.impact = "version disclosure only"
        result = ValidationGate.run(f)
        assert not result.passed
        assert any("Q7" in r for r in result.reasons)

    def test_q9_fails_theory_without_evidence(self):
        f = self._valid_finding()
        f.evidence = None
        f.oob_hit = None
        f.description = "An attacker could potentially exploit this to gain access"
        result = ValidationGate.run(f)
        assert not result.passed
        assert any("Q9" in r for r in result.reasons)

    def test_q9_passes_theory_with_evidence(self):
        f = self._valid_finding()
        f.description = "An attacker could potentially exploit this — confirmed via PoC"
        # Has evidence, so Q9 should pass
        result = ValidationGate.run(f)
        assert result.question_results[9] is True

    def test_gate_result_has_question_results(self):
        f = self._valid_finding()
        result = ValidationGate.run(f)
        assert len(result.question_results) == 9
        assert all(k in result.question_results for k in range(1, 10))


class TestBrain:
    @pytest.fixture
    def workspace(self):
        with tempfile.TemporaryDirectory() as d:
            # Create brain.md
            with open(os.path.join(d, "brain.md"), "w") as f:
                f.write("# Test\n")
            yield d

    def test_record_dead_end_appends(self, workspace):
        brain = Brain(workspace)
        f = Finding(title="SQLi", vuln_class="sqli", target="https://x.com")
        brain.record_dead_end(f, ["Q3 FAIL: no evidence", "Q7 FAIL: no impact"])
        content = brain.read()
        assert "Dead End" in content
        assert "SQLi" in content
        assert "Q3 FAIL" in content

    def test_append_note(self, workspace):
        brain = Brain(workspace)
        brain.append_note("## Patterns Learned\n- SQLi common in login forms")
        content = brain.read()
        assert "Patterns Learned" in content

    def test_read_returns_empty_when_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            brain = Brain(d)
            assert brain.read() == ""

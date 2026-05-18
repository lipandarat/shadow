import pytest
from shadow.core.models import Finding, Evidence, Scope, ScopeEntry
from shadow.agents.validate import ValidateAgent


def valid_finding() -> Finding:
    return Finding(
        title="SQL Injection in /login",
        vuln_class="sqli",
        target="https://example.com/login",
        reproduction_steps=["Send payload", "Observe response"],
        impact="Authentication bypass",
        evidence=Evidence(request="POST /login", response="200 OK"),
        description="Confirmed via manual testing.",
    )


class TestValidateAgent:
    def test_validate_returns_dict(self):
        agent = ValidateAgent()
        result = agent.validate(valid_finding())
        assert isinstance(result, dict)
        assert "passed" in result
        assert "questions" in result
        assert "failures" in result
        assert "summary" in result

    def test_validate_passes_valid_finding(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        agent = ValidateAgent(scope=scope)
        result = agent.validate(valid_finding())
        assert result["passed"] is True
        assert result["failures"] == []

    def test_validate_fails_missing_evidence(self):
        agent = ValidateAgent()
        f = valid_finding()
        f.evidence = None
        f.oob_hit = None
        result = agent.validate(f)
        assert result["passed"] is False
        assert len(result["failures"]) > 0

    def test_questions_dict_has_9_entries(self):
        agent = ValidateAgent()
        result = agent.validate(valid_finding())
        assert len(result["questions"]) == 9

    def test_questions_have_label_and_passed(self):
        agent = ValidateAgent()
        result = agent.validate(valid_finding())
        for q_num, q_data in result["questions"].items():
            assert "passed" in q_data
            assert "label" in q_data
            assert isinstance(q_data["label"], str)

    def test_summary_format(self):
        agent = ValidateAgent()
        result = agent.validate(valid_finding())
        assert "/" in result["summary"]
        assert "passed" in result["summary"]

    def test_format_output_contains_pass(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        agent = ValidateAgent(scope=scope)
        result = agent.validate(valid_finding())
        output = agent.format_output(result)
        assert "PASS" in output

    def test_format_output_contains_fail_reasons(self):
        agent = ValidateAgent()
        f = valid_finding()
        f.evidence = None
        f.oob_hit = None
        result = agent.validate(f)
        output = agent.format_output(result)
        assert "FAIL" in output
        assert "Failure reasons" in output

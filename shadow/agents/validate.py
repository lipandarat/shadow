"""Validate agent — CLI-friendly wrapper around ValidationGate."""

from shadow.core.models import Finding, Scope
from shadow.core.validate import ValidationGate, GateResult


class ValidateAgent:
    def __init__(self, scope: Scope = None):
        self.scope = scope

    def validate(self, finding: Finding) -> dict:
        """Run 9-question gate. Returns structured result dict."""
        result = ValidationGate.run(finding, self.scope)
        return {
            "passed": result.passed,
            "finding_id": finding.id,
            "finding_title": finding.title,
            "questions": {
                q: {"passed": passed, "label": self._label(q)}
                for q, passed in result.question_results.items()
            },
            "failures": result.reasons,
            "summary": self._summary(result),
        }

    def format_output(self, result: dict) -> str:
        """Format validation result for CLI display."""
        lines = []
        status = "PASS" if result["passed"] else "FAIL"
        lines.append(f"\n=== Validation Gate: {status} ===")
        if result.get("finding_title"):
            lines.append(f"Finding: {result['finding_title']}")
        lines.append("")
        for q_num, q_data in result["questions"].items():
            icon = "✓" if q_data["passed"] else "✗"
            lines.append(f"  {icon} Q{q_num}: {q_data['label']}")
        if result["failures"]:
            lines.append("\nFailure reasons:")
            for reason in result["failures"]:
                lines.append(f"  - {reason}")
        lines.append("")
        return "\n".join(lines)

    def _label(self, question_num: int) -> str:
        labels = {
            1: "Reproducible",
            2: "In-scope",
            3: "Has concrete evidence",
            4: "Severity realistic",
            5: "Not known false positive",
            6: "Not duplicate",
            7: "Real impact",
            8: "Exploitable concretely",
            9: "Not AI hallucination",
        }
        return labels.get(question_num, f"Question {question_num}")

    def _summary(self, result: GateResult) -> str:
        passed = sum(1 for v in result.question_results.values() if v)
        total = len(result.question_results)
        return f"{passed}/{total} questions passed"

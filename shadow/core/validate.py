"""9-question validation gate. Every finding MUST pass before being saved."""

from dataclasses import dataclass, field
from shadow.core.models import Finding, Scope
from shadow.core.scope import ScopeEngine


THEORY_PHRASES = [
    "could potentially",
    "may allow",
    "it is possible",
    "attacker could",
    "might be able",
    "theoretically",
    "could lead to",
    "may result in",
    "it may be possible",
    "an attacker might",
    "this could allow",
]

KNOWN_FALSE_POSITIVES = [
    "x-powered-by header",
    "server version disclosure",
    "ssl certificate expiry",
    "directory listing without sensitive files",
    "missing security headers without impact",
]

NO_IMPACT_PATTERNS = [
    "header disclosure",
    "ssl expiry",
    "version disclosure",
    "missing header",
    "banner grabbing",
    "fingerprinting only",
]


@dataclass
class GateResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)
    question_results: dict[int, bool] = field(default_factory=dict)


class ValidationGate:
    @staticmethod
    def run(finding: Finding, scope: Scope = None) -> GateResult:
        """Run all 9 validation questions. Returns GateResult."""
        reasons = []
        results = {}

        # Q1: Reproducible?
        q1 = bool(finding.reproduction_steps)
        results[1] = q1
        if not q1:
            reasons.append("Q1 FAIL: No reproduction steps provided")

        # Q2: In-scope?
        if scope is not None:
            q2 = ScopeEngine.is_in_scope(finding.target, scope)
        else:
            q2 = True  # skip scope check if no scope provided
        results[2] = q2
        if not q2:
            reasons.append(f"Q2 FAIL: Target '{finding.target}' is not in scope")

        # Q3: Has concrete evidence?
        q3 = finding.has_evidence()
        results[3] = q3
        if not q3:
            reasons.append("Q3 FAIL: No concrete evidence (request/response/screenshot/PoC/OOB hit)")

        # Q4: Severity realistic?
        q4 = finding.cvss_score is None or finding.cvss_score >= 0.0
        results[4] = q4
        if not q4:
            reasons.append("Q4 FAIL: Invalid CVSS score")

        # Q5: Not a known false positive?
        desc_lower = (finding.description + " " + finding.title).lower()
        q5 = not any(fp in desc_lower for fp in KNOWN_FALSE_POSITIVES)
        results[5] = q5
        if not q5:
            reasons.append("Q5 FAIL: Matches known false positive pattern")

        # Q6: Not a duplicate? (fingerprint check — full dedup done in store)
        q6 = True  # fingerprint dedup is enforced at store level
        results[6] = q6

        # Q7: Real impact?
        impact_text = (finding.impact or "").lower()
        title_lower = finding.title.lower()
        q7 = bool(finding.impact) and not any(p in impact_text or p in title_lower for p in NO_IMPACT_PATTERNS)
        results[7] = q7
        if not q7:
            if not finding.impact:
                reasons.append("Q7 FAIL: No impact statement provided")
            else:
                reasons.append("Q7 FAIL: Impact appears informational with no real harm")

        # Q8: Exploitable concretely (not just theory)?
        q8 = finding.has_evidence()
        results[8] = q8
        if not q8:
            reasons.append("Q8 FAIL: No proof of concrete exploitability — evidence required")

        # Q9: Not AI hallucination?
        full_text = f"{finding.title} {finding.description} {finding.impact or ''}".lower()
        has_theory_phrase = any(phrase in full_text for phrase in THEORY_PHRASES)
        q9 = not has_theory_phrase or finding.has_evidence()
        results[9] = q9
        if not q9:
            reasons.append("Q9 FAIL: Description contains theoretical language without concrete evidence")

        passed = all(results.values())
        return GateResult(passed=passed, reasons=reasons, question_results=results)

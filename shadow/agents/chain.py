"""Chain agent — builds exploit chains from related findings."""

from shadow.core.models import Finding, FindingStatus
from shadow.core.store import FindingStore
from shadow.core.cvss import CVSSCalculator


# Exploit chain ordering — lower number = earlier in chain
CHAIN_ORDER = {
    "recon": 0,
    "info": 1,
    "ssrf": 2,
    "xxe": 2,
    "lfi": 2,
    "path": 2,
    "idor": 3,
    "bola": 3,
    "auth": 3,
    "sqli": 4,
    "ssti": 4,
    "cmdi": 5,
    "rce": 6,
    "xss": 3,
    "csrf": 3,
}


class ChainAgent:
    def __init__(self, store: FindingStore):
        self.store = store

    def build_chain(self, finding_id: str) -> dict:
        """Find related findings and build an exploit chain."""
        root = self.store.load(finding_id)
        if root is None:
            return {"error": f"Finding {finding_id} not found"}

        all_findings = self.store.load_all()
        related = self._find_related(root, all_findings)

        # Sort by chain order
        chain = sorted(related, key=lambda f: CHAIN_ORDER.get(f.vuln_class.lower(), 99))

        # Compute combined severity
        combined_score = self._combined_severity(chain)

        return {
            "root_finding": finding_id,
            "chain": [
                {
                    "id": f.id,
                    "title": f.title,
                    "vuln_class": f.vuln_class,
                    "severity": f.severity.value,
                    "step": i + 1,
                }
                for i, f in enumerate(chain)
            ],
            "chain_length": len(chain),
            "combined_cvss": combined_score,
            "combined_severity": CVSSCalculator.severity_from_score(combined_score).value,
        }

    def create_chain_finding(self, chain_result: dict) -> Finding:
        """Create a new Finding representing the full exploit chain."""
        chain = chain_result["chain"]
        titles = " → ".join(f["title"] for f in chain)
        finding = Finding(
            title=f"Exploit Chain: {titles}",
            vuln_class="chain",
            target=self.store.load(chain[0]["id"]).target if chain else "",
            impact=f"Multi-step exploit chain with combined CVSS {chain_result['combined_cvss']}",
            reproduction_steps=[f"Step {f['step']}: {f['title']}" for f in chain],
            chain_parents=[f["id"] for f in chain],
            description=f"Exploit chain of {chain_result['chain_length']} findings.",
        )
        return finding

    def _find_related(self, root: Finding, all_findings: list[Finding]) -> list[Finding]:
        """Find findings that share the same target domain."""
        from urllib.parse import urlparse
        root_host = urlparse(root.target).netloc.lower()
        related = []
        for f in all_findings:
            if f.id == root.id:
                continue
            f_host = urlparse(f.target).netloc.lower()
            if f_host == root_host:
                related.append(f)
        # Always include root
        related.insert(0, root)
        return related

    def _combined_severity(self, findings: list[Finding]) -> float:
        """Combine CVSS scores — highest score + 0.5 per additional finding, max 10."""
        if not findings:
            return 0.0
        scores = []
        for f in findings:
            if f.cvss_score is not None:
                scores.append(f.cvss_score)
            else:
                score, _ = CVSSCalculator.calculate(f)
                scores.append(score)
        if not scores:
            return 0.0
        base = max(scores)
        bonus = 0.5 * (len(scores) - 1)
        return min(round(base + bonus, 1), 10.0)

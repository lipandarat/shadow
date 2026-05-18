"""Hunt agent — orchestrates the full vulnerability hunting cycle."""

from shadow.core.models import Engagement, Finding
from shadow.core.store import FindingStore
from shadow.core.validate import ValidationGate
from shadow.core.brain import Brain
from shadow.core.dedup import DedupEngine, FingerprintEngine
from shadow.core.cvss import CVSSCalculator
from shadow.core.scope import ScopeEngine
from shadow.core.opsec import OpsecGuard
from shadow.core.toolcheck import ToolChecker
from shadow.core.session import SessionManager
from shadow.core.audit import AuditLogger


class HuntAgent:
    def __init__(
        self,
        engagement: Engagement,
        store: FindingStore,
        toolcheck: ToolChecker = None,
        opsec: OpsecGuard = None,
        session: SessionManager = None,
        audit: AuditLogger = None,
    ):
        self.engagement = engagement
        self.store = store
        self.toolcheck = toolcheck or ToolChecker()
        self.opsec = opsec or OpsecGuard()
        self.session = session or SessionManager(engagement.workspace_path)
        self.audit = audit or AuditLogger(engagement.workspace_path)
        self.brain = Brain(engagement.workspace_path)
        self.dedup = DedupEngine(store)

    def process_candidate(self, finding: Finding) -> dict:
        """
        Process a candidate finding through the full pipeline:
        1. Scope check
        2. Dedup check
        3. CVSS calculation
        4. Validation gate (9 questions)
        5. Save if passes, record dead end if fails

        Returns dict with status and details.
        """
        # Step 1: Scope check
        if not ScopeEngine.is_in_scope(finding.target, self.engagement.scope):
            self.audit.log("finding_rejected_scope", target=finding.target)
            return {"status": "rejected", "reason": "out_of_scope", "finding_id": None}

        # Step 2: Dedup check
        fp = FingerprintEngine.compute(finding)
        finding.fingerprint = fp
        dedup_result = self.dedup.check(finding)
        if dedup_result.is_duplicate:
            self.audit.log(
                "finding_rejected_duplicate",
                fingerprint=fp,
                match=dedup_result.match,
            )
            return {
                "status": "rejected",
                "reason": "duplicate",
                "match": dedup_result.match,
                "finding_id": None,
            }

        # Step 3: CVSS calculation
        score, vector = CVSSCalculator.calculate(finding)
        finding.cvss_score = score
        finding.cvss_vector = vector

        # Step 4: Validation gate
        gate_result = ValidationGate.run(finding, self.engagement.scope)
        if not gate_result.passed:
            self.brain.record_dead_end(finding, gate_result.reasons)
            self.audit.log(
                "finding_rejected_gate",
                title=finding.title,
                reasons=gate_result.reasons,
            )
            return {
                "status": "rejected",
                "reason": "gate_failed",
                "failures": gate_result.reasons,
                "finding_id": None,
            }

        # Step 5: Save
        self.store.save(finding)
        self.audit.log("finding_saved", finding_id=finding.id, title=finding.title)
        return {"status": "saved", "finding_id": finding.id, "cvss_score": score}

    def run(self, target: str, vuln_class: str = None, resume: bool = False) -> dict:
        """
        Run a hunt cycle against target.
        Returns summary dict with counts.
        """
        # Scope check
        if not ScopeEngine.is_in_scope(target, self.engagement.scope):
            return {"error": f"Target {target} is not in scope"}

        step = f"hunt:{target}:{vuln_class or 'all'}"

        # Resume check
        if resume and self.session.is_done(step):
            return {"status": "already_done", "step": step}

        self.session.checkpoint(step, {"target": target, "vuln_class": vuln_class})
        self.audit.log("hunt_start", target=target, vuln_class=vuln_class)

        saved = 0
        rejected = 0

        # Hunt is driven by agents/tools — this method is the orchestration layer.
        # Actual probing happens via tool integrations in subclasses or plugins.

        self.session.mark_done(step)
        self.audit.log("hunt_complete", target=target, saved=saved, rejected=rejected)

        return {
            "status": "complete",
            "target": target,
            "vuln_class": vuln_class,
            "saved": saved,
            "rejected": rejected,
        }

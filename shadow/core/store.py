"""File-based finding store with pre-save hook for validation gate."""

import os
import re
import yaml
from typing import Optional
from shadow.core.models import Finding, Evidence, FindingStatus, Severity, Scope
from shadow.core.validate import ValidationGate


class ValidationFailed(Exception):
    """Raised when a finding fails the 9-question validation gate."""
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__(f"Validation failed: {'; '.join(reasons)}")


class FindingStore:
    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir
        self.findings_dir = os.path.join(workspace_dir, "findings")
        self._next_id = 1

    def save(self, finding: Finding) -> None:
        """Save a finding to disk. Assigns ID if not set."""
        if finding.id is None:
            finding.id = self._next_id_fn()
        os.makedirs(self.findings_dir, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", finding.vuln_class.lower()).strip("-")
        filename = f"{finding.id}-{slug}.yaml"
        path = os.path.join(self.findings_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(
                finding.to_dict(),
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )

    def save_validated(self, finding: Finding, scope: Scope = None) -> None:
        """Save a finding only if it passes the 9-question validation gate.

        This is the spec-required entry point for agent-generated findings.
        Use save() only for internal/test use where gate is not needed.

        Raises:
            ValidationFailed: if any of the 9 gate questions fail.
        """
        gate_result = ValidationGate.run(finding, scope)
        if not gate_result.passed:
            raise ValidationFailed(gate_result.reasons)
        self.save(finding)

    def load(self, finding_id: str) -> Optional[Finding]:
        """Load a finding by ID."""
        if not os.path.exists(self.findings_dir):
            return None
        for filename in os.listdir(self.findings_dir):
            if filename.startswith(finding_id + "-"):
                path = os.path.join(self.findings_dir, filename)
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                return self._dict_to_finding(data)
        return None

    def list_ids(self) -> list[str]:
        """Return sorted list of all finding IDs."""
        if not os.path.exists(self.findings_dir):
            return []
        ids = []
        for fname in os.listdir(self.findings_dir):
            m = re.match(r"^(F\d+)", fname)
            if m:
                ids.append(m.group(1))
        return sorted(ids)

    def find_by_fingerprint(self, fingerprint: str) -> Optional[Finding]:
        """Find a finding by its dedup fingerprint."""
        if not os.path.exists(self.findings_dir):
            return None
        for fname in os.listdir(self.findings_dir):
            if not fname.endswith(".yaml"):
                continue
            path = os.path.join(self.findings_dir, fname)
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and data.get("fingerprint") == fingerprint:
                return self._dict_to_finding(data)
        return None

    def load_all(self) -> list[Finding]:
        """Load all findings."""
        return [self.load(fid) for fid in self.list_ids()]

    def _next_id_fn(self) -> str:
        existing = self.list_ids()
        while True:
            candidate = f"F{self._next_id:03d}"
            self._next_id += 1
            if candidate not in existing:
                return candidate

    def _dict_to_finding(self, data: dict) -> Finding:
        f = Finding(
            title=data.get("title", ""),
            vuln_class=data.get("vuln_class", ""),
            target=data.get("target", ""),
            id=data.get("id"),
            parameter=data.get("parameter"),
            method=data.get("method", "GET"),
            status=FindingStatus(data.get("status", "draft")),
            severity=Severity(data.get("severity", "info")),
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            oob_hit=data.get("oob_hit"),
            reproduction_steps=data.get("reproduction_steps") or [],
            impact=data.get("impact"),
            fix=data.get("fix"),
            fingerprint=data.get("fingerprint"),
            description=data.get("description", ""),
            chain_parents=data.get("chain_parents") or [],
            created_at=data.get("created_at", ""),
            validated_at=data.get("validated_at"),
        )
        if data.get("evidence"):
            ev = data["evidence"]
            f.evidence = Evidence(
                request=ev.get("request"),
                response=ev.get("response"),
                screenshot=ev.get("screenshot"),
                poc=ev.get("poc"),
            )
        return f

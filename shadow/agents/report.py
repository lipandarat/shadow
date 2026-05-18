"""Report agent — generates Markdown bug bounty reports. Never auto-submits."""

import os
from datetime import datetime, timezone
from shadow.core.models import Engagement, Finding, FindingStatus
from shadow.core.store import FindingStore
from shadow.core.cvss import CVSSCalculator
from shadow.core.dedup import DedupEngine


class ReportAgent:
    def __init__(
        self,
        engagement: Engagement,
        store: FindingStore,
        platform_client=None,
    ):
        self.engagement = engagement
        self.store = store
        self.platform_client = platform_client
        self.dedup = DedupEngine(store)

    def generate(self, output_path: str = None) -> str:
        """Generate Markdown report. Returns path to report file. NEVER auto-submits."""
        findings = self.store.load_all()
        validated = [f for f in findings if f.status in (
            FindingStatus.VALIDATED, FindingStatus.REPORTED, FindingStatus.ACCEPTED
        )]

        report = self._build_report(validated)

        if output_path is None:
            output_path = os.path.join(self.engagement.workspace_path, "report.md")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

        return output_path

    def _build_report(self, findings: list[Finding]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines = [
            f"# Bug Bounty Report — {self.engagement.program}",
            f"**Platform:** {self.engagement.platform}",
            f"**Program:** {self.engagement.program}",
            f"**Date:** {now}",
            f"**Total findings:** {len(findings)}",
            "",
            "---",
            "",
        ]

        if not findings:
            lines.append("*No validated findings.*")
            return "\n".join(lines)

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| ID | Title | Severity | CVSS | Status |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            cvss = f.cvss_score or "N/A"
            lines.append(f"| {f.id} | {f.title} | {f.severity.value} | {cvss} | {f.status.value} |")
        lines.append("")

        # Per-finding detail
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            lines.extend(self._finding_section(f))

        return "\n".join(lines)

    def _finding_section(self, f: Finding) -> list[str]:
        lines = [
            f"### {f.id}: {f.title}",
            "",
            f"**Severity:** {f.severity.value}",
            f"**CVSS Score:** {f.cvss_score or 'N/A'}",
            f"**CVSS Vector:** {f.cvss_vector or 'N/A'}",
            f"**Target:** {f.target}",
            f"**Parameter:** {f.parameter or 'N/A'}",
            f"**Vuln Class:** {f.vuln_class}",
            "",
            "#### Impact",
            "",
            f.impact or "*No impact statement.*",
            "",
            "#### Reproduction Steps",
            "",
        ]
        if f.reproduction_steps:
            for i, step in enumerate(f.reproduction_steps, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append("*No reproduction steps.*")
        lines.append("")

        if f.evidence:
            lines.append("#### Evidence")
            lines.append("")
            if f.evidence.request:
                lines.append("**Request:**")
                lines.append("```http")
                lines.append(f.evidence.request)
                lines.append("```")
            if f.evidence.response:
                lines.append("**Response:**")
                lines.append("```http")
                lines.append(f.evidence.response)
                lines.append("```")
            lines.append("")

        if f.fix:
            lines.append("#### Recommended Fix")
            lines.append("")
            lines.append(f.fix)
            lines.append("")

        lines.append("---")
        lines.append("")
        return lines

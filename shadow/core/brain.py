"""Brain — persistent memory for an engagement (brain.md)."""

import os
from datetime import datetime, timezone
from shadow.core.models import Finding


class Brain:
    def __init__(self, workspace_dir: str):
        self.brain_path = os.path.join(workspace_dir, "brain.md")

    def record_dead_end(self, finding: Finding, reasons: list[str]) -> None:
        """Append a dead end entry to brain.md."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"\n### Dead End: {finding.title} [{timestamp}]",
            f"- Target: {finding.target}",
            f"- Vuln class: {finding.vuln_class}",
            "- Reasons failed gate:",
        ]
        for r in reasons:
            lines.append(f"  - {r}")
        lines.append("")
        with open(self.brain_path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def append_note(self, note: str) -> None:
        """Append a free-form note to brain.md."""
        with open(self.brain_path, "a", encoding="utf-8") as f:
            f.write(f"\n{note}\n")

    def read(self) -> str:
        """Read full brain.md content."""
        if not os.path.exists(self.brain_path):
            return ""
        with open(self.brain_path, encoding="utf-8") as f:
            return f.read()

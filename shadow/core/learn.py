"""Learning engine — records platform responses and updates brain patterns."""

from datetime import datetime, timezone
from shadow.core.brain import Brain


class LearningEntry:
    def __init__(self, finding_id, status, bounty=None, vuln_type=None, program=None):
        self.finding_id = finding_id
        self.status = status
        self.bounty = bounty
        self.vuln_type = vuln_type
        self.program = program
        self.timestamp = datetime.now(timezone.utc).isoformat()


class LearningEngine:
    def __init__(self, brain: Brain):
        self.brain = brain
        self._entries = []

    def record(self, finding_id, status, bounty=None, vuln_type=None, program=None):
        entry = LearningEntry(finding_id, status, bounty, vuln_type, program)
        self._entries.append(entry)
        self._write_to_brain(entry)

    def get_priority_areas(self, program=None) -> list:
        accepted = [e for e in self._entries if e.status == "accepted"]
        if program:
            accepted = [e for e in accepted if e.program == program]
        counts = {}
        for e in accepted:
            if e.vuln_type:
                counts[e.vuln_type] = counts.get(e.vuln_type, 0) + 1
        return sorted(counts, key=lambda k: counts[k], reverse=True)

    def get_stats(self) -> dict:
        total = len(self._entries)
        accepted = sum(1 for e in self._entries if e.status == "accepted")
        duplicates = sum(1 for e in self._entries if e.status == "duplicate")
        total_bounty = sum(e.bounty for e in self._entries if e.bounty)
        return {
            "total": total,
            "accepted": accepted,
            "duplicates": duplicates,
            "total_bounty": total_bounty,
            "acceptance_rate": round(accepted / total, 2) if total > 0 else 0.0,
        }

    def _write_to_brain(self, entry: LearningEntry):
        status_emoji = {
            "accepted": "ACCEPTED",
            "duplicate": "DUPLICATE",
            "informational": "INFO",
            "not_applicable": "N/A",
        }.get(entry.status, entry.status.upper())
        bounty_str = f" (${entry.bounty})" if entry.bounty else ""
        note = (
            f"\n### Learning [{entry.timestamp[:10]}]\n"
            f"- Finding: {entry.finding_id}\n"
            f"- Status: {status_emoji}{bounty_str}\n"
            f"- Vuln type: {entry.vuln_type or 'unknown'}\n"
            f"- Program: {entry.program or 'unknown'}\n"
        )
        self.brain.append_note(note)

"""Learn agent — CLI wrapper for recording platform responses."""

from shadow.core.learn import LearningEngine
from shadow.core.brain import Brain


class LearnAgent:
    def __init__(self, brain: Brain):
        self.engine = LearningEngine(brain)

    def learn(self, finding_id, status, bounty=None, vuln_type=None, program=None) -> dict:
        self.engine.record(finding_id, status, bounty=bounty, vuln_type=vuln_type, program=program)
        stats = self.engine.get_stats()
        return {
            "recorded": True,
            "finding_id": finding_id,
            "status": status,
            "bounty": bounty,
            "stats": stats,
        }

    def priority_areas(self, program=None) -> list:
        return self.engine.get_priority_areas(program=program)

    def format_output(self, result: dict) -> str:
        lines = ["\n=== Learning Recorded ==="]
        lines.append(f"Finding: {result['finding_id']}")
        lines.append(f"Status: {result['status']}")
        if result.get("bounty"):
            lines.append(f"Bounty: ${result['bounty']}")
        stats = result.get("stats", {})
        lines.append(f"\nStats: {stats.get('accepted', 0)} accepted / {stats.get('total', 0)} total")
        if stats.get("total_bounty"):
            lines.append(f"Total bounty: ${stats['total_bounty']}")
        lines.append("")
        return "\n".join(lines)

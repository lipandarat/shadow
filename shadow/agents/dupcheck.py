"""Dupcheck agent — CLI-friendly wrapper around DedupEngine."""

from shadow.core.models import Finding
from shadow.core.store import FindingStore
from shadow.core.dedup import DedupEngine, FingerprintEngine, DedupResult


class DupcheckAgent:
    def __init__(self, store: FindingStore, platform_client=None):
        self.store = store
        self.platform_client = platform_client
        self.engine = DedupEngine(store)

    def check(self, finding: Finding) -> dict:
        """Check if finding is a duplicate. Returns structured result dict."""
        # Compute fingerprint
        fp = FingerprintEngine.compute(finding)

        # Local check
        local_result = self.engine.check(finding)

        # Platform check (if client available)
        platform_match = None
        if self.platform_client and not local_result.is_duplicate:
            try:
                platform_match = self.platform_client.search_hacktivity(finding)
            except Exception:
                platform_match = None

        is_dup = local_result.is_duplicate or (platform_match is not None)
        match = local_result.match or (platform_match.get("url") if platform_match else None)

        return {
            "is_duplicate": is_dup,
            "fingerprint": fp,
            "local_match": local_result.match,
            "platform_match": platform_match,
            "finding_title": finding.title,
            "finding_target": finding.target,
        }

    def format_output(self, result: dict) -> str:
        """Format dupcheck result for CLI display."""
        lines = []
        status = "DUPLICATE" if result["is_duplicate"] else "UNIQUE"
        lines.append(f"\n=== Dupcheck: {status} ===")
        lines.append(f"Finding: {result['finding_title']}")
        lines.append(f"Target: {result['finding_target']}")
        lines.append(f"Fingerprint: {result['fingerprint'][:16]}...")
        if result["local_match"]:
            lines.append(f"Local match: {result['local_match']}")
        if result["platform_match"]:
            lines.append(f"Platform match: {result['platform_match']}")
        lines.append("")
        return "\n".join(lines)

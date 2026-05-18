"""Fingerprint-based deduplication to prevent duplicate findings."""

import hashlib
from dataclasses import dataclass
from typing import Optional
from shadow.core.models import Finding


@dataclass
class DedupResult:
    is_duplicate: bool
    match: Optional[str] = None  # finding ID or platform URL


class FingerprintEngine:
    @staticmethod
    def compute(finding: Finding) -> str:
        """Compute SHA-256 fingerprint from endpoint + vuln_class + parameter."""
        from urllib.parse import urlparse
        parsed = urlparse(finding.target)
        # Normalize: scheme+host+path, lowercase
        normalized_target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower().rstrip("/")
        parameter = (finding.parameter or "").lower()
        key = f"{normalized_target}:{finding.vuln_class.lower()}:{parameter}"
        return hashlib.sha256(key.encode()).hexdigest()


class DedupEngine:
    def __init__(self, store):
        """store: FindingStore instance"""
        self.store = store

    def check(self, finding: Finding) -> DedupResult:
        """Check if finding is a duplicate of an existing local finding."""
        fp = FingerprintEngine.compute(finding)
        local_match = self.store.find_by_fingerprint(fp)
        if local_match:
            return DedupResult(is_duplicate=True, match=local_match.id)
        return DedupResult(is_duplicate=False)

    def compute_and_assign(self, finding: Finding) -> str:
        """Compute fingerprint and assign it to finding.fingerprint. Returns fingerprint."""
        fp = FingerprintEngine.compute(finding)
        finding.fingerprint = fp
        return fp

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class FindingStatus(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    REPORTED = "reported"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIONAL = "informational"
    NOT_APPLICABLE = "not_applicable"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Evidence:
    request: Optional[str] = None
    response: Optional[str] = None
    screenshot: Optional[str] = None
    poc: Optional[str] = None

    def has_any(self) -> bool:
        return any([self.request, self.response, self.screenshot, self.poc])


@dataclass
class Finding:
    title: str
    vuln_class: str
    target: str
    id: Optional[str] = None
    parameter: Optional[str] = None
    method: str = "GET"
    status: FindingStatus = FindingStatus.DRAFT
    severity: Severity = Severity.INFO
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    evidence: Optional[Evidence] = None
    oob_hit: Optional[str] = None
    reproduction_steps: list[str] = field(default_factory=list)
    impact: Optional[str] = None
    fix: Optional[str] = None
    fingerprint: Optional[str] = None
    description: str = ""
    chain_parents: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    validated_at: Optional[str] = None

    def has_evidence(self) -> bool:
        if self.oob_hit:
            return True
        if self.evidence and self.evidence.has_any():
            return True
        return False

    def to_dict(self) -> dict:
        # asdict() handles str, Enum fields correctly (produces string values)
        return asdict(self)


@dataclass
class ScopeEntry:
    domain: str
    wildcard: bool = False
    include_subdomains: bool = True
    notes: str = ""

    def __post_init__(self):
        self.domain = self.domain.lstrip(".").lower()

    def matches(self, url_or_domain: str) -> bool:
        host = url_or_domain
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            host = parsed.hostname or url_or_domain
        host = host.lower().rstrip("/")
        domain = self.domain.lower().rstrip("/")
        if host == domain:
            return True
        if (self.wildcard or self.include_subdomains) and host.endswith("." + domain):
            return True
        return False


@dataclass
class Scope:
    entries: list[ScopeEntry] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)

    def matches(self, url_or_domain: str) -> bool:
        # Check exclusions first
        if any(ScopeEntry(domain=ex).matches(url_or_domain) for ex in self.excluded):
            return False
        return any(e.matches(url_or_domain) for e in self.entries)


@dataclass
class Engagement:
    platform: str
    program: str
    workspace_path: str
    scope: Scope = field(default_factory=Scope)
    metadata: dict = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

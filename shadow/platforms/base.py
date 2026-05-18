"""Abstract base interface for bug bounty platform API clients."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


class PlatformError(Exception):
    """Raised when a platform API call fails."""
    pass


@dataclass
class ProgramScope:
    domains: list[str] = field(default_factory=list)
    wildcards: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    policy_url: str = ""
    notes: str = ""


@dataclass
class HacktivityEntry:
    title: str
    url: str
    severity: str = "unknown"
    vuln_type: str = "unknown"
    bounty: Optional[float] = None
    disclosed_at: str = ""
    program: str = ""


@dataclass
class ProgramInfo:
    slug: str
    name: str
    platform: str
    scope: ProgramScope = field(default_factory=ProgramScope)
    bounty_table: dict = field(default_factory=dict)
    submission_state: str = "open"
    url: str = ""


class BasePlatform(ABC):
    def __init__(self, api_key: str = None):
        self.api_key = api_key

    @abstractmethod
    def sync_program(self, slug: str) -> ProgramInfo:
        """Fetch program details including scope and policy."""
        pass

    @abstractmethod
    def list_programs(self) -> list[ProgramInfo]:
        """List active programs."""
        pass

    @abstractmethod
    def get_hacktivity(self, slug: str, limit: int = 20) -> list[HacktivityEntry]:
        """Fetch recent public reports for a program."""
        pass

    @abstractmethod
    def search_hacktivity(self, finding) -> Optional[HacktivityEntry]:
        """Search hacktivity for a finding that matches. Returns first match or None."""
        pass

    def _require_api_key(self) -> None:
        if not self.api_key:
            raise PlatformError("API key required. Set in ~/.shadow/config.yaml")

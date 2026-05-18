"""OOB detection infrastructure — abstract base and data types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class OOBHit:
    finding_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hit_type: str = "dns"       # dns / http
    remote_ip: str = ""
    raw_data: str = ""
    canary_url: str = ""


class OOBCollector(ABC):
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._running = False

    @abstractmethod
    def get_canary(self, finding_id: str) -> str:
        """Generate a unique canary URL for this finding."""
        pass

    @abstractmethod
    def check_hit(self, finding_id: str) -> Optional[OOBHit]:
        """Check if the canary for this finding was triggered. Returns OOBHit or None."""
        pass

    def start(self) -> None:
        """Start the OOB listener."""
        self._running = True

    def stop(self) -> None:
        """Stop the OOB listener."""
        self._running = False

    def is_running(self) -> bool:
        """Return True if listener is active."""
        return self._running

    def canary_id(self, finding_id: str) -> str:
        """Generate a short correlation ID from engagement + finding."""
        return f"shadow-{self.engagement_id[:8]}-{finding_id.lower()}"

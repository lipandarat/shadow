"""Interactsh OOB collector — uses interactsh-client binary if available."""

import json
import shutil
import subprocess
import threading
import time
from typing import Optional
from shadow.oob.collector import OOBCollector, OOBHit


class InteractshCollector(OOBCollector):
    DEFAULT_DOMAIN = "interactsh.com"
    POLL_INTERVAL = 5  # seconds

    def __init__(self, engagement_id: str, domain: str = None):
        super().__init__(engagement_id)
        self.domain = domain or self.DEFAULT_DOMAIN
        self._hits: dict[str, OOBHit] = {}
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("interactsh-client") is not None

    def get_canary(self, finding_id: str) -> str:
        cid = self.canary_id(finding_id)
        return f"{cid}.{self.domain}"

    def check_hit(self, finding_id: str) -> Optional[OOBHit]:
        return self._hits.get(finding_id)

    def start(self) -> None:
        if not self.is_available():
            return
        super().start()
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=10)
        super().stop()

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception:
                pass
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_once(self) -> None:
        result = subprocess.run(
            ["interactsh-client", "-poll", "5", "-json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                self._process_hit(data)
            except json.JSONDecodeError:
                continue

    def _process_hit(self, data: dict) -> None:
        correlation_id = data.get("correlation-id", data.get("unique-id", ""))
        for finding_id in self._extract_finding_ids(correlation_id):
            hit = OOBHit(
                finding_id=finding_id,
                hit_type=data.get("protocol", "dns").lower(),
                remote_ip=data.get("remote-address", ""),
                raw_data=json.dumps(data),
                canary_url=self.get_canary(finding_id),
            )
            self._hits[finding_id] = hit

    def _extract_finding_ids(self, correlation_id: str) -> list[str]:
        parts = correlation_id.lower().split("-")
        for part in parts:
            if part.startswith("f") and part[1:].isdigit():
                return [part.upper()]
        return []

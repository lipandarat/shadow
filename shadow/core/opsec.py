"""OPSEC guard — rate limiting and user-agent rotation to avoid detection."""

import random
import time
from collections import deque
from typing import Optional


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


class OpsecGuard:
    DEFAULT_DELAY_RANGE = (1.0, 3.0)   # seconds between requests
    MAX_REQUESTS_PER_MINUTE = 30

    def __init__(
        self,
        delay_range: tuple[float, float] = DEFAULT_DELAY_RANGE,
        max_rpm: int = MAX_REQUESTS_PER_MINUTE,
        audit_logger=None,
    ):
        self.delay_range = delay_range
        self.max_rpm = max_rpm
        self.audit = audit_logger
        self._request_times: deque = deque()
        self._ua_index = 0

    def before_request(self, target: str = "") -> dict:
        """Call before every HTTP request. Returns headers to use."""
        self._enforce_rate_limit(target)
        self._record_request()
        return self._build_headers()

    def get_user_agent(self) -> str:
        """Return next user-agent in rotation."""
        ua = USER_AGENTS[self._ua_index % len(USER_AGENTS)]
        self._ua_index += 1
        return ua

    def requests_last_minute(self) -> int:
        """Return count of requests in the last 60 seconds."""
        self._prune_old_requests()
        return len(self._request_times)

    def _enforce_rate_limit(self, target: str) -> None:
        self._prune_old_requests()
        if len(self._request_times) >= self.max_rpm:
            wait = random.uniform(5.0, 15.0)
            if self.audit:
                self.audit.log("opsec_rate_limit", target=target, wait_seconds=round(wait, 2))
            time.sleep(wait)
            self._prune_old_requests()
        else:
            delay = random.uniform(*self.delay_range)
            time.sleep(delay)

    def _record_request(self) -> None:
        self._request_times.append(time.monotonic())

    def _prune_old_requests(self) -> None:
        cutoff = time.monotonic() - 60.0
        while self._request_times and self._request_times[0] < cutoff:
            self._request_times.popleft()

    def _build_headers(self) -> dict:
        return {
            "User-Agent": self.get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

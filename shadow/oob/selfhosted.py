"""Self-hosted OOB collector — local HTTP listener for lab/VPN environments."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from shadow.oob.collector import OOBCollector, OOBHit


class _HitHandler(BaseHTTPRequestHandler):
    """HTTP request handler that records OOB hits."""

    collector_ref = None  # set by SelfHostedCollector before starting

    def do_GET(self):
        path = self.path.lstrip("/")
        if self.collector_ref:
            hit = OOBHit(
                finding_id=path,
                hit_type="http",
                remote_ip=self.client_address[0],
                raw_data=f"GET {self.path}",
                canary_url=f"http://127.0.0.1/{path}",
            )
            self.collector_ref._record_hit(path, hit)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass  # suppress default logging


class SelfHostedCollector(OOBCollector):
    def __init__(self, engagement_id: str, port: int = 0):
        super().__init__(engagement_id)
        self.port = port  # 0 = auto-assign
        self._hits: dict[str, OOBHit] = {}
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._actual_port: int = 0

    def get_canary(self, finding_id: str) -> str:
        cid = self.canary_id(finding_id)
        port = self._actual_port or self.port or 80
        return f"http://127.0.0.1:{port}/{cid}"

    def check_hit(self, finding_id: str) -> Optional[OOBHit]:
        cid = self.canary_id(finding_id)
        return self._hits.get(cid) or self._hits.get(finding_id)

    def start(self) -> None:
        _HitHandler.collector_ref = self
        self._server = HTTPServer(("127.0.0.1", self.port), _HitHandler)
        self._actual_port = self._server.server_address[1]
        super().start()
        self._server_thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._server_thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        super().stop()

    def _record_hit(self, path: str, hit: OOBHit) -> None:
        self._hits[path] = hit

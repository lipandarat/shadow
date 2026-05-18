"""Recon agent — discovers endpoints using available tools."""

import json
import os
import subprocess
from shadow.core.models import Engagement
from shadow.core.scope import ScopeEngine
from shadow.core.opsec import OpsecGuard
from shadow.core.toolcheck import ToolChecker
from shadow.core.audit import AuditLogger


class ReconAgent:
    def __init__(
        self,
        engagement: Engagement,
        toolcheck: ToolChecker = None,
        opsec: OpsecGuard = None,
        audit: AuditLogger = None,
    ):
        self.engagement = engagement
        self.toolcheck = toolcheck or ToolChecker()
        self.opsec = opsec or OpsecGuard()
        self.audit = audit or AuditLogger(engagement.workspace_path)
        self._endpoints_path = os.path.join(engagement.workspace_path, "endpoints.jsonl")

    def discover_endpoints(self, target: str) -> list[str]:
        """Run available recon tools against target. Returns list of discovered URLs."""
        # Scope check first
        ScopeEngine.assert_in_scope(target, self.engagement.scope)

        self.audit.log("recon_start", target=target)
        endpoints = set()

        tools = self.toolcheck.available_tools()

        # subfinder — subdomain enumeration
        if tools.get("subfinder"):
            subs = self._run_subfinder(target)
            endpoints.update(subs)

        # httpx — probe discovered subdomains
        if tools.get("httpx") and endpoints:
            live = self._run_httpx(list(endpoints))
            endpoints = set(live)

        # gau — historical URLs
        if tools.get("gau"):
            urls = self._run_gau(target)
            endpoints.update(urls)

        # waybackurls — historical URLs
        if tools.get("waybackurls"):
            urls = self._run_waybackurls(target)
            endpoints.update(urls)

        # Filter to in-scope only
        scoped = [
            ep for ep in endpoints
            if ScopeEngine.is_in_scope(ep, self.engagement.scope)
        ]

        self.audit.log("recon_complete", target=target, endpoints_found=len(scoped))
        return sorted(scoped)

    def append_endpoints(self, endpoints: list[str]) -> None:
        """Append discovered endpoints to endpoints.jsonl."""
        with open(self._endpoints_path, "a", encoding="utf-8") as f:
            for ep in endpoints:
                f.write(json.dumps({"url": ep}) + "\n")

    def load_endpoints(self) -> list[str]:
        """Load all endpoints from endpoints.jsonl."""
        if not os.path.exists(self._endpoints_path):
            return []
        endpoints = []
        with open(self._endpoints_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    endpoints.append(data.get("url", ""))
        return [ep for ep in endpoints if ep]

    def _run_subfinder(self, target: str) -> list[str]:
        try:
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent"],
                capture_output=True, text=True, timeout=60
            )
            return [f"https://{line.strip()}" for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _run_httpx(self, targets: list[str]) -> list[str]:
        try:
            input_data = "\n".join(targets)
            result = subprocess.run(
                ["httpx", "-silent", "-no-color"],
                input=input_data, capture_output=True, text=True, timeout=120
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _run_gau(self, target: str) -> list[str]:
        try:
            result = subprocess.run(
                ["gau", target],
                capture_output=True, text=True, timeout=60
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _run_waybackurls(self, target: str) -> list[str]:
        try:
            result = subprocess.run(
                ["waybackurls", target],
                capture_output=True, text=True, timeout=60
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

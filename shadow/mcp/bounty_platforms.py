# shadow/mcp/bounty_platforms.py
"""bounty-platforms MCP server — platform sync and scope tools for Claude Code."""

import os
import yaml
from shadow.mcp.server import ShadowMCPServer
from shadow.platforms.factory import get_platform
from shadow.core.engagement import EngagementManager
from shadow.core.scope import ScopeEngine


class BountyPlatformsMCP(ShadowMCPServer):
    def __init__(self):
        super().__init__("bounty-platforms")
        self._register_tools()

    def _register_tools(self):
        self.register_tool(
            name="sync_program",
            description="Sync scope and policy from a bug bounty platform for a program slug. Returns scope domains and policy URL.",
            parameters={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Platform name: hackerone or bugcrowd"},
                    "slug": {"type": "string", "description": "Program slug/handle"},
                },
                "required": ["platform", "slug"],
            },
            handler=self._sync_program,
        )
        self.register_tool(
            name="list_programs",
            description="List active bug bounty programs on a platform.",
            parameters={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Platform name: hackerone or bugcrowd"},
                },
                "required": ["platform"],
            },
            handler=self._list_programs,
        )
        self.register_tool(
            name="get_hacktivity",
            description="Fetch recent public vulnerability reports for a program.",
            parameters={
                "type": "object",
                "properties": {
                    "platform": {"type": "string"},
                    "slug": {"type": "string"},
                    "limit": {"type": "integer", "default": 10},
                },
                "required": ["platform", "slug"],
            },
            handler=self._get_hacktivity,
        )
        self.register_tool(
            name="check_scope",
            description="Check if a URL or domain is in scope for the current engagement.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL or domain to check"},
                    "engagement_id": {"type": "string", "description": "Engagement workspace path"},
                },
                "required": ["url"],
            },
            handler=self._check_scope,
        )

    def _sync_program(self, platform: str, slug: str) -> dict:
        try:
            api_key = self._get_api_key(platform)
            client = get_platform(platform, api_key=api_key)
            program = client.sync_program(slug)
            return {
                "success": True,
                "slug": program.slug,
                "name": program.name,
                "platform": program.platform,
                "domains": program.scope.domains,
                "wildcards": program.scope.wildcards,
                "excluded": program.scope.excluded,
                "submission_state": program.submission_state,
                "url": program.url,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _list_programs(self, platform: str) -> dict:
        try:
            api_key = self._get_api_key(platform)
            client = get_platform(platform, api_key=api_key)
            programs = client.list_programs()
            return {
                "success": True,
                "programs": [
                    {"slug": p.slug, "name": p.name, "state": p.submission_state}
                    for p in programs
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_hacktivity(self, platform: str, slug: str, limit: int = 10) -> dict:
        try:
            api_key = self._get_api_key(platform)
            client = get_platform(platform, api_key=api_key)
            entries = client.get_hacktivity(slug, limit=limit)
            return {
                "success": True,
                "entries": [
                    {
                        "title": e.title,
                        "url": e.url,
                        "severity": e.severity,
                        "vuln_type": e.vuln_type,
                        "bounty": e.bounty,
                    }
                    for e in entries
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _check_scope(self, url: str, engagement_id: str = None) -> dict:
        try:
            if engagement_id:
                mgr = EngagementManager()
                eng = mgr.load(engagement_id)
                if eng:
                    in_scope = ScopeEngine.is_in_scope(url, eng.scope)
                    return {"success": True, "url": url, "in_scope": in_scope}
            return {"success": True, "url": url, "in_scope": None, "note": "No engagement loaded"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_api_key(self, platform: str) -> str:
        config_path = os.path.join(os.path.expanduser("~"), ".shadow", "config.yaml")
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("platforms", {}).get(platform, {}).get("api_key", "")
        return ""

    def serve(self) -> None:
        """Start the MCP server via stdio transport."""
        try:
            import mcp.server.stdio
            import mcp.types as types
            from mcp.server import Server

            server = Server(self.name)

            @server.list_tools()
            async def list_tools():
                return [
                    types.Tool(
                        name=t["name"],
                        description=t["description"],
                        inputSchema=t["parameters"],
                    )
                    for t in self.list_tools()
                ]

            @server.call_tool()
            async def call_tool(name: str, arguments: dict):
                tool = self._tools.get(name)
                if not tool:
                    raise ValueError(f"Unknown tool: {name}")
                result = tool["handler"](**arguments)
                return [types.TextContent(type="text", text=str(result))]

            import asyncio
            asyncio.run(mcp.server.stdio.stdio_server(server))
        except ImportError:
            print("mcp package not available — install with: pip install mcp", flush=True)

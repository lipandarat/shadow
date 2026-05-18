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
            cfg = self._get_platform_config(platform)
            api_key = cfg.get("api_key", "")
            username = cfg.get("username", "")
            client = get_platform(platform, api_key=api_key, username=username)
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
            cfg = self._get_platform_config(platform)
            api_key = cfg.get("api_key", "")
            username = cfg.get("username", "")
            client = get_platform(platform, api_key=api_key, username=username)
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
            cfg = self._get_platform_config(platform)
            api_key = cfg.get("api_key", "")
            username = cfg.get("username", "")
            client = get_platform(platform, api_key=api_key, username=username)
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
                        "program": e.program,
                        "disclosed_at": e.disclosed_at,
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

    def _get_platform_config(self, platform: str) -> dict:
        """Return full platform config dict with api_key, username, etc."""
        config_path = os.path.join(os.path.expanduser("~"), ".shadow", "config.yaml")
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("platforms", {}).get(platform, {})
        return {}

    def _get_api_key(self, platform: str) -> str:
        return self._get_platform_config(platform).get("api_key", "")

    def serve(self) -> None:
        """Start the MCP server via stdio transport."""
        try:
            import asyncio
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

            async def main():
                async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
                    await server.run(
                        read_stream,
                        write_stream,
                        server.create_initialization_options(),
                    )

            asyncio.run(main())
        except ImportError:
            print("mcp package not available — install with: pip install mcp", flush=True)

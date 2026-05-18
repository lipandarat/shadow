# shadow/mcp/writeup_search.py
"""writeup-search MCP server — search writeups and hacktivity for Claude Code."""

from shadow.mcp.server import ShadowMCPServer
from shadow.platforms.factory import get_platform, SUPPORTED_PLATFORMS


class WriteupSearchMCP(ShadowMCPServer):
    def __init__(self):
        super().__init__("writeup-search")
        self._register_tools()

    def _register_tools(self):
        self.register_tool(
            name="search_writeups",
            description="Search public bug bounty writeups and hacktivity reports by query string.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (e.g. 'SQL injection login')"},
                    "platform": {"type": "string", "description": "Optional: hackerone or bugcrowd"},
                    "limit": {"type": "integer", "default": 10},
                },
                "required": ["query"],
            },
            handler=self._search_writeups,
        )
        self.register_tool(
            name="get_writeup",
            description="Fetch the content of a specific writeup by URL.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL of the writeup"},
                },
                "required": ["url"],
            },
            handler=self._get_writeup,
        )
        self.register_tool(
            name="similar_findings",
            description="Find similar public findings by vulnerability type across platforms.",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "Vulnerability type (e.g. sqli, xss, ssrf)"},
                    "limit": {"type": "integer", "default": 5},
                },
                "required": ["vuln_type"],
            },
            handler=self._similar_findings,
        )

    def _search_writeups(self, query: str, platform: str = None, limit: int = 10) -> dict:
        results = []
        platforms_to_search = [platform] if platform else SUPPORTED_PLATFORMS
        for p in platforms_to_search:
            try:
                client = get_platform(p)
                entries = client.get_hacktivity("", limit=limit)
                query_lower = query.lower()
                for e in entries:
                    if query_lower in e.title.lower() or query_lower in e.vuln_type.lower():
                        results.append({
                            "title": e.title,
                            "url": e.url,
                            "severity": e.severity,
                            "vuln_type": e.vuln_type,
                            "platform": p,
                        })
            except Exception:
                continue
        return {"success": True, "results": results, "count": len(results)}

    def _get_writeup(self, url: str) -> dict:
        try:
            import httpx
            resp = httpx.get(url, timeout=15, follow_redirects=True)
            return {
                "success": True,
                "url": url,
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "preview": resp.text[:500],
            }
        except Exception as e:
            return {"success": False, "url": url, "error": str(e)}

    def _similar_findings(self, vuln_type: str, limit: int = 5) -> dict:
        results = []
        for p in SUPPORTED_PLATFORMS:
            try:
                client = get_platform(p)
                entries = client.get_hacktivity("", limit=50)
                vuln_lower = vuln_type.lower()
                for e in entries:
                    if vuln_lower in e.vuln_type.lower() or vuln_lower in e.title.lower():
                        results.append({
                            "title": e.title,
                            "url": e.url,
                            "severity": e.severity,
                            "platform": p,
                        })
                        if len(results) >= limit:
                            break
            except Exception:
                continue
        return {"success": True, "results": results, "count": len(results)}

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
            print("mcp package not available", flush=True)

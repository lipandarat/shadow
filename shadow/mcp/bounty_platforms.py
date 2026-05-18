# shadow/mcp/bounty_platforms.py
"""Bounty platforms MCP server stub."""

from shadow.mcp.server import ShadowMCPServer


class BountyPlatformsMCP(ShadowMCPServer):
    def __init__(self):
        super().__init__("bounty-platforms")
        self.register_tool("sync_program", "Sync program", {}, lambda: None)
        self.register_tool("list_programs", "List programs", {}, lambda: None)
        self.register_tool("get_hacktivity", "Get hacktivity", {}, lambda: None)
        self.register_tool("check_scope", "Check scope", {}, lambda: None)

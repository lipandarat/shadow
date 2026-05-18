# shadow/mcp/writeup_search.py
"""Writeup search MCP server stub."""

from shadow.mcp.server import ShadowMCPServer


class WriteupSearchMCP(ShadowMCPServer):
    def __init__(self):
        super().__init__("writeup-search")
        self.register_tool("search_writeups", "Search writeups", {}, lambda: None)
        self.register_tool("get_writeup", "Get writeup", {}, lambda: None)
        self.register_tool("similar_findings", "Similar findings", {}, lambda: None)

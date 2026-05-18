# tests/test_mcp_bundle.py
"""MCP bundle drift test — ensures tool definitions are consistent."""

import pytest
from shadow.mcp.server import ShadowMCPServer


# Expected tools for bounty-platforms MCP
BOUNTY_PLATFORM_TOOLS = [
    "sync_program",
    "list_programs",
    "get_hacktivity",
    "check_scope",
]

# Expected tools for writeup-search MCP
WRITEUP_SEARCH_TOOLS = [
    "search_writeups",
    "get_writeup",
    "similar_findings",
]


class TestMCPBundle:
    def test_shadow_mcp_server_instantiates(self):
        server = ShadowMCPServer("test-server")
        assert server.name == "test-server"
        assert server.version == "0.1.0"

    def test_register_tool(self):
        server = ShadowMCPServer("test")
        server.register_tool(
            name="test_tool",
            description="A test tool",
            parameters={"type": "object", "properties": {}},
            handler=lambda: None,
        )
        assert "test_tool" in server.get_tool_names()

    def test_list_tools_excludes_handler(self):
        server = ShadowMCPServer("test")
        server.register_tool("t1", "desc", {}, lambda: None)
        tools = server.list_tools()
        assert len(tools) == 1
        assert "handler" not in tools[0]
        assert "name" in tools[0]
        assert "description" in tools[0]

    def test_dry_run_returns_true(self):
        server = ShadowMCPServer("test")
        assert server.dry_run() is True

    def test_bounty_platforms_tools_defined(self):
        from shadow.mcp.bounty_platforms import BountyPlatformsMCP
        server = BountyPlatformsMCP()
        registered = server.get_tool_names()
        for tool in BOUNTY_PLATFORM_TOOLS:
            assert tool in registered, f"Missing tool: {tool}"

    def test_writeup_search_tools_defined(self):
        from shadow.mcp.writeup_search import WriteupSearchMCP
        server = WriteupSearchMCP()
        registered = server.get_tool_names()
        for tool in WRITEUP_SEARCH_TOOLS:
            assert tool in registered, f"Missing tool: {tool}"

    def test_no_extra_tools_in_bounty_platforms(self):
        from shadow.mcp.bounty_platforms import BountyPlatformsMCP
        server = BountyPlatformsMCP()
        registered = set(server.get_tool_names())
        expected = set(BOUNTY_PLATFORM_TOOLS)
        extra = registered - expected
        assert not extra, f"Unexpected tools: {extra}"

    def test_no_extra_tools_in_writeup_search(self):
        from shadow.mcp.writeup_search import WriteupSearchMCP
        server = WriteupSearchMCP()
        registered = set(server.get_tool_names())
        expected = set(WRITEUP_SEARCH_TOOLS)
        extra = registered - expected
        assert not extra, f"Unexpected tools: {extra}"

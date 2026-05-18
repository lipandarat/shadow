# tests/test_mcp_bundle.py
"""MCP bundle drift test — ensures tool definitions are consistent."""

import os
import re

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


def _parse_tools_from_claude_md() -> dict[str, list[str]]:
    """Parse MCP tool names from claude/CLAUDE.md."""
    claude_md = os.path.join(os.path.dirname(__file__), "..", "claude", "CLAUDE.md")
    if not os.path.exists(claude_md):
        return {}
    with open(claude_md, encoding="utf-8") as f:
        content = f.read()
    bounty_tools = re.findall(r"`(sync_program|list_programs|get_hacktivity|check_scope)[\(`]", content)
    writeup_tools = re.findall(r"`(search_writeups|get_writeup|similar_findings)[\(`]", content)
    return {
        "bounty-platforms": list(dict.fromkeys(bounty_tools)),
        "writeup-search": list(dict.fromkeys(writeup_tools)),
    }


class TestMCPBundleClaudeMD:
    def test_claude_md_exists(self):
        """claude/CLAUDE.md must exist for bundle drift detection."""
        claude_md = os.path.join(
            os.path.dirname(__file__), "..", "claude", "CLAUDE.md"
        )
        assert os.path.exists(claude_md), "claude/CLAUDE.md not found"

    def test_bounty_tools_in_claude_md(self):
        """All bounty-platforms tools must be mentioned in claude/CLAUDE.md."""
        tools = _parse_tools_from_claude_md()
        for tool in BOUNTY_PLATFORM_TOOLS:
            assert tool in tools.get("bounty-platforms", []), \
                f"Tool '{tool}' not found in claude/CLAUDE.md"

    def test_writeup_tools_in_claude_md(self):
        """All writeup-search tools must be mentioned in claude/CLAUDE.md."""
        tools = _parse_tools_from_claude_md()
        for tool in WRITEUP_SEARCH_TOOLS:
            assert tool in tools.get("writeup-search", []), \
                f"Tool '{tool}' not found in claude/CLAUDE.md"

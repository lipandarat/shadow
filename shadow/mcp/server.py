# shadow/mcp/server.py
"""MCP server base — shared setup for Shadow MCP servers."""

import sys
from typing import Any


class ShadowMCPServer:
    """Base class for Shadow MCP servers."""

    def __init__(self, name: str, version: str = "0.1.0"):
        self.name = name
        self.version = version
        self._tools: dict[str, dict] = {}

    def register_tool(self, name: str, description: str, parameters: dict, handler) -> None:
        """Register a tool with the server."""
        self._tools[name] = {
            "name": name,
            "description": description,
            "parameters": parameters,
            "handler": handler,
        }

    def list_tools(self) -> list[dict]:
        """Return list of registered tools (without handlers)."""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            }
            for t in self._tools.values()
        ]

    def get_tool_names(self) -> list[str]:
        """Return list of registered tool names."""
        return list(self._tools.keys())

    def dry_run(self) -> bool:
        """Verify server can be instantiated without side effects. Returns True."""
        return True

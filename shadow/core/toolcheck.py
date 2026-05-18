"""Auto-detect available security tools via shutil.which()."""

import shutil
from dataclasses import dataclass
from typing import Optional


TOOLS = {
    "nmap":               "network scanning",
    "ffuf":               "directory/parameter fuzzing",
    "nuclei":             "template-based scanning",
    "httpx":              "HTTP probing",
    "subfinder":          "subdomain enumeration",
    "gau":                "URL collection",
    "waybackurls":        "historical URLs",
    "sqlmap":             "SQL injection",
    "dalfox":             "XSS scanning",
    "interactsh-client":  "OOB detection",
}


@dataclass
class ToolInfo:
    name: str
    description: str
    available: bool
    path: Optional[str] = None


class ToolChecker:
    def __init__(self):
        self._cache: Optional[dict[str, ToolInfo]] = None

    def check_all(self) -> dict[str, ToolInfo]:
        """Check all known tools. Results are cached."""
        if self._cache is None:
            self._cache = {}
            for name, desc in TOOLS.items():
                path = shutil.which(name)
                self._cache[name] = ToolInfo(
                    name=name,
                    description=desc,
                    available=path is not None,
                    path=path,
                )
        return self._cache

    def available_tools(self) -> dict[str, bool]:
        """Return dict of tool_name -> is_available."""
        return {name: info.available for name, info in self.check_all().items()}

    def is_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        return self.check_all().get(tool_name, ToolInfo(tool_name, "", False)).available

    def get_path(self, tool_name: str) -> Optional[str]:
        """Return full path to tool, or None if not available."""
        info = self.check_all().get(tool_name)
        return info.path if info else None

    def summary(self) -> str:
        """Return human-readable summary of available tools."""
        lines = ["## Available Security Tools\n"]
        for name, info in self.check_all().items():
            status = "✓" if info.available else "✗"
            path_str = f" ({info.path})" if info.path else ""
            lines.append(f"  {status} {name}{path_str} — {info.description}")
        return "\n".join(lines)

    def invalidate_cache(self) -> None:
        """Clear cached results (useful for testing)."""
        self._cache = None

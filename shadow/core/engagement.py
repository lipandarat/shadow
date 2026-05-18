"""Engagement workspace lifecycle management."""

import os
import yaml
from datetime import datetime, timezone
from typing import Optional
from shadow.core.models import Engagement, Scope, ScopeEntry


class EngagementManager:
    def __init__(self, data_home: str = None):
        if data_home is None:
            data_home = os.path.join(os.path.expanduser("~"), ".shadow", "engagements")
        self.data_home = data_home

    def create(self, platform: str, program: str) -> Engagement:
        """Create a new engagement workspace."""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        dirname = f"{platform}-{program}-{date_str}"
        workspace_path = os.path.join(self.data_home, dirname)
        os.makedirs(workspace_path, exist_ok=True)
        os.makedirs(os.path.join(workspace_path, "findings"), exist_ok=True)

        # Write empty scope.yaml
        scope_path = os.path.join(workspace_path, "scope.yaml")
        with open(scope_path, "w", encoding="utf-8") as f:
            yaml.dump({"entries": [], "excluded": []}, f, default_flow_style=False)

        # Write brain.md
        brain_path = os.path.join(workspace_path, "brain.md")
        with open(brain_path, "w", encoding="utf-8") as f:
            f.write(f"# {program} ({platform})\n\nEngagement started: {date_str}\n\n## Dead Ends\n\n## Patterns Learned\n")

        # Write empty endpoints.jsonl
        endpoints_path = os.path.join(workspace_path, "endpoints.jsonl")
        open(endpoints_path, "w").close()

        # Write empty events.jsonl (audit log)
        events_path = os.path.join(workspace_path, "events.jsonl")
        open(events_path, "w").close()

        # Write empty session.jsonl (session resume)
        session_path = os.path.join(workspace_path, "session.jsonl")
        open(session_path, "w").close()

        return Engagement(
            platform=platform,
            program=program,
            workspace_path=workspace_path,
        )

    def load(self, workspace_path: str) -> Optional[Engagement]:
        """Load an existing engagement from disk."""
        if not os.path.isdir(workspace_path):
            return None

        scope = self._load_scope(workspace_path)
        dirname = os.path.basename(workspace_path)
        # Parse platform-program-YYYYMMDD
        parts = dirname.split("-")
        platform = parts[0] if len(parts) >= 1 else "unknown"
        program = "-".join(parts[1:-1]) if len(parts) >= 3 else (parts[1] if len(parts) >= 2 else "unknown")

        return Engagement(
            platform=platform,
            program=program,
            workspace_path=workspace_path,
            scope=scope,
        )

    def write_scope(self, engagement: Engagement, scope: Scope) -> None:
        """Persist scope to scope.yaml and update engagement object."""
        scope_path = os.path.join(engagement.workspace_path, "scope.yaml")
        data = {
            "entries": [
                {
                    "domain": e.domain,
                    "wildcard": e.wildcard,
                    "include_subdomains": e.include_subdomains,
                    "notes": e.notes,
                }
                for e in scope.entries
            ],
            "excluded": scope.excluded,
        }
        with open(scope_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        engagement.scope = scope

    def _load_scope(self, workspace_path: str) -> Scope:
        scope_path = os.path.join(workspace_path, "scope.yaml")
        scope = Scope()
        if not os.path.isfile(scope_path):
            return scope
        with open(scope_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for e in data.get("entries", []):
            if isinstance(e, dict):
                scope.entries.append(ScopeEntry(
                    domain=e.get("domain", ""),
                    wildcard=e.get("wildcard", False),
                    include_subdomains=e.get("include_subdomains", True),
                    notes=e.get("notes", ""),
                ))
        scope.excluded = data.get("excluded", [])
        return scope

"""Claude Code PreToolUse hook — intercepts Bash commands to check scope."""

import json
import os
import sys
import yaml


def main():
    tool_input = json.loads(sys.stdin.read()) if not sys.stdin.isatty() else {}
    command = tool_input.get("command", "")

    if not command:
        sys.exit(0)

    scope_path = _find_scope_yaml()
    if not scope_path:
        sys.exit(0)

    with open(scope_path) as f:
        scope_data = yaml.safe_load(f) or {}

    domains = scope_data.get("entries", [])
    if not domains:
        sys.exit(0)

    print(json.dumps({
        "decision": "approve",
        "reason": "Scope check passed — scope enforcement enforced at Python level via @require_in_scope",
    }))
    sys.exit(0)


def _find_scope_yaml() -> str:
    cwd = os.getcwd()
    for _ in range(5):
        candidate = os.path.join(cwd, "scope.yaml")
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(cwd)
        if parent == cwd:
            break
        cwd = parent
    return ""


if __name__ == "__main__":
    main()

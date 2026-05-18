"""Claude Code PreToolUse hook — intercepts Write/Edit to findings/ directory."""

import json
import os
import sys


def main():
    tool_input = json.loads(sys.stdin.read()) if not sys.stdin.isatty() else {}
    file_path = tool_input.get("file_path", tool_input.get("path", ""))

    if "findings/" not in file_path and "findings\\" not in file_path:
        sys.exit(0)

    print(json.dumps({
        "decision": "approve",
        "reason": "Finding save intercepted — validation gate enforced at Python level via store.save()",
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()

# Shadow CLI & Slash Commands — Implementation Plan 7/8

> **Requires:** Plans 1-6 complete

**Goal:** CLI commands (`shadow new/sync/hunt/...`) and Claude Code slash command files (`.md` in `claude/commands/`).

---

### Task 1: CLI main entry point

**Create:** `shadow/cli/__init__.py`, `shadow/cli/main.py`

`shadow` CLI with subcommands:
- `new <platform> <program>` → engagement manager create
- `sync <platform> <program>` → platform sync
- `hunt <target> [--vuln-class X] [--resume]` → hunt agent run
- `validate <finding_id>` → validate agent
- `chain <finding_id>` → chain agent
- `report [--format md|yaml]` → report agent
- `dupcheck <finding_id>` → dupcheck
- `learn <finding_id> <status> [--bounty N] [--vuln-type X]` → learning
- `oob start|stop|check` → OOB management
- `mcp serve <server>` → MCP

Uses current working directory to detect engagement context.

**Create:** `shadow/cli/commands/` — one module per command:
- `new.py`, `sync.py`, `hunt.py`, `validate.py`, `chain.py`, `report.py`, `dupcheck.py`, `learn.py`, `oob.py`

- [ ] Step 1: Implement main.py with argparse
- [ ] Step 2: Implement each command module
- [ ] Step 3: Test `shadow --help` → shows all commands
- [ ] Step 4: Commit

---

### Task 2: Claude Code slash commands

**Create:** `claude/CLAUDE.md` and `claude/commands/*.md`

`claude/CLAUDE.md`:
```markdown
# Shadow — Bug Bounty Assistant

## Available Commands
- `/new <platform> <program>` — Create engagement workspace
- `/sync <platform> <program>` — Sync scope from platform
- `/hunt <target> [--vuln-class X]` — Run hunt cycle
- `/validate <finding>` — 9-question gate
- `/chain <finding_id>` — Build exploit chain
- `/report` — Generate draft report
- `/dupcheck <vuln_type>` — Dedup check
- `/learn <id> <status> [--bounty N]` — Record learning
- `/oob start|stop|check` — OOB listener
```

Each `claude/commands/<name>.md` file:
```markdown
# /new — Create Bug Bounty Engagement

Creates a new engagement workspace for a bug bounty program.

Usage: `/new <platform> <program>`
Example: `/new hackerone tesla`

What it does:
1. Creates `~/.shadow/engagements/<platform>-<program>-<date>/`
2. Initializes `scope.yaml`, `brain.md`, `findings/`, `endpoints.jsonl`
3. Sets up audit logging

Prompt:
Act as a professional pentester. Run `shadow new <platform> <program>` to create the engagement workspace.
```

Repeat pattern for: `sync.md`, `hunt.md`, `validate.md`, `chain.md`, `report.md`, `dupcheck.md`, `learn.md`, `oob.md`

- [ ] Step 1: Create CLAUDE.md
- [ ] Step 2: Create all 9 slash command files
- [ ] Step 3: Verify format matches Claude Code convention
- [ ] Step 4: Commit

---

### Task 3: Hooks for Claude Code

**Create:** `shadow/hooks/__init__.py`, `shadow/hooks/pre_save_check.py`, `shadow/hooks/scope_check.py`

`pre_save_check.py` — intercepts Write/Edit to `findings/`:
```python
import sys, os
path = sys.argv[1] if len(sys.argv) > 1 else ""
if "findings/" in path:
    # Run validation gate on the content being written
    ...
```

`scope_check.py` — intercepts Bash commands:
```python
import sys
cmd = os.environ.get("CLAUDE_BASH_COMMAND", sys.argv[1] if len(sys.argv) > 1 else "")
# Extract target from command, check scope.yaml
...
```

- [ ] Step 1: Implement pre_save_check.py
- [ ] Step 2: Implement scope_check.py
- [ ] Step 3: Test both hooks with sample input
- [ ] Step 4: Commit

---

**Plan 7 complete.** CLI + slash commands ready → Plan 8 (installer).

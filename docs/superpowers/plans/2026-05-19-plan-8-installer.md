# Shadow Installer — Implementation Plan 8/8

> **Requires:** Plans 1-7 complete

**Goal:** CLI installer (`install.py`) with install/verify/render/uninstall subcommands. Manages Claude Code config, MCP servers, slash commands, and hooks.

---

### Task 1: Installer framework

**Create:** `install.py`

Subcommands:
- `python install.py install` — full install
- `python install.py verify` — check everything
- `python install.py render` — show config
- `python install.py uninstall` — clean removal

Installer uses `shadow` package itself after pip install.

- [ ] Step 1: Create install.py with argparse for 4 subcommands
- [ ] Step 2: Implement install flow
- [ ] Step 3: Commit

---

### Task 2: Install flow

`python install.py install`:
1. `pip install -e .` (editable install of shadow package)
2. Read `~/.claude/settings.json` (or create if missing)
3. Add MCP server entries:
   ```json
   {
     "mcpServers": {
       "bounty-platforms": {
         "command": "python", "args": ["-m", "shadow.cli.main", "mcp", "serve", "bounty-platforms"]
       },
       "writeup-search": {
         "command": "python", "args": ["-m", "shadow.cli.main", "mcp", "serve", "writeup-search"]
       }
     }
   }
   ```
4. Add Claude Code hooks to settings.json (PreToolUse for Write/Edit + Bash)
5. Copy `claude/commands/*.md` → `~/.claude/commands/`
6. Copy `claude/CLAUDE.md` → `~/.claude/CLAUDE.md` (merge, don't overwrite)
7. Create `~/.shadow/config.yaml` with empty template if not exists
8. Run verify automatically

---

### Task 3: Verify flow

`python install.py verify`:
1. Import all shadow modules → no ImportError
2. Check MCP entries in `~/.claude/settings.json`
3. Check hooks in `~/.claude/settings.json`
4. Check slash commands in `~/.claude/commands/`
5. `shadow mcp serve --dry-run` for both servers (import + init only)
6. Run `pytest tests/test_mcp_bundle.py -v`
7. Report: PASS/FAIL per check

---

### Task 4: Render flow

`python install.py render`:
- Display current config:
  - `~/.shadow/config.yaml` contents
  - MCP servers registered
  - Slash commands installed
  - Hooks active
  - Shadow version

---

### Task 5: Uninstall flow

`python install.py uninstall`:
1. Remove MCP entries from `~/.claude/settings.json`
2. Remove hooks from `~/.claude/settings.json`
3. Remove slash commands from `~/.claude/commands/`
4. `pip uninstall shadow -y`
5. Warn: engagement data in `~/.shadow/` NOT deleted
6. Print: "To delete all data: rm -rf ~/.shadow/"

---

### Task 6: Integration test

**Create:** `tests/test_installer.py`

Tests:
- `python install.py verify` exits 0 on clean install
- `python install.py render` outputs expected sections
- `python install.py uninstall` removes entries, exits 0

- [ ] Step 1: Write integration test
- [ ] Step 2: Run `python install.py install` then `python install.py verify`
- [ ] Step 3: Verify all checks pass
- [ ] Step 4: Commit

---

**Plan 8 complete.** Installer works → ALL PLANS DONE. Ready for execution.

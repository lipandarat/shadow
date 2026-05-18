# Shadow MCP Servers — Implementation Plan 6/8

> **Requires:** Plans 1+2+5 complete

**Goal:** Two MCP servers for Claude Code integration: `bounty-platforms` and `writeup-search`. Both use Python `mcp` SDK, stdio transport.

---

### Task 1: MCP server base setup

**Create:** `shadow/mcp/__init__.py`, `shadow/mcp/server.py`, `tests/test_mcp_bundle.py`

Base server class with shared logic:
- `ShadowMCPServer(mcp.server.Server)` — common setup
- `serve_stdio()` — entry point for stdio transport
- Requires `mcp>=1.0` in dependencies

Bundle drift test (`test_mcp_bundle.py`):
- Loads tool definitions from `claude/CLAUDE.md` (parse markdown tables)
- Loads tool implementations from MCP modules (inspect decorators)
- Asserts: all CLAUDE.md tools implemented, all implementations registered in CLAUDE.md
- Asserts: parameter schemas match

- [ ] Step 1: Write bundle drift test → run (expect FAIL)
- [ ] Step 2: Implement server.py base
- [ ] Step 3: Run base tests → PASS (import works)
- [ ] Step 4: Commit

---

### Task 2: `bounty-platforms` MCP server

**Create:** `shadow/mcp/bounty_platforms.py`

Tools:
- `sync_program(platform: str, slug: str) -> str` — syncs scope+policy to engagement workspace
- `list_programs(platform: str) -> list[dict]` — active programs
- `get_hacktivity(platform: str, slug: str, limit: int = 10) -> list[dict]` — recent public reports
- `check_scope(url: str, engagement_id: str) -> bool` — in-scope check

Uses `PlatformFactory` and `EngagementManager` internally.
Entry point CLI: `shadow mcp serve bounty-platforms`

Tests: mock platform API, verify tool outputs

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement bounty_platforms.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 3: `writeup-search` MCP server

**Create:** `shadow/mcp/writeup_search.py`

Tools:
- `search_writeups(query: str, platform: str | None = None) -> list[dict]` — searches hacktivity
- `get_writeup(url: str) -> dict` — fetches writeup content
- `similar_findings(vuln_type: str, limit: int = 5) -> list[dict]` — similar findings across platforms

Uses `PlatformFactory` for hacktivity search.
Entry point CLI: `shadow mcp serve writeup-search`

Tests: mock platform API, verify search results

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement writeup_search.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 4: CLI entry points for MCP

**Add to:** `shadow/cli/main.py` (stub)

```python
def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    mcp = sub.add_parser("mcp")
    mcp_sub = mcp.add_subparsers()
    serve = mcp_sub.add_parser("serve")
    serve.add_argument("server", choices=["bounty-platforms", "writeup-search"])
    args = parser.parse_args()
    if args.server == "bounty-platforms":
        from shadow.mcp.bounty_platforms import serve
        serve()
    ...
```

- [ ] Step 1: Create CLI stub for `shadow mcp serve <server>`
- [ ] Step 2: Test `python -m shadow.cli.main mcp serve --dry-run` (import works)
- [ ] Step 3: Commit

---

**Plan 6 complete.** MCP servers ready → Plan 7 (CLI commands + slash commands).

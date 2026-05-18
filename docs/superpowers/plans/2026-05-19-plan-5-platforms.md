# Shadow Platform Integrations — Implementation Plan 5/8

> **Requires:** Plans 1+2 complete

**Goal:** HackerOne + Bugcrowd API clients. Sync scope, fetch program details, search hacktivity.

---

### Task 1: Platform base interface

**Create:** `shadow/platforms/__init__.py`, `shadow/platforms/base.py`

`BasePlatform` (ABC):
- `sync_program(slug) -> dict` — returns scope entries, policy URL, bounty table
- `list_programs() -> list[dict]`
- `get_hacktivity(slug, limit=20) -> list[dict]`
- `search_hacktivity(query) -> list[dict]`
- Requires API key from `~/.shadow/config.yaml`

`PlatformError(Exception)` — raised on API errors

- [ ] Step 1: Define base interface (no tests needed for ABC)
- [ ] Step 2: Commit

---

### Task 2: HackerOne API client

**Create:** `shadow/platforms/hackerone.py`, `tests/test_hackerone.py`

`HackerOneAPI(BasePlatform)`:
- GraphQL API (`https://api.hackerone.com/v1`)
- `sync_program(slug)` → query `team(handle: slug) { ... }` for scope structured_scopes, policy
- `list_programs()` → query `teams(where: {submission_state: open})` for active programs
- `get_hacktivity(slug)` → query hacktivity feed for recent public reports
- Falls back to `httpx` HTTP client
- API key from config: `config.yaml` → `platforms.hackerone.api_key`

Tests: mock httpx responses, verify scope parsing, verify pagination

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement hackerone.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 3: Bugcrowd API client

**Create:** `shadow/platforms/bugcrowd.py`, `tests/test_bugcrowd.py`

`BugcrowdAPI(BasePlatform)`:
- REST API (`https://api.bugcrowd.com`)
- `sync_program(slug)` → fetch program details, scope, policy
- `list_programs()` → fetch active programs
- `get_hacktivity(slug)` → recent submissions
- API key from config: `config.yaml` → `platforms.bugcrowd.api_key`

Tests: mock httpx responses, verify scope parsing

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement bugcrowd.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 4: Platform factory

**Create:** `shadow/platforms/factory.py`, `tests/test_platform_factory.py`

`PlatformFactory.get(platform_name) -> BasePlatform`:
- `"hackerone"` → `HackerOneAPI`
- `"bugcrowd"` → `BugcrowdAPI`
- Raises ValueError for unknown platform

Tests: verify correct class returned for each platform

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement factory.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

**Plan 5 complete.** Platforms integrated → Plan 6 (MCP servers).

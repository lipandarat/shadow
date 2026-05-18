# Shadow Agents — Implementation Plan 3/8

> **Requires:** Plans 1+2 complete

**Goal:** Agent modules: recon, hunt, validate, chain, report, dupcheck, learn. Each agent takes an Engagement and produces/modifies findings.

---

### Task 1: Recon agent

**Create:** `shadow/agents/recon.py`, `tests/test_recon.py`

`ReconAgent(engagement, toolcheck, opsec)`:
- `discover_endpoints(target)` → runs subfinder → httpx → gau → waybackurls (only tools that exist)
- `append_endpoints(endpoints)` → writes to endpoints.jsonl
- `load_endpoints() -> list[str]` → reads endpoints.jsonl
- Respects scope enforcement via `@require_in_scope`
- Respects OPSEC via `opsec.before_request(target)`

Tests: mock toolcheck to simulate tools available/unavailable, verify endpoints.jsonl written

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement recon.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 2: Hunt agent

**Create:** `shadow/agents/hunt.py`, `tests/test_hunt.py`

`HuntAgent(engagement, store, validation_gate, toolcheck, opsec, session)`:
- `run(target, vuln_class=None)` → full hunt cycle
- Loads endpoints from recon, runs tool-based + manual probes
- Each anomaly → validate immediately via gate
- PASS → store.save_finding()
- FAIL → brain.record_dead_end()
- Checkpoints every step via session.py for resume
- Respects scope + OPSEC

Tests: mock store and gate, verify findings saved only when gate passes

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement hunt.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 3: Validate agent (CLI-friendly)

**Create:** `shadow/agents/validate.py`, `tests/test_validate_agent.py`

Wraps `ValidationGate` from core with CLI-friendly output:
- `validate(finding, engagement) -> dict` — returns gate results with pass/fail per question
- Formatted output: colored PASS/FAIL per question

Tests: use real gate, verify output format

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement validate.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 4: Chain agent

**Create:** `shadow/agents/chain.py`, `tests/test_chain.py`

`ChainAgent(store)`:
- `build_chain(finding_id)` → finds other findings that share target/parameter
- Returns findings sorted by exploit order (e.g., XSS → session hijack → privilege escalation)
- Creates chain finding with `chain_parents`

Tests: create mock findings, verify chain ordering

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement chain.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 5: Report agent

**Create:** `shadow/agents/report.py`, `tests/test_report.py`

`ReportAgent(engagement, store, cvss, dedup)`:
- `generate() -> str` — Markdown report with:
  - Engagement summary (platform, program, findings count)
  - Per-finding: title, CVSS, reproduction, impact, fix
  - Dedup results
  - Overall statistics
- Outputs to `report.md` in workspace
- Returns draft path, NEVER auto-submits

Tests: verify report contains all finding fields

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement report.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 6: Dupcheck agent

**Create:** `shadow/agents/dupcheck.py`, `tests/test_dupcheck.py`

Wraps `DedupEngine` from core with CLI output:
- `check(finding, platform_client=None) -> dict` — local + platform check

Tests: mock platform API, verify dedup detection

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement dupcheck.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 7: Learn agent

**Create:** `shadow/core/learn.py`, `shadow/agents/learn.py`, `tests/test_learn.py`

`LearningEngine(brain)`:
- `record(finding_id, status, bounty, vuln_type, program)` → writes to brain.md
- `get_priority_areas(program) -> list[str]` → top accepted vuln classes

Agent wraps for CLI:
- `learn(finding_id, status, bounty=None, vuln_type=None)` → updates brain patterns

Tests: verify brain.md updated with learning entries, priority calculation

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement learn core + agent
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

**Plan 3 complete.** Agents ready → Plan 4 (adaptive payloads + OOB).

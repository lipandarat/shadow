# Shadow Validation & Quality — Implementation Plan 2/8

> **Requires:** Plan 1 complete (models, store, engagement, scope, audit)

**Goal:** 9-question validation gate, anti-hallucination filter, CVSS 3.1 calculator, fingerprint-based dedup, OPSEC guard, session resume.

---

### Task 1: Validation gate (9 questions)

**Create:** `shadow/core/validate.py`, `tests/test_validate.py`

`ValidationGate.run(finding, engagement) -> GateResult` — runs all 9 checks:
1. Reproducible (has reproduction_steps)
2. In-scope (ScopeEngine check)
3. Has concrete evidence (request/response/screenshot/PoC/OOB)
4. Severity realistic (not inflated without CVSS justification)
5. Not known false positive
6. Not duplicate (fingerprint check)
7. Real impact (not informational-only)
8. Exploitable concretely (not theory)
9. Not AI hallucination (no theory phrases without evidence)

`THEORY_PHRASES = ["could potentially", "may allow", "it is possible", "attacker could", "might be able", "theoretically", "could lead to", "may result in"]`

Tests: 9 tests — one per question, plus `test_all_pass_returns_valid`, `test_theory_phrase_fails`

**Create also:** `shadow/core/brain.py` — simple Markdown append for dead ends:
```python
class Brain:
    def __init__(self, workspace_dir): ...
    def record_dead_end(self, finding, reasons): ...  # append to brain.md
    def get_dead_ends(self) -> list: ...
```

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement validate.py + brain.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 2: CVSS 3.1 calculator

**Create:** `shadow/core/cvss.py`, `tests/test_cvss.py`

`CVSSCalculator.calculate(finding) -> tuple[score: float, vector: str]`:
- Derives AV/AC/PR/UI/S/C/I/A from finding metadata
- Severity mapping: Critical >=9.0, High >=7.0, Medium >=4.0, Low >=0.1, Info <0.1

Tests: `test_sqli_high`, `test_xss_medium`, `test_info_low`, `test_vector_format`

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement cvss.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 3: Deduplication fingerprinting

**Create:** `shadow/core/dedup.py`, `tests/test_dedup.py`

`FingerprintEngine.compute(finding) -> str` — sha256 of `{target}:{vuln_class}:{parameter}`
`DedupEngine(store).check(finding) -> DedupResult` — checks local findings + (stub for platform)

Tests: `test_same_fingerprint_for_same_params`, `test_different_fingerprint`, `test_dedup_finds_local_match`, `test_dedup_no_match`

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement dedup.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 4: OPSEC guard

**Create:** `shadow/core/opsec.py`, `tests/test_opsec.py`

`OpsecGuard` — rate limiting, user-agent rotation:
- `before_request(target)` → sleep if rate limit exceeded
- DEFAULT_DELAY_RANGE = (1.0, 3.0), MAX_REQUESTS_PER_MINUTE = 30
- Rotates realistic browser User-Agent strings
- Logs warnings to audit log if rate too high

Tests: `test_delay_between_requests`, `test_rate_limit_enforced`, `test_user_agent_rotation` (use time mocking)

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement opsec.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 5: Tool auto-detection

**Create:** `shadow/core/toolcheck.py`, `tests/test_toolcheck.py`

`ToolChecker.available_tools() -> dict[str, bool]` — checks `shutil.which()` for each tool
`ToolChecker.get_command(tool_name) -> str | None` — returns full path if available
TOOLS dict: nmap, ffuf, nuclei, httpx, subfinder, gau, waybackurls, sqlmap, dalfox, interactsh-client

Tests: `test_detects_python` (python always available), `test_unknown_tool_returns_none`

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement toolcheck.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 6: Session resume

**Create:** `shadow/core/session.py`, `tests/test_session.py`

`SessionManager(workspace_dir)` — session.jsonl:
- `checkpoint(step, state)` → write pending step
- `mark_done(step)` → update status to done
- `get_resume_point() -> str | None` → first pending step

Tests: `test_checkpoint_writes`, `test_mark_done`, `test_resume_point_pending`, `test_resume_point_all_done`

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement session.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

**Plan 2 complete.** All tests green → ready for Plan 3 (agents).

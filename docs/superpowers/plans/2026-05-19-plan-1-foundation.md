# Shadow Foundation — Implementation Plan 1/8

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]` checkbox syntax.

**Goal:** Package scaffold, core data models, file-based store, engagement workspace manager, audit log, and scope enforcement.

**Tech Stack:** Python 3.11+, PyYAML, dataclasses, pathlib, hashlib, pytest

---

### Task 1: Package scaffold

- [ ] **Step 1:** Create `pyproject.toml` (see spec section 2 for full content)
- [ ] **Step 2:** Create `shadow/__init__.py` with version `0.1.0`
- [ ] **Step 3:** Create `shadow/core/__init__.py` and `tests/__init__.py` (empty)
- [ ] **Step 4:** Run `pip install -e .` and `python -c "import shadow; print(shadow.__version__)"` → `0.1.0`
- [ ] **Step 5:** Commit `feat: shadow package scaffold`

---

### Task 2: Core data models

**Create:** `shadow/core/models.py`, `tests/test_models.py`

Models to implement (full code in spec section 2):
- `FindingStatus(str, Enum)` — draft/validated/reported/accepted/duplicate/informational/not_applicable
- `Severity(str, Enum)` — critical/high/medium/low/info
- `Evidence` dataclass — request/response/screenshot/poc with `has_any()`
- `Finding` dataclass — all fields from spec, `has_evidence()`, `to_dict()`
- `ScopeEntry` dataclass — domain/wildcard/include_subdomains, `matches(url_or_domain)`
- `Scope` dataclass — entries + excluded, `matches(url_or_domain)`
- `Engagement` dataclass — platform/program/workspace_path/scope/metadata

Tests: `test_finding_creation_minimal`, `test_has_evidence_false_when_empty`, `test_has_evidence_with_oob`, `test_to_dict`, `test_scope_exact_match`, `test_scope_subdomain_match`, `test_scope_no_match`, `test_engagement_creation`

- [ ] **Step 1:** Write tests → run `pytest tests/test_models.py -v` (expect ImportError)
- [ ] **Step 2:** Implement `shadow/core/models.py`
- [ ] **Step 3:** Run tests → all 8 PASS
- [ ] **Step 4:** Commit `feat: core data models` (not edit this exact commit msg — use descriptive msg)

---

### Task 3: Audit logger

**Create:** `shadow/core/audit.py`, `tests/test_audit.py`

`AuditLogger(workspace_dir)` — append-only events.jsonl with `log(event, **kwargs)` and `read_all() -> list[dict]`. Uses `os.fsync()` after each write for durability.

Tests: `test_log_writes_event`, `test_log_multiple_events_append`, `test_log_safe_from_crash`, `test_read_all_returns_events`

- [ ] **Step 1:** Write tests → run (expect FAIL)
- [ ] **Step 2:** Implement audit.py
- [ ] **Step 3:** Run tests → PASS
- [ ] **Step 4:** Commit

---

### Task 4: Finding store (pre-save hook ready)

**Create:** `shadow/core/store.py`, `tests/test_store.py`

`FindingStore(workspace_dir)` — YAML persistence:
- `save(finding)` → assigns `F001`, `F002`... auto-id, writes `F001-sqli.yaml`
- `load(finding_id) -> Finding | None`
- `list_ids() -> list[str]`
- `find_by_fingerprint(fingerprint) -> Finding | None`

Tests: `test_save_creates_yaml_file`, `test_save_assigns_id`, `test_save_preserves_data`, `test_list_all_returns_ids`, `test_find_by_fingerprint`, `test_next_id_increments`, `test_yaml_roundtrip`

- [ ] **Step 1:** Write tests → run (expect FAIL)
- [ ] **Step 2:** Implement store.py
- [ ] **Step 3:** Run tests → 7 PASS
- [ ] **Step 4:** Commit

---

### Task 5: Engagement manager

**Create:** `shadow/core/engagement.py`, `tests/test_engagement.py`

`EngagementManager(data_home=str|None)`:
- `create(platform, program) -> Engagement` — creates `~/.shadow/engagements/platform-program-YYYYMMDD/` with scope.yaml, brain.md, findings/
- `load(workspace_path) -> Engagement | None` — parses scope.yaml back into Scope/ScopeEntry objects
- `write_scope(engagement, scope)` — serializes Scope to YAML

Tests: `test_create_workspace`, `test_workspace_naming`, `test_load_workspace`, `test_write_scope`, `test_load_nonexistent`

- [ ] **Step 1:** Write tests → run (expect FAIL)
- [ ] **Step 2:** Implement engagement.py
- [ ] **Step 3:** Run tests → PASS
- [ ] **Step 4:** Commit

---

### Task 6: Scope enforcement

**Create:** `shadow/core/scope.py`, `tests/test_scope.py`

`ScopeEngine.is_in_scope(url_or_domain, scope) -> bool` — checks against scope entries
`ScopeViolation(Exception)` — raised when out of scope

Tests: `test_in_scope_exact`, `test_in_scope_subdomain`, `test_out_of_scope`, `test_empty_scope_blocks_all`, `test_scope_violation_is_exception`

- [ ] **Step 1:** Write tests → run (expect FAIL)
- [ ] **Step 2:** Implement scope.py
- [ ] **Step 3:** Run tests → PASS
- [ ] **Step 4:** Commit

---

**Plan 1 complete.** All tests green → ready for Plan 2 (validation gate, CVSS, dedup, OPSEC, session).

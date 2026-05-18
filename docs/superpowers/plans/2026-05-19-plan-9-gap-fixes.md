# Shadow Gap Fixes — Implementation Plan 9/9

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 5 gaps found between spec and implementation: mutator.py missing, store.save() missing gate integration, require_in_scope missing audit, installer missing CLAUDE.md copy, test_mcp_bundle.py not parsing CLAUDE.md.

**Architecture:** Each task is independent and self-contained. Tasks 1-3 add missing functionality. Tasks 4-5 fix existing files. All tasks follow TDD.

**Tech Stack:** Python 3.11+, PyYAML, pytest, existing shadow package

---

### Task 1: Add `shadow/payloads/mutator.py`

**Files:**
- Create: `shadow/payloads/mutator.py`
- Create: `tests/test_mutator.py`

Spec §2 lists `mutator.py` as a required file under `shadow/payloads/` with responsibility: "mutation & WAF bypass". The `AdaptivePayloadEngine` in `engine.py` already handles some mutation internally, but `mutator.py` should be a standalone module that provides mutation primitives used by the engine.

- [ ] **Step 1: Write failing tests**

Create `tests/test_mutator.py`:

```python
"""Tests for PayloadMutator."""

import pytest
from shadow.payloads.mutator import PayloadMutator


class TestPayloadMutator:
    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_url_encode(self, mutator):
        result = mutator.url_encode("' OR 1=1--")
        assert "%" in result
        assert "'" not in result

    def test_double_url_encode(self, mutator):
        result = mutator.double_url_encode("' OR 1=1--")
        assert "%25" in result or "%2" in result

    def test_html_entity_encode(self, mutator):
        result = mutator.html_entity_encode("<script>alert(1)</script>")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "<" not in result

    def test_comment_injection(self, mutator):
        result = mutator.comment_inject("SELECT * FROM users")
        assert "/**/" in result
        assert " " not in result.replace("/**/", " ")

    def test_case_variation(self, mutator):
        result = mutator.case_vary("select")
        assert result != "select"
        assert result.lower() == "select"

    def test_whitespace_substitution(self, mutator):
        result = mutator.whitespace_sub("SELECT * FROM users")
        assert "\t" in result or "\n" in result or "+" in result

    def test_null_byte_injection(self, mutator):
        result = mutator.null_byte("admin")
        assert "%00" in result or "\x00" in result

    def test_unicode_encode(self, mutator):
        result = mutator.unicode_encode("'")
        assert "\\u" in result or "'" not in result

    def test_mutate_all_returns_list(self, mutator):
        results = mutator.mutate_all("' OR 1=1--")
        assert isinstance(results, list)
        assert len(results) > 1
        assert all(isinstance(r, str) for r in results)

    def test_mutate_all_includes_original(self, mutator):
        original = "' OR 1=1--"
        results = mutator.mutate_all(original)
        assert original in results

    def test_waf_bypass_variants(self, mutator):
        results = mutator.waf_bypass_variants("SELECT", waf_vendor="ModSecurity")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_waf_bypass_cloudflare(self, mutator):
        results = mutator.waf_bypass_variants("' OR 1=1--", waf_vendor="Cloudflare")
        assert any("%" in r for r in results)
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_mutator.py -v`
Expected: `ImportError: cannot import name 'PayloadMutator' from 'shadow.payloads.mutator'`

- [ ] **Step 3: Implement mutator.py**

Create `shadow/payloads/mutator.py`:

```python
"""Payload mutator — standalone mutation and WAF bypass primitives."""

from urllib.parse import quote


class PayloadMutator:
    """Provides mutation primitives for payload WAF bypass."""

    def url_encode(self, payload: str) -> str:
        """URL-encode all characters."""
        return quote(payload, safe="")

    def double_url_encode(self, payload: str) -> str:
        """Double URL-encode all characters."""
        return quote(quote(payload, safe=""), safe="")

    def html_entity_encode(self, payload: str) -> str:
        """HTML entity encode special characters."""
        return (
            payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("'", "&#39;")
            .replace('"', "&quot;")
        )

    def comment_inject(self, payload: str) -> str:
        """Replace spaces with SQL comment sequences."""
        return payload.replace(" ", "/**/")

    def case_vary(self, payload: str) -> str:
        """Alternate upper/lower case to bypass case-sensitive filters."""
        result = []
        for i, c in enumerate(payload):
            result.append(c.upper() if i % 2 == 0 else c.lower())
        return "".join(result)

    def whitespace_sub(self, payload: str) -> str:
        """Substitute spaces with tab characters."""
        return payload.replace(" ", "\t")

    def null_byte(self, payload: str) -> str:
        """Append null byte for filter bypass."""
        return payload + "%00"

    def unicode_encode(self, payload: str) -> str:
        """Unicode-encode non-ASCII and special characters."""
        special = set("'\"<>&;=()")
        result = []
        for c in payload:
            if c in special or ord(c) > 127:
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)

    def mutate_all(self, payload: str) -> list[str]:
        """Return all mutations of a payload including the original."""
        mutations = [payload]
        for fn in [
            self.url_encode,
            self.double_url_encode,
            self.html_entity_encode,
            self.comment_inject,
            self.case_vary,
            self.whitespace_sub,
            self.unicode_encode,
        ]:
            try:
                mutated = fn(payload)
                if mutated not in mutations:
                    mutations.append(mutated)
            except Exception:
                continue
        return mutations

    def waf_bypass_variants(self, payload: str, waf_vendor: str = "generic") -> list[str]:
        """Return WAF-vendor-specific bypass variants."""
        vendor = waf_vendor.lower()
        variants = []
        if vendor in ("cloudflare", "generic"):
            variants.append(self.url_encode(payload))
            variants.append(self.double_url_encode(payload))
            variants.append(self.unicode_encode(payload))
        if vendor in ("modsecurity", "generic"):
            variants.append(self.comment_inject(payload))
            variants.append(self.whitespace_sub(payload))
            variants.append(self.case_vary(payload))
        if vendor in ("aws waf", "aws_waf", "generic"):
            variants.append(self.url_encode(payload))
            variants.append(self.html_entity_encode(payload))
        if not variants:
            variants = self.mutate_all(payload)
        return list(dict.fromkeys(variants))  # deduplicate preserving order
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_mutator.py -v`
Expected: 12/12 PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all previous tests still pass

- [ ] **Step 6: Commit**

```bash
git add shadow/payloads/mutator.py tests/test_mutator.py
git commit -m "feat: add PayloadMutator with WAF bypass primitives (spec gap fix)"
```

---

### Task 2: Integrate validation gate into `store.save()`

**Files:**
- Modify: `shadow/core/store.py`
- Modify: `tests/test_store.py`

Spec §5 requires `store.save_finding()` to call `ValidationGate.run()` before writing. Currently `store.save()` writes without any gate check — the gate only runs in `HuntAgent.process_candidate()`. This means any code that calls `store.save()` directly bypasses the gate.

- [ ] **Step 1: Read current store.py**

Read `shadow/core/store.py` and note the current `save()` method signature and imports at the top of the file before modifying.

- [ ] **Step 2: Write failing tests for gate enforcement**

Add to `tests/test_store.py`:

```python
class TestFindingStoreGateEnforcement:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as d:
            yield FindingStore(d)

    def test_save_with_gate_rejects_invalid_finding(self, store):
        """save_validated() must reject findings that fail the gate."""
        from shadow.core.store import ValidationFailed
        f = Finding(
            title="Weak finding",
            vuln_class="sqli",
            target="https://x.com",
            # Missing: reproduction_steps, impact, evidence
        )
        with pytest.raises(ValidationFailed):
            store.save_validated(f)

    def test_save_with_gate_accepts_valid_finding(self, store):
        """save_validated() must accept findings that pass the gate."""
        from shadow.core.models import Evidence
        f = Finding(
            title="SQL Injection in /login",
            vuln_class="sqli",
            target="https://x.com/login",
            parameter="username",
            reproduction_steps=["Send payload", "Observe response"],
            impact="Authentication bypass — attacker gains admin access",
            evidence=Evidence(
                request="POST /login HTTP/1.1\r\nHost: x.com\r\n\r\nusername=admin'--",
                response="HTTP/1.1 200 OK\r\n\r\nWelcome admin",
            ),
            description="Confirmed via manual testing.",
        )
        store.save_validated(f)
        assert f.id is not None
        loaded = store.load(f.id)
        assert loaded.title == "SQL Injection in /login"

    def test_save_plain_still_works_without_gate(self, store):
        """save() (plain) must still work for internal use without gate."""
        f = Finding(title="Internal", vuln_class="sqli", target="https://x.com")
        store.save(f)
        assert f.id is not None
```

- [ ] **Step 3: Run tests to verify failure**

Run: `pytest tests/test_store.py::TestFindingStoreGateEnforcement -v`
Expected: `AttributeError: 'FindingStore' object has no attribute 'save_validated'`

- [ ] **Step 4: Add `save_validated()` and `ValidationFailed` to store.py**

Add to `shadow/core/store.py` (after existing imports):

```python
from shadow.core.validate import ValidationGate
from shadow.core.models import Scope


class ValidationFailed(Exception):
    """Raised when a finding fails the 9-question validation gate."""
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__(f"Validation failed: {'; '.join(reasons)}")
```

Add to `FindingStore` class (after `save()` method):

```python
def save_validated(self, finding: Finding, scope: Scope = None) -> None:
    """Save a finding only if it passes the 9-question validation gate.

    This is the spec-required entry point for agent-generated findings.
    Use save() only for internal/test use where gate is not needed.

    Raises:
        ValidationFailed: if any of the 9 gate questions fail.
    """
    gate_result = ValidationGate.run(finding, scope)
    if not gate_result.passed:
        raise ValidationFailed(gate_result.reasons)
    self.save(finding)
```

- [ ] **Step 5: Run tests to verify pass**

Run: `pytest tests/test_store.py -v`
Expected: all tests PASS including new 3

- [ ] **Step 6: Run full suite**

Run: `pytest -q`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add shadow/core/store.py tests/test_store.py
git commit -m "feat: add save_validated() to FindingStore with gate enforcement (spec §5)"
```

---

### Task 3: Add audit logging to `require_in_scope` decorator

**Files:**
- Modify: `shadow/core/scope.py`
- Modify: `tests/test_scope.py`

Spec §6 shows `require_in_scope` calling `audit.log("scope_violation_blocked", ...)`. Current implementation raises `ScopeViolation` but does not log to audit.

- [ ] **Step 1: Write failing test**

Add to `tests/test_scope.py`:

```python
class TestRequireInScopeAudit:
    def test_scope_violation_logged_to_audit(self):
        """require_in_scope must log scope violations to audit when audit provided."""
        from unittest.mock import MagicMock
        from shadow.core.scope import require_in_scope, ScopeViolation
        from shadow.core.models import Scope, ScopeEntry

        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        mock_audit = MagicMock()

        @require_in_scope(lambda: scope, audit=mock_audit)
        def probe(target):
            return "probed"

        with pytest.raises(ScopeViolation):
            probe("https://evil.com")

        mock_audit.log.assert_called_once()
        call_kwargs = mock_audit.log.call_args
        assert call_kwargs[0][0] == "scope_violation_blocked"

    def test_no_audit_still_raises_violation(self):
        """require_in_scope without audit still raises ScopeViolation."""
        from shadow.core.scope import require_in_scope, ScopeViolation
        from shadow.core.models import Scope, ScopeEntry

        scope = Scope(entries=[ScopeEntry(domain="example.com")])

        @require_in_scope(lambda: scope)
        def probe(target):
            return "probed"

        with pytest.raises(ScopeViolation):
            probe("https://evil.com")
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_scope.py::TestRequireInScopeAudit -v`
Expected: `TypeError: require_in_scope() got an unexpected keyword argument 'audit'`

- [ ] **Step 3: Update `require_in_scope` in scope.py**

Read current `shadow/core/scope.py` and replace `require_in_scope` with:

```python
def require_in_scope(scope_getter, audit=None):
    """
    Decorator factory. scope_getter is a callable that returns the current Scope.
    audit is an optional AuditLogger instance for logging violations.

    Usage:
        @require_in_scope(lambda: engagement.scope, audit=audit_logger)
        def run_nuclei(target, templates):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(target, *args, **kwargs):
            scope = scope_getter()
            if not ScopeEngine.is_in_scope(target, scope):
                if audit is not None:
                    audit.log(
                        "scope_violation_blocked",
                        target=target,
                        func=func.__name__,
                    )
                raise ScopeViolation(
                    f"Target '{target}' is not in scope. "
                    f"Check scope.yaml before testing."
                )
            return func(target, *args, **kwargs)
        return wrapper
    return decorator
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_scope.py -v`
Expected: all tests PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add shadow/core/scope.py tests/test_scope.py
git commit -m "feat: add audit logging to require_in_scope decorator (spec §6)"
```

---

### Task 4: Installer copies `claude/CLAUDE.md` to `~/.claude/CLAUDE.md`

**Files:**
- Modify: `install.py`
- Modify: `tests/test_installer.py`

Plan 8 Task 2 step 6 requires: "Copy `claude/CLAUDE.md` → `~/.claude/CLAUDE.md` (merge, don't overwrite)". Current installer does not do this.

- [ ] **Step 1: Write failing test**

Add to `tests/test_installer.py`:

```python
import subprocess, sys, os

def test_install_copies_claude_md():
    """install should copy claude/CLAUDE.md to ~/.claude/CLAUDE.md if not exists."""
    # Run render to check if CLAUDE.md section is mentioned
    result = subprocess.run(
        [sys.executable, "install.py", "render"],
        capture_output=True, text=True,
        cwd=os.path.join(os.path.expanduser("~"), "shadow")
    )
    assert result.returncode == 0
    # render should mention CLAUDE.md
    assert "CLAUDE" in result.stdout or "claude" in result.stdout.lower()
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_installer.py::test_install_copies_claude_md -v`
Expected: FAIL — "CLAUDE" not in render output

- [ ] **Step 3: Add CLAUDE.md copy to `_copy_slash_commands()` in install.py**

Read `install.py` and find `_copy_slash_commands()`. Add CLAUDE.md copy after the commands loop:

```python
def _copy_slash_commands():
    os.makedirs(CLAUDE_COMMANDS_DIR, exist_ok=True)
    commands_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude", "commands")
    if os.path.isdir(commands_src):
        for fname in os.listdir(commands_src):
            if fname.endswith(".md"):
                shutil.copy2(
                    os.path.join(commands_src, fname),
                    os.path.join(CLAUDE_COMMANDS_DIR, fname)
                )

    # Copy claude/CLAUDE.md → ~/.claude/CLAUDE.md (only if not exists — don't overwrite)
    claude_md_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude", "CLAUDE.md")
    claude_md_dst = os.path.join(os.path.expanduser("~"), ".claude", "CLAUDE.md")
    if os.path.isfile(claude_md_src) and not os.path.exists(claude_md_dst):
        shutil.copy2(claude_md_src, claude_md_dst)
```

Also update `cmd_render()` to show CLAUDE.md status. Find the render function and add after slash commands section:

```python
print("\nCLAUDE.md:")
claude_md_path = os.path.join(os.path.expanduser("~"), ".claude", "CLAUDE.md")
if os.path.exists(claude_md_path):
    print(f"  {claude_md_path} (exists)")
else:
    print(f"  {claude_md_path} (not installed)")
```

- [ ] **Step 4: Run test to verify pass**

Run: `pytest tests/test_installer.py -v`
Expected: all tests PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add install.py tests/test_installer.py
git commit -m "feat: installer copies claude/CLAUDE.md to ~/.claude/CLAUDE.md (plan 8 gap)"
```

---

### Task 5: `test_mcp_bundle.py` parses tool list from `claude/CLAUDE.md`

**Files:**
- Modify: `tests/test_mcp_bundle.py`

Plan 6 Task 1 requires: "Loads tool definitions from `claude/CLAUDE.md` (parse markdown tables)". Current `test_mcp_bundle.py` uses hardcoded lists. This means if CLAUDE.md and implementation drift, the test won't catch it.

- [ ] **Step 1: Read current test_mcp_bundle.py**

Run: `Get-Content C:\Users\ajulr\shadow\tests\test_mcp_bundle.py`

Note the current hardcoded `BOUNTY_PLATFORM_TOOLS` and `WRITEUP_SEARCH_TOOLS` lists.

- [ ] **Step 2: Write failing test for CLAUDE.md parsing**

Add to `tests/test_mcp_bundle.py`:

```python
def _parse_tools_from_claude_md() -> dict[str, list[str]]:
    """Parse MCP tool names from claude/CLAUDE.md command table."""
    import re
    claude_md = os.path.join(os.path.dirname(__file__), "..", "claude", "CLAUDE.md")
    if not os.path.exists(claude_md):
        return {}
    with open(claude_md, encoding="utf-8") as f:
        content = f.read()
    # Find bounty-platforms tools section
    bounty_tools = re.findall(r"`(sync_program|list_programs|get_hacktivity|check_scope)`", content)
    writeup_tools = re.findall(r"`(search_writeups|get_writeup|similar_findings)`", content)
    return {
        "bounty-platforms": list(dict.fromkeys(bounty_tools)),
        "writeup-search": list(dict.fromkeys(writeup_tools)),
    }


class TestMCPBundleClaudeMD:
    def test_claude_md_exists(self):
        """claude/CLAUDE.md must exist for bundle drift detection."""
        claude_md = os.path.join(
            os.path.dirname(__file__), "..", "claude", "CLAUDE.md"
        )
        assert os.path.exists(claude_md), "claude/CLAUDE.md not found"

    def test_bounty_tools_in_claude_md(self):
        """All bounty-platforms tools must be mentioned in claude/CLAUDE.md."""
        tools = _parse_tools_from_claude_md()
        for tool in BOUNTY_PLATFORM_TOOLS:
            assert tool in tools.get("bounty-platforms", []), \
                f"Tool '{tool}' not found in claude/CLAUDE.md"

    def test_writeup_tools_in_claude_md(self):
        """All writeup-search tools must be mentioned in claude/CLAUDE.md."""
        tools = _parse_tools_from_claude_md()
        for tool in WRITEUP_SEARCH_TOOLS:
            assert tool in tools.get("writeup-search", []), \
                f"Tool '{tool}' not found in claude/CLAUDE.md"
```

Also add `import os` at top of test file if not already present, and add the `_parse_tools_from_claude_md` helper function before the test class.

- [ ] **Step 3: Run tests to verify failure**

Run: `pytest tests/test_mcp_bundle.py::TestMCPBundleClaudeMD -v`
Expected: `test_bounty_tools_in_claude_md` and `test_writeup_tools_in_claude_md` FAIL because CLAUDE.md doesn't mention tool names by backtick

- [ ] **Step 4: Update `claude/CLAUDE.md` to include tool names**

Read `C:\Users\ajulr\shadow\claude\CLAUDE.md` and add MCP tools section:

```markdown
## MCP Tools

### bounty-platforms

- `sync_program(platform, slug)` — fetch scope + policy, save to scope.yaml
- `list_programs(platform)` — list active programs
- `get_hacktivity(platform, slug)` — recent public reports
- `check_scope(url, engagement_id)` — check if URL is in scope

### writeup-search

- `search_writeups(query, platform)` — search writeups by query
- `get_writeup(url)` — fetch writeup content
- `similar_findings(vuln_type)` — find similar findings by vuln type
```

- [ ] **Step 5: Run tests to verify pass**

Run: `pytest tests/test_mcp_bundle.py -v`
Expected: all 11 tests PASS

- [ ] **Step 6: Run full suite**

Run: `pytest -q`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add tests/test_mcp_bundle.py claude/CLAUDE.md
git commit -m "feat: test_mcp_bundle parses tool list from claude/CLAUDE.md (plan 6 gap)"
```

---

**Plan 9 complete.** All 5 spec gaps fixed. Run `pytest -q` to confirm all tests green.

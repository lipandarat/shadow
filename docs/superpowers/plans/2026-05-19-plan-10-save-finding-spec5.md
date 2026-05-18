# Shadow save_finding() Spec §5 Gap Fix — Implementation Plan 10/10

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `save_finding()` on `FindingStore` exactly as spec §5 describes — with gate, dedup, CVSS, fingerprint, and audit all integrated — and add `DuplicateFinding` exception.

**Architecture:** Spec §5 shows `save_finding()` as the single authoritative entry point that runs the full pipeline: gate → dedup → CVSS → fingerprint → write → audit. Current `save_validated()` only runs the gate. This task adds the full pipeline as `save_finding()` while keeping `save_validated()` as a simpler alias for backward compatibility.

**Tech Stack:** Python 3.11+, existing shadow.core modules (validate, dedup, cvss, audit), pytest

---

### Task 1: Add `save_finding()` with full pipeline to `FindingStore`

**Files:**
- Modify: `shadow/core/store.py`
- Modify: `tests/test_store.py`

Spec §5 shows this exact pipeline in `save_finding()`:

```python
class FindingStore:
    def save_finding(self, finding: Finding) -> SaveResult:
        gate_result = ValidationGate.run(finding)  # 9 pertanyaan
        if not gate_result.passed:
            self._record_dead_end(finding, gate_result.reasons)
            raise ValidationFailed(gate_result.reasons)
        dedup_result = DedupEngine.check(finding)
        if dedup_result.is_duplicate:
            raise DuplicateFinding(dedup_result.match)
        finding.cvss_score = CVSSCalculator.calculate(finding)
        finding.fingerprint = FingerprintEngine.compute(finding)
        self._write(finding)
        self.audit.log("finding_saved", finding.id)
```

- [ ] **Step 1: Write failing tests**

Add to `tests/test_store.py`:

```python
class TestFindingStoreSaveFinding:
    """Tests for save_finding() — the full spec §5 pipeline."""

    @pytest.fixture
    def workspace(self):
        with tempfile.TemporaryDirectory() as d:
            # Create brain.md for dead end recording
            with open(os.path.join(d, "brain.md"), "w") as f:
                f.write("# Test\n")
            yield d

    @pytest.fixture
    def store(self, workspace):
        from shadow.core.audit import AuditLogger
        from shadow.core.brain import Brain
        s = FindingStore(workspace)
        s.audit = AuditLogger(workspace)
        s.brain = Brain(workspace)
        return s

    def _valid_finding(self):
        from shadow.core.models import Evidence
        return Finding(
            title="SQL Injection in /login",
            vuln_class="sqli",
            target="https://example.com/login",
            parameter="username",
            reproduction_steps=["Send payload", "Observe response"],
            impact="Authentication bypass — attacker gains admin access",
            evidence=Evidence(
                request="POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin'--",
                response="HTTP/1.1 200 OK\r\n\r\nWelcome admin",
            ),
            description="Confirmed via manual testing.",
        )

    def test_save_finding_exists(self, store):
        """FindingStore must have save_finding() method."""
        assert hasattr(store, "save_finding"), "save_finding() method missing"

    def test_save_finding_rejects_invalid(self, store):
        """save_finding() must reject findings that fail the gate."""
        from shadow.core.store import ValidationFailed
        f = Finding(title="Weak", vuln_class="sqli", target="https://example.com")
        with pytest.raises(ValidationFailed):
            store.save_finding(f)

    def test_save_finding_accepts_valid(self, store):
        """save_finding() must save valid findings."""
        f = self._valid_finding()
        store.save_finding(f)
        assert f.id is not None
        loaded = store.load(f.id)
        assert loaded.title == "SQL Injection in /login"

    def test_save_finding_assigns_cvss(self, store):
        """save_finding() must calculate and assign CVSS score."""
        f = self._valid_finding()
        store.save_finding(f)
        assert f.cvss_score is not None
        assert f.cvss_score > 0

    def test_save_finding_assigns_fingerprint(self, store):
        """save_finding() must compute and assign fingerprint."""
        f = self._valid_finding()
        store.save_finding(f)
        assert f.fingerprint is not None
        assert len(f.fingerprint) == 64  # SHA-256 hex

    def test_save_finding_rejects_duplicate(self, store):
        """save_finding() must reject duplicate findings."""
        from shadow.core.store import DuplicateFinding
        f1 = self._valid_finding()
        store.save_finding(f1)
        f2 = self._valid_finding()  # same params = same fingerprint
        with pytest.raises(DuplicateFinding):
            store.save_finding(f2)

    def test_save_finding_logs_to_audit(self, store):
        """save_finding() must log finding_saved to audit."""
        f = self._valid_finding()
        store.save_finding(f)
        events = store.audit.read_all()
        assert any(e["event"] == "finding_saved" for e in events)

    def test_save_finding_records_dead_end_on_failure(self, store):
        """save_finding() must record dead end in brain.md when gate fails."""
        f = Finding(title="Weak", vuln_class="sqli", target="https://example.com")
        try:
            store.save_finding(f)
        except Exception:
            pass
        content = store.brain.read()
        assert "Dead End" in content

    def test_duplicate_finding_exception_has_match(self, store):
        """DuplicateFinding exception must contain the matching finding ID."""
        from shadow.core.store import DuplicateFinding
        f1 = self._valid_finding()
        store.save_finding(f1)
        f2 = self._valid_finding()
        try:
            store.save_finding(f2)
            assert False, "Should have raised"
        except DuplicateFinding as e:
            assert e.match == f1.id
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_store.py::TestFindingStoreSaveFinding -v`
Expected: `AttributeError: 'FindingStore' object has no attribute 'save_finding'` and `ImportError: cannot import name 'DuplicateFinding'`

- [ ] **Step 3: Implement `save_finding()` and `DuplicateFinding` in store.py**

Read `shadow/core/store.py` first to see current imports and structure.

Add `DuplicateFinding` exception after `ValidationFailed`:

```python
class DuplicateFinding(Exception):
    """Raised when a finding is a duplicate of an existing finding."""
    def __init__(self, match: str):
        self.match = match
        super().__init__(f"Duplicate finding: matches {match}")
```

Add these imports at the top of store.py (after existing imports):

```python
from shadow.core.cvss import CVSSCalculator
from shadow.core.dedup import DedupEngine, FingerprintEngine
```

Add `save_finding()` method to `FindingStore` class (after `save_validated()`):

```python
def save_finding(self, finding: Finding, scope=None) -> None:
    """Full spec §5 pipeline: gate → dedup → CVSS → fingerprint → write → audit.

    This is the canonical entry point for all agent-generated findings.
    Raises:
        ValidationFailed: if gate fails
        DuplicateFinding: if fingerprint matches existing finding
    """
    # Step 1: Validation gate (9 questions)
    gate_result = ValidationGate.run(finding, scope)
    if not gate_result.passed:
        if hasattr(self, "brain") and self.brain is not None:
            self.brain.record_dead_end(finding, gate_result.reasons)
        raise ValidationFailed(gate_result.reasons)

    # Step 2: Dedup check
    fp = FingerprintEngine.compute(finding)
    finding.fingerprint = fp
    dedup_engine = DedupEngine(self)
    dedup_result = dedup_engine.check(finding)
    if dedup_result.is_duplicate:
        raise DuplicateFinding(dedup_result.match)

    # Step 3: CVSS calculation
    score, vector = CVSSCalculator.calculate(finding)
    finding.cvss_score = score
    finding.cvss_vector = vector

    # Step 4: Write to disk
    self.save(finding)

    # Step 5: Audit log
    if hasattr(self, "audit") and self.audit is not None:
        self.audit.log("finding_saved", finding_id=finding.id, title=finding.title)
```

Also add `audit` and `brain` as optional attributes in `__init__`:

```python
def __init__(self, workspace_dir: str):
    self.workspace_dir = workspace_dir
    self.findings_dir = os.path.join(workspace_dir, "findings")
    self._next_id = 1
    self.audit = None   # set externally if audit logging needed
    self.brain = None   # set externally if dead end recording needed
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_store.py::TestFindingStoreSaveFinding -v`
Expected: 9/9 PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all previous tests still pass

- [ ] **Step 6: Commit**

```bash
git add shadow/core/store.py tests/test_store.py
git commit -m "feat(store): add save_finding() full pipeline per spec §5 (gate+dedup+cvss+fingerprint+audit)"
```

---

**Plan 10 complete.** `save_finding()` now matches spec §5 exactly. Run `pytest -q` to confirm all tests green.

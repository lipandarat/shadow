import os, tempfile
import pytest
import yaml
from shadow.core.models import Finding, Evidence
from shadow.core.store import FindingStore


class TestFindingStore:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as d:
            yield FindingStore(d)

    def test_save_creates_yaml_file(self, store):
        f = Finding(title="SQLi", vuln_class="sqli", target="https://x.com")
        store.save(f)
        files = os.listdir(store.findings_dir)
        assert len(files) == 1
        assert files[0].endswith(".yaml")

    def test_save_assigns_id(self, store):
        f = Finding(title="SQLi", vuln_class="sqli", target="https://x.com")
        store.save(f)
        assert f.id is not None
        assert f.id.startswith("F")

    def test_save_preserves_data(self, store):
        f = Finding(
            title="XSS in search",
            vuln_class="xss",
            target="https://x.com/search",
            parameter="q",
            impact="session hijack",
        )
        store.save(f)
        loaded = store.load(f.id)
        assert loaded.title == "XSS in search"
        assert loaded.vuln_class == "xss"
        assert loaded.parameter == "q"
        assert loaded.impact == "session hijack"

    def test_save_preserves_evidence(self, store):
        e = Evidence(request="GET / HTTP/1.1", response="200 OK")
        f = Finding(title="XSS", vuln_class="xss", target="https://x.com", evidence=e)
        store.save(f)
        loaded = store.load(f.id)
        assert loaded.evidence.request == "GET / HTTP/1.1"
        assert loaded.evidence.response == "200 OK"

    def test_list_ids_returns_sorted(self, store):
        store.save(Finding(title="A", vuln_class="sqli", target="https://x.com"))
        store.save(Finding(title="B", vuln_class="xss", target="https://x.com"))
        ids = store.list_ids()
        assert ids == ["F001", "F002"]

    def test_find_by_fingerprint(self, store):
        f = Finding(
            title="SQLi",
            vuln_class="sqli",
            target="https://x.com/login",
            fingerprint="abc123",
        )
        store.save(f)
        match = store.find_by_fingerprint("abc123")
        assert match is not None
        assert match.id == f.id
        assert store.find_by_fingerprint("nonexistent") is None

    def test_next_id_increments(self, store):
        store.save(Finding(title="1", vuln_class="sqli", target="https://x.com"))
        store.save(Finding(title="2", vuln_class="sqli", target="https://x.com"))
        assert store.list_ids() == ["F001", "F002"]

    def test_yaml_roundtrip_complex(self, store):
        f = Finding(
            title="SQLi",
            vuln_class="sqli",
            target="https://x.com",
            reproduction_steps=["step1", "step2"],
            impact="data breach",
            cvss_score=8.6,
        )
        store.save(f)
        path = os.path.join(store.findings_dir, f"{f.id}-sqli.yaml")
        with open(path) as fh:
            data = yaml.safe_load(fh)
        assert data["cvss_score"] == 8.6
        assert data["reproduction_steps"] == ["step1", "step2"]

    def test_load_nonexistent_returns_none(self, store):
        assert store.load("F999") is None

    def test_load_all(self, store):
        store.save(Finding(title="A", vuln_class="sqli", target="https://x.com"))
        store.save(Finding(title="B", vuln_class="xss", target="https://x.com"))
        all_findings = store.load_all()
        assert len(all_findings) == 2


class TestFindingStoreGateEnforcement:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as d:
            yield FindingStore(d)

    def test_save_validated_rejects_invalid_finding(self, store):
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

    def test_save_validated_accepts_valid_finding(self, store):
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

    def test_validation_failed_has_reasons(self, store):
        """ValidationFailed exception must contain failure reasons."""
        from shadow.core.store import ValidationFailed
        f = Finding(title="X", vuln_class="sqli", target="https://x.com")
        try:
            store.save_validated(f)
            assert False, "Should have raised"
        except ValidationFailed as e:
            assert len(e.reasons) > 0
            assert isinstance(e.reasons[0], str)


class TestFindingStoreSaveFinding:
    """Tests for save_finding() — the full spec §5 pipeline."""

    @pytest.fixture
    def workspace(self):
        with tempfile.TemporaryDirectory() as d:
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
        assert hasattr(store, "save_finding"), "save_finding() method missing"

    def test_save_finding_rejects_invalid(self, store):
        from shadow.core.store import ValidationFailed
        f = Finding(title="Weak", vuln_class="sqli", target="https://example.com")
        with pytest.raises(ValidationFailed):
            store.save_finding(f)

    def test_save_finding_accepts_valid(self, store):
        f = self._valid_finding()
        store.save_finding(f)
        assert f.id is not None
        loaded = store.load(f.id)
        assert loaded.title == "SQL Injection in /login"

    def test_save_finding_assigns_cvss(self, store):
        f = self._valid_finding()
        store.save_finding(f)
        assert f.cvss_score is not None
        assert f.cvss_score > 0

    def test_save_finding_assigns_fingerprint(self, store):
        f = self._valid_finding()
        store.save_finding(f)
        assert f.fingerprint is not None
        assert len(f.fingerprint) == 64

    def test_save_finding_rejects_duplicate(self, store):
        from shadow.core.store import DuplicateFinding
        f1 = self._valid_finding()
        store.save_finding(f1)
        f2 = self._valid_finding()
        with pytest.raises(DuplicateFinding):
            store.save_finding(f2)

    def test_save_finding_logs_to_audit(self, store):
        f = self._valid_finding()
        store.save_finding(f)
        events = store.audit.read_all()
        assert any(e["event"] == "finding_saved" for e in events)

    def test_save_finding_records_dead_end_on_failure(self, store):
        f = Finding(title="Weak", vuln_class="sqli", target="https://example.com")
        try:
            store.save_finding(f)
        except Exception:
            pass
        content = store.brain.read()
        assert "Dead End" in content

    def test_duplicate_finding_exception_has_match(self, store):
        from shadow.core.store import DuplicateFinding
        f1 = self._valid_finding()
        store.save_finding(f1)
        f2 = self._valid_finding()
        try:
            store.save_finding(f2)
            assert False, "Should have raised"
        except DuplicateFinding as e:
            assert e.match == f1.id

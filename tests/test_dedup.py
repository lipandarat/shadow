import os, tempfile
import pytest
from shadow.core.models import Finding
from shadow.core.store import FindingStore
from shadow.core.dedup import FingerprintEngine, DedupEngine, DedupResult


class TestFingerprintEngine:
    def test_same_params_same_fingerprint(self):
        f1 = Finding(title="A", vuln_class="sqli", target="https://x.com/login", parameter="user")
        f2 = Finding(title="B", vuln_class="sqli", target="https://x.com/login", parameter="user")
        assert FingerprintEngine.compute(f1) == FingerprintEngine.compute(f2)

    def test_different_vuln_class_different_fingerprint(self):
        f1 = Finding(title="A", vuln_class="sqli", target="https://x.com/login", parameter="user")
        f2 = Finding(title="A", vuln_class="xss", target="https://x.com/login", parameter="user")
        assert FingerprintEngine.compute(f1) != FingerprintEngine.compute(f2)

    def test_different_target_different_fingerprint(self):
        f1 = Finding(title="A", vuln_class="sqli", target="https://x.com/login")
        f2 = Finding(title="A", vuln_class="sqli", target="https://x.com/register")
        assert FingerprintEngine.compute(f1) != FingerprintEngine.compute(f2)

    def test_different_parameter_different_fingerprint(self):
        f1 = Finding(title="A", vuln_class="sqli", target="https://x.com/login", parameter="user")
        f2 = Finding(title="A", vuln_class="sqli", target="https://x.com/login", parameter="pass")
        assert FingerprintEngine.compute(f1) != FingerprintEngine.compute(f2)

    def test_title_does_not_affect_fingerprint(self):
        f1 = Finding(title="Title A", vuln_class="sqli", target="https://x.com/login")
        f2 = Finding(title="Title B", vuln_class="sqli", target="https://x.com/login")
        assert FingerprintEngine.compute(f1) == FingerprintEngine.compute(f2)

    def test_fingerprint_is_hex_string(self):
        f = Finding(title="X", vuln_class="sqli", target="https://x.com")
        fp = FingerprintEngine.compute(f)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_url_normalized_case_insensitive(self):
        f1 = Finding(title="X", vuln_class="sqli", target="https://X.COM/Login")
        f2 = Finding(title="X", vuln_class="sqli", target="https://x.com/login")
        assert FingerprintEngine.compute(f1) == FingerprintEngine.compute(f2)


class TestDedupEngine:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as d:
            yield FindingStore(d)

    def test_no_duplicate_when_store_empty(self, store):
        engine = DedupEngine(store)
        f = Finding(title="SQLi", vuln_class="sqli", target="https://x.com/login")
        result = engine.check(f)
        assert not result.is_duplicate
        assert result.match is None

    def test_detects_local_duplicate(self, store):
        engine = DedupEngine(store)
        f1 = Finding(title="SQLi", vuln_class="sqli", target="https://x.com/login", parameter="user")
        f1.fingerprint = FingerprintEngine.compute(f1)
        store.save(f1)

        f2 = Finding(title="SQLi again", vuln_class="sqli", target="https://x.com/login", parameter="user")
        result = engine.check(f2)
        assert result.is_duplicate
        assert result.match == f1.id

    def test_compute_and_assign(self, store):
        engine = DedupEngine(store)
        f = Finding(title="X", vuln_class="xss", target="https://x.com/search")
        fp = engine.compute_and_assign(f)
        assert f.fingerprint == fp
        assert len(fp) == 64

import pytest
from shadow.core.models import Scope, ScopeEntry
from shadow.core.scope import ScopeEngine, ScopeViolation, require_in_scope


class TestScopeEngine:
    def test_in_scope_exact_domain(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        assert ScopeEngine.is_in_scope("example.com", scope)

    def test_in_scope_url_with_path(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        assert ScopeEngine.is_in_scope("https://example.com/login", scope)

    def test_in_scope_subdomain(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        assert ScopeEngine.is_in_scope("sub.example.com", scope)

    def test_out_of_scope_different_domain(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        assert not ScopeEngine.is_in_scope("other.com", scope)

    def test_out_of_scope_similar_domain(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        assert not ScopeEngine.is_in_scope("notexample.com", scope)

    def test_empty_scope_blocks_all(self):
        scope = Scope()
        assert not ScopeEngine.is_in_scope("example.com", scope)

    def test_excluded_domain_blocked(self):
        scope = Scope(
            entries=[ScopeEntry(domain="example.com")],
            excluded=["admin.example.com"],
        )
        assert scope.matches("example.com")
        assert not ScopeEngine.is_in_scope("admin.example.com", scope)

    def test_assert_in_scope_raises_violation(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        with pytest.raises(ScopeViolation) as exc_info:
            ScopeEngine.assert_in_scope("evil.com", scope)
        assert "evil.com" in str(exc_info.value)

    def test_assert_in_scope_passes_silently(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        ScopeEngine.assert_in_scope("example.com", scope)  # no exception

    def test_require_in_scope_decorator_allows(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])

        @require_in_scope(lambda: scope)
        def probe(target):
            return f"probed {target}"

        result = probe("example.com")
        assert result == "probed example.com"

    def test_require_in_scope_decorator_blocks(self):
        scope = Scope(entries=[ScopeEntry(domain="example.com")])

        @require_in_scope(lambda: scope)
        def probe(target):
            return f"probed {target}"

        with pytest.raises(ScopeViolation):
            probe("evil.com")


class TestRequireInScopeAudit:
    def test_scope_violation_logged_to_audit(self):
        """require_in_scope must log scope violations to audit when audit provided."""
        from unittest.mock import MagicMock
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        mock_audit = MagicMock()

        @require_in_scope(lambda: scope, audit=mock_audit)
        def probe(target):
            return "probed"

        with pytest.raises(ScopeViolation):
            probe("https://evil.com")

        mock_audit.log.assert_called_once()
        assert mock_audit.log.call_args[0][0] == "scope_violation_blocked"

    def test_audit_log_contains_target(self):
        """Audit log must include the target that was blocked."""
        from unittest.mock import MagicMock
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        mock_audit = MagicMock()

        @require_in_scope(lambda: scope, audit=mock_audit)
        def probe(target):
            return "probed"

        with pytest.raises(ScopeViolation):
            probe("https://evil.com")

        call_kwargs = mock_audit.log.call_args[1]
        assert call_kwargs.get("target") == "https://evil.com"

    def test_no_audit_still_raises_violation(self):
        """require_in_scope without audit still raises ScopeViolation."""
        scope = Scope(entries=[ScopeEntry(domain="example.com")])

        @require_in_scope(lambda: scope)
        def probe(target):
            return "probed"

        with pytest.raises(ScopeViolation):
            probe("https://evil.com")

    def test_no_audit_log_when_in_scope(self):
        """Audit must NOT be called when target is in scope."""
        from unittest.mock import MagicMock
        scope = Scope(entries=[ScopeEntry(domain="example.com")])
        mock_audit = MagicMock()

        @require_in_scope(lambda: scope, audit=mock_audit)
        def probe(target):
            return "probed"

        result = probe("https://example.com")
        assert result == "probed"
        mock_audit.log.assert_not_called()

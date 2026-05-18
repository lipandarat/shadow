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

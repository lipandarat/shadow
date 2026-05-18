"""Scope enforcement — blocks any tool call targeting out-of-scope assets."""

from functools import wraps
from typing import Callable
from shadow.core.models import Scope


class ScopeViolation(Exception):
    """Raised when a tool call targets an out-of-scope asset."""
    pass


class ScopeEngine:
    @staticmethod
    def is_in_scope(url_or_domain: str, scope: Scope) -> bool:
        """Return True if url_or_domain matches any scope entry and is not excluded."""
        return scope.matches(url_or_domain)

    @staticmethod
    def assert_in_scope(url_or_domain: str, scope: Scope) -> None:
        """Raise ScopeViolation if url_or_domain is not in scope."""
        if not ScopeEngine.is_in_scope(url_or_domain, scope):
            raise ScopeViolation(
                f"Target '{url_or_domain}' is not in scope. "
                f"Check scope.yaml before testing."
            )


def require_in_scope(scope_getter: Callable, audit=None):
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

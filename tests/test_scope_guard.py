from __future__ import annotations

import pytest

from bb_assistant.core.models import AssetType, ScopeRule
from bb_assistant.core.scope_guard import OutOfScopeError, ScopeGuard


def rule(value: str, asset_type: AssetType, *, in_scope: bool = True) -> ScopeRule:
    return ScopeRule(
        program_id="program-1",
        asset_type=asset_type,
        value=value,
        in_scope=in_scope,
    )


def test_exact_domain_is_allowed_when_in_scope() -> None:
    guard = ScopeGuard([rule("example.com", AssetType.DOMAIN)])

    decision = guard.validate("https://example.com")

    assert decision.in_scope is True
    assert decision.matched_rule is not None
    assert decision.matched_rule.value == "example.com"


def test_wildcard_allows_subdomain() -> None:
    guard = ScopeGuard([rule("*.example.com", AssetType.WILDCARD)])

    decision = guard.validate("https://sub.example.com")

    assert decision.in_scope is True


def test_wildcard_does_not_allow_apex_domain() -> None:
    guard = ScopeGuard([rule("*.example.com", AssetType.WILDCARD)])

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        guard.validate("https://example.com")


def test_unrelated_domain_is_blocked() -> None:
    guard = ScopeGuard([rule("example.com", AssetType.DOMAIN)])

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        guard.validate("https://evil.com")


def test_out_of_scope_rule_has_priority() -> None:
    guard = ScopeGuard(
        [
            rule("*.example.com", AssetType.WILDCARD),
            rule("out.example.com", AssetType.DOMAIN, in_scope=False),
        ]
    )

    with pytest.raises(OutOfScopeError, match="blocked by out-of-scope rule"):
        guard.validate("https://out.example.com")


def test_foreign_redirect_is_blocked() -> None:
    guard = ScopeGuard([rule("example.com", AssetType.DOMAIN)])

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        guard.validate_redirect("https://example.com/login", "https://evil.com/callback")


def test_relative_redirect_is_checked_against_scope() -> None:
    guard = ScopeGuard([rule("example.com", AssetType.DOMAIN)])

    decision = guard.validate_redirect("https://example.com/login", "/dashboard")

    assert decision.in_scope is True
    assert decision.url == "https://example.com/dashboard"


def test_without_scope_rules_everything_is_blocked() -> None:
    guard = ScopeGuard([])

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        guard.validate("https://example.com")


def test_url_prefix_rule_allows_matching_path() -> None:
    guard = ScopeGuard([rule("https://example.com/app", AssetType.URL)])

    decision = guard.validate("https://example.com/app/dashboard")

    assert decision.in_scope is True


def test_url_prefix_rule_blocks_other_path() -> None:
    guard = ScopeGuard([rule("https://example.com/app", AssetType.URL)])

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        guard.validate("https://example.com/admin")

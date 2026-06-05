from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from bb_assistant.core.checks.base import CheckStatus, SafetyCategory
from bb_assistant.core.checks.cors import CorsHeadersCheck
from bb_assistant.core.checks.csp import ContentSecurityPolicyCheck, parse_csp_directives
from bb_assistant.core.http_client import InMemoryRequestLogger, SafeHttpClient
from bb_assistant.core.models import AssetType, ScopeRule
from bb_assistant.core.rate_limiter import RateLimiter
from bb_assistant.core.scope_guard import OutOfScopeError, ScopeGuard


class NoSleepClock:
    def __init__(self) -> None:
        self.current = 0.0

    def now(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.current += seconds


def rule(value: str, asset_type: AssetType, *, in_scope: bool = True) -> ScopeRule:
    return ScopeRule(
        program_id="program-1",
        asset_type=asset_type,
        value=value,
        in_scope=in_scope,
    )


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> SafeHttpClient:
    clock = NoSleepClock()
    return SafeHttpClient(
        scope_guard=ScopeGuard([rule("example.com", AssetType.DOMAIN)]),
        rate_limiter=RateLimiter(100.0, clock=clock.now, sleeper=clock.sleep),
        request_logger=InMemoryRequestLogger(),
        transport=httpx.MockTransport(handler),
    )


def test_cors_without_headers_returns_info() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    result = CorsHeadersCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.summary == "No CORS headers observed"
    assert result.details["passive_only"] is True
    assert result.needs_manual_review is False


def test_cors_wildcard_without_credentials_is_info_low() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})

    result = CorsHeadersCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "low"
    assert result.needs_manual_review is True
    assert "allows any origin" in result.details["issues"][0]


def test_cors_wildcard_with_credentials_needs_manual_review_medium() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    result = CorsHeadersCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "medium"
    assert result.needs_manual_review is True
    assert "credentials=true" in result.details["issues"][1]


def test_specific_cors_origin_without_vary_origin_produces_hint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "https://app.example.com"},
        )

    result = CorsHeadersCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "low"
    assert result.needs_manual_review is True
    assert "Vary: Origin" in result.summary


def test_cors_check_sends_no_additional_origin_requests() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})

    CorsHeadersCheck().run("https://example.com", make_client(handler))

    assert len(requests) == 1
    assert "Origin" not in requests[0].headers


def test_csp_missing_returns_info_and_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    result = ContentSecurityPolicyCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "low"
    assert result.needs_manual_review is True
    assert "Content-Security-Policy header is missing" in result.details["issues"]


def test_csp_good_baseline_passes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none'"
                )
            },
        )

    result = ContentSecurityPolicyCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.PASS
    assert result.needs_manual_review is False
    assert result.details["issues"] == []


def test_csp_unsafe_inline_is_detected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"},
        )

    result = ContentSecurityPolicyCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.needs_manual_review is True
    assert "script-src contains 'unsafe-inline'" in result.details["issues"]


def test_csp_unsafe_eval_is_detected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'"},
        )

    result = ContentSecurityPolicyCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "medium"
    assert "script-src contains 'unsafe-eval'" in result.details["issues"]


def test_csp_wildcard_is_detected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Security-Policy": "default-src *; object-src 'none'"},
        )

    result = ContentSecurityPolicyCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.needs_manual_review is True
    assert "CSP contains wildcard source '*'" in result.details["issues"]


def test_csp_parser_handles_semicolon_and_whitespace() -> None:
    directives = parse_csp_directives("  default-src   'self'  ; ; script-src  'self'  ; ")

    assert directives == {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
    }


def test_cors_and_csp_checks_are_passive() -> None:
    assert CorsHeadersCheck().safety_category == SafetyCategory.PASSIVE
    assert ContentSecurityPolicyCheck().safety_category == SafetyCategory.PASSIVE


def test_oos_targets_are_blocked_by_safe_http_client() -> None:
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(200)

    with pytest.raises(OutOfScopeError):
        CorsHeadersCheck().run("https://evil.com", make_client(handler))

    assert sent_urls == []

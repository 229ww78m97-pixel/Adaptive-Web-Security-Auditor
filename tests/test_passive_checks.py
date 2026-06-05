from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from bb_assistant.core.checks.base import CheckStatus, SafetyCategory
from bb_assistant.core.checks.cookies import CookieFlagsCheck
from bb_assistant.core.checks.robots_txt import RobotsTxtCheck
from bb_assistant.core.checks.security_headers import (
    REQUIRED_SECURITY_HEADERS,
    SecurityHeadersCheck,
)
from bb_assistant.core.checks.security_txt import SecurityTxtCheck
from bb_assistant.core.checks.tls_basics import TLSBasicsCheck
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


def make_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    rules: list[ScopeRule] | None = None,
    logger: InMemoryRequestLogger | None = None,
) -> SafeHttpClient:
    clock = NoSleepClock()
    return SafeHttpClient(
        scope_guard=ScopeGuard(rules or [rule("example.com", AssetType.DOMAIN)]),
        rate_limiter=RateLimiter(100.0, clock=clock.now, sleeper=clock.sleep),
        request_logger=logger or InMemoryRequestLogger(),
        transport=httpx.MockTransport(handler),
    )


def test_security_headers_check_passes_when_all_headers_are_present() -> None:
    headers = {header: "present" for header in REQUIRED_SECURITY_HEADERS}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers)

    result = SecurityHeadersCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.PASS
    assert result.needs_manual_review is False
    assert result.details["missing_headers"] == []


def test_security_headers_check_reports_missing_headers_for_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Strict-Transport-Security": "max-age=31536000"})

    result = SecurityHeadersCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "low"
    assert result.needs_manual_review is True
    assert "Content-Security-Policy" in result.details["missing_headers"]


def test_cookie_flags_check_does_not_store_cookie_values() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Set-Cookie": "sessionid=super-secret-value; Secure; HttpOnly; SameSite=Lax"},
        )

    result = CookieFlagsCheck().run("https://example.com", make_client(handler))

    assert result.details["raw_cookie_names_only"] == ["sessionid"]
    assert "super-secret-value" not in str(result.details)


def test_cookie_flags_check_detects_missing_recommended_flags() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Set-Cookie": "sessionid=abc123; Path=/"})

    result = CookieFlagsCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.severity_hint == "low"
    assert result.needs_manual_review is True
    assert result.details["missing_flags_by_cookie"] == {
        "sessionid": ["Secure", "HttpOnly", "SameSite"]
    }


def test_cookie_flags_check_returns_info_when_no_cookies_are_set() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    result = CookieFlagsCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.summary == "No Set-Cookie headers observed"
    assert result.details["cookies_checked"] == 0
    assert result.needs_manual_review is False


def test_security_txt_check_detects_200() -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="Contact: mailto:security@example.com",
        )

    result = SecurityTxtCheck().run("https://example.com/app", make_client(handler))

    assert result.status == CheckStatus.PASS
    assert result.summary == "security.txt found"
    assert requested_urls == ["https://example.com/.well-known/security.txt"]
    assert result.details["contacts_found"] == ["mailto:security@example.com"]


def test_security_txt_check_treats_404_as_info() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    result = SecurityTxtCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.summary == "security.txt not found"


def test_robots_txt_check_detects_200_and_counts_disallow_lines() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="User-agent: *\nDisallow: /admin\nDisallow: /private\n")

    result = RobotsTxtCheck().run("https://example.com/app", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.summary == "robots.txt found"
    assert result.details["url_checked"] == "https://example.com/robots.txt"
    assert result.details["disallow_count"] == 2


def test_robots_txt_check_treats_404_as_info() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    result = RobotsTxtCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.INFO
    assert result.summary == "robots.txt not found"


def test_tls_basics_check_passes_for_https() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    result = TLSBasicsCheck().run("https://example.com", make_client(handler))

    assert result.status == CheckStatus.PASS
    assert result.details == {"scheme": "https", "is_https": True}


def test_tls_basics_check_fails_for_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    result = TLSBasicsCheck().run("http://example.com", make_client(handler))

    assert result.status == CheckStatus.FAIL
    assert result.severity_hint == "medium"
    assert result.needs_manual_review is True
    assert result.details == {"scheme": "http", "is_https": False}


def test_all_checks_are_passive() -> None:
    checks = [
        SecurityHeadersCheck(),
        CookieFlagsCheck(),
        SecurityTxtCheck(),
        RobotsTxtCheck(),
        TLSBasicsCheck(),
    ]

    assert all(check.safety_category == SafetyCategory.PASSIVE for check in checks)


def test_http_based_checks_use_safe_http_client_and_scope_guard() -> None:
    logger = InMemoryRequestLogger()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={header: "present" for header in REQUIRED_SECURITY_HEADERS},
        )

    client = make_client(handler, logger=logger)

    SecurityHeadersCheck().run("https://example.com", client)

    assert len(logger.entries) == 1
    assert logger.entries[0].in_scope_validated is True
    assert logger.entries[0].check_type == "security_headers"


def test_oos_target_is_blocked_by_checks_before_network_request() -> None:
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(200)

    client = make_client(handler, rules=[rule("example.com", AssetType.DOMAIN)])

    with pytest.raises(OutOfScopeError):
        SecurityTxtCheck().run("https://evil.com", client)

    assert sent_urls == []

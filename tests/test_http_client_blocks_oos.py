from __future__ import annotations

import httpx
import pytest

from bb_assistant.core.http_client import InMemoryRequestLogger, SafeHttpClient, UnsafeMethodError
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
    handler: httpx.MockTransport,
    *,
    rules: list[ScopeRule] | None = None,
    logger: InMemoryRequestLogger | None = None,
    identification_header: tuple[str, str] | None = None,
) -> SafeHttpClient:
    clock = NoSleepClock()
    return SafeHttpClient(
        scope_guard=ScopeGuard(rules or [rule("example.com", AssetType.DOMAIN)]),
        rate_limiter=RateLimiter(100.0, clock=clock.now, sleeper=clock.sleep),
        request_logger=logger or InMemoryRequestLogger(),
        identification_header=identification_header,
        transport=handler,
    )


def test_get_in_scope_is_sent() -> None:
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(200, text="ok")

    client = make_client(httpx.MockTransport(handler))

    response = client.get("https://example.com")

    assert response.status_code == 200
    assert sent_urls == ["https://example.com"]


def test_get_out_of_scope_is_blocked_before_network_request() -> None:
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(200)

    client = make_client(httpx.MockTransport(handler))

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        client.get("https://evil.com")

    assert sent_urls == []


def test_post_is_blocked_in_safe_mode() -> None:
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(200)

    client = make_client(httpx.MockTransport(handler))

    with pytest.raises(UnsafeMethodError, match="POST is not allowed"):
        client.request("POST", "https://example.com")

    assert sent_urls == []


def test_identification_header_is_set() -> None:
    observed_headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_headers.append(request.headers["X-Bug-Bounty-Contact"])
        return httpx.Response(200)

    client = make_client(
        httpx.MockTransport(handler),
        identification_header=("X-Bug-Bounty-Contact", "researcher@example.test"),
    )

    client.get("https://example.com")

    assert observed_headers == ["researcher@example.test"]


def test_allowed_request_is_logged() -> None:
    logger = InMemoryRequestLogger()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, content=b"")

    client = make_client(httpx.MockTransport(handler), logger=logger)

    client.get("https://example.com/path", check_type="security_headers")

    assert len(logger.entries) == 1
    entry = logger.entries[0]
    assert entry.method == "GET"
    assert entry.url == "https://example.com/path"
    assert entry.check_type == "security_headers"
    assert entry.in_scope_validated is True
    assert entry.response_status == 204
    assert entry.response_size == 0


def test_redirect_to_out_of_scope_domain_is_blocked() -> None:
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil.com/callback"})

    client = make_client(httpx.MockTransport(handler))

    with pytest.raises(OutOfScopeError, match="no in-scope rule matched"):
        client.get("https://example.com/login")

    assert sent_urls == ["https://example.com/login"]


def test_head_is_allowed_in_safe_mode() -> None:
    sent_methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_methods.append(request.method)
        return httpx.Response(200)

    client = make_client(httpx.MockTransport(handler))

    response = client.head("https://example.com")

    assert response.status_code == 200
    assert sent_methods == ["HEAD"]

"""Safe HTTP client that enforces scope, method, and rate-limit boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar, Protocol
from urllib.parse import urljoin

import httpx

from bb_assistant.core.rate_limiter import RateLimiter
from bb_assistant.core.scope_guard import ScopeGuard


class UnsafeMethodError(ValueError):
    """Raised when safe mode blocks an unsafe HTTP method."""


@dataclass(frozen=True)
class LoggedRequest:
    method: str
    url: str
    check_type: str
    in_scope_validated: bool
    response_status: int | None
    response_size: int | None
    identifying_header: str | None = None
    notes: str | None = None


class RequestLogger(Protocol):
    def log(self, entry: LoggedRequest) -> None:
        """Persist or store an allowed request log entry."""


class InMemoryRequestLogger:
    def __init__(self) -> None:
        self.entries: list[LoggedRequest] = []

    def log(self, entry: LoggedRequest) -> None:
        self.entries.append(entry)


class SafeHttpClient:
    """Synchronous httpx client with defensive boundaries enforced in core code."""

    SAFE_MODE_METHODS: ClassVar[set[str]] = {"GET", "HEAD"}
    REDIRECT_STATUS_CODES: ClassVar[set[int]] = {301, 302, 303, 307, 308}

    def __init__(
        self,
        *,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter,
        request_logger: RequestLogger,
        identification_header: tuple[str, str] | None = None,
        safe_mode: bool = True,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
    ) -> None:
        self._scope_guard = scope_guard
        self._rate_limiter = rate_limiter
        self._request_logger = request_logger
        self._identification_header = identification_header
        self._safe_mode = safe_mode
        self._max_redirects = max_redirects
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
        )

    def get(
        self,
        url: str,
        *,
        check_type: str = "manual",
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        return self.request("GET", url, check_type=check_type, headers=headers)

    def head(
        self,
        url: str,
        *,
        check_type: str = "manual",
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        return self.request("HEAD", url, check_type=check_type, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        check_type: str = "manual",
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        method = method.upper().strip()
        self._validate_method(method)

        current_url = url
        current_method = method
        for redirect_count in range(self._max_redirects + 1):
            response = self._send_once(
                current_method,
                current_url,
                check_type=check_type,
                headers=headers,
            )

            location = response.headers.get("Location")
            if response.status_code not in self.REDIRECT_STATUS_CODES or not location:
                return response

            if redirect_count == self._max_redirects:
                raise httpx.TooManyRedirects(
                    f"Exceeded {self._max_redirects} redirects",
                    request=response.request,
                )

            next_url = urljoin(str(response.url), location)
            self._scope_guard.validate_redirect(str(response.url), location)
            current_url = next_url
            if response.status_code == 303 and current_method != "HEAD":
                current_method = "GET"

        raise httpx.TooManyRedirects(f"Exceeded {self._max_redirects} redirects")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeHttpClient:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def _send_once(
        self,
        method: str,
        url: str,
        *,
        check_type: str,
        headers: Mapping[str, str] | None,
    ) -> httpx.Response:
        self._scope_guard.validate(url)
        request_headers = dict(headers or {})
        identifying_header = self._apply_identification_header(request_headers)

        request = self._client.build_request(method, url, headers=request_headers)
        host = request.url.host
        if host is None:
            self._scope_guard.validate(url)
            raise ValueError("request URL must include a host")

        self._rate_limiter.wait(host)
        response = self._client.send(request)
        self._request_logger.log(
            LoggedRequest(
                method=method,
                url=str(request.url),
                check_type=check_type,
                in_scope_validated=True,
                response_status=response.status_code,
                response_size=len(response.content),
                identifying_header=identifying_header,
            )
        )
        return response

    def _validate_method(self, method: str) -> None:
        if self._safe_mode and method not in self.SAFE_MODE_METHODS:
            raise UnsafeMethodError(f"{method} is not allowed while safe_mode is enabled")

    def _apply_identification_header(self, headers: dict[str, str]) -> str | None:
        if self._identification_header is None:
            return None

        header_name, header_value = self._identification_header
        headers[header_name] = header_value
        return f"{header_name}: {header_value}"

"""Small synchronous rate limiter used before outbound requests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic, sleep
from urllib.parse import urlparse

Clock = Callable[[], float]
Sleeper = Callable[[float], None]


@dataclass
class _HostBucket:
    tokens: float
    updated_at: float


class RateLimiter:
    """Token-bucket limiter with separate budgets per host."""

    def __init__(
        self,
        requests_per_second: float,
        *,
        clock: Clock = monotonic,
        sleeper: Sleeper = sleep,
        burst_capacity: float | None = None,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than 0")
        if burst_capacity is not None and burst_capacity <= 0:
            raise ValueError("burst_capacity must be greater than 0")

        self._requests_per_second = float(requests_per_second)
        self._capacity = (
            float(burst_capacity)
            if burst_capacity is not None
            else max(1.0, float(requests_per_second))
        )
        self._clock = clock
        self._sleeper = sleeper
        self._buckets: dict[str, _HostBucket] = {}

    def wait(self, host: str) -> None:
        """Block until one request token is available for the host."""

        normalized_host = _normalize_host(host)
        bucket = self._bucket_for(normalized_host)
        self._refill(bucket)

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return

        wait_seconds = (1.0 - bucket.tokens) / self._requests_per_second
        self._sleeper(wait_seconds)
        self._refill(bucket)
        bucket.tokens = max(0.0, bucket.tokens - 1.0)

    def _bucket_for(self, host: str) -> _HostBucket:
        now = self._clock()
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _HostBucket(tokens=self._capacity, updated_at=now)
            self._buckets[host] = bucket
        return bucket

    def _refill(self, bucket: _HostBucket) -> None:
        now = self._clock()
        elapsed = max(0.0, now - bucket.updated_at)
        bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._requests_per_second)
        bucket.updated_at = now


def _normalize_host(host: str) -> str:
    parsed = urlparse(host)
    normalized = parsed.hostname if parsed.hostname else host
    return normalized.lower().strip().rstrip(".")

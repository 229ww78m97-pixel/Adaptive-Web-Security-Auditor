from __future__ import annotations

import pytest

from bb_assistant.core.rate_limiter import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.current = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += seconds


def test_second_request_at_one_rps_waits() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1.0, clock=clock.now, sleeper=clock.sleep)

    limiter.wait("example.com")
    limiter.wait("example.com")

    assert clock.sleeps == pytest.approx([1.0])


def test_different_hosts_have_separate_budgets() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1.0, clock=clock.now, sleeper=clock.sleep)

    limiter.wait("one.example.com")
    limiter.wait("two.example.com")

    assert clock.sleeps == []


def test_higher_limit_allows_multiple_immediate_requests() -> None:
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock.now, sleeper=clock.sleep)

    limiter.wait("example.com")
    limiter.wait("example.com")
    limiter.wait("example.com")

    assert clock.sleeps == pytest.approx([0.5])


def test_invalid_limit_is_rejected() -> None:
    with pytest.raises(ValueError, match="requests_per_second must be greater than 0"):
        RateLimiter(0)

    with pytest.raises(ValueError, match="requests_per_second must be greater than 0"):
        RateLimiter(-1)

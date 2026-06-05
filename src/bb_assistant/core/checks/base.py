"""Shared types for passive checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from bb_assistant.core.http_client import SafeHttpClient


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INFO = "info"
    ERROR = "error"


class SafetyCategory(StrEnum):
    PASSIVE = "passive"
    MANUAL = "manual"
    ACTIVE_OPTIONAL = "active_optional"


@dataclass(frozen=True)
class CheckResult:
    check_name: str
    status: CheckStatus
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    affected_url: str | None = None
    severity_hint: str | None = None
    needs_manual_review: bool = False


class BaseCheck(Protocol):
    name: str
    safety_category: SafetyCategory

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        """Run a passive check for the given target URL."""

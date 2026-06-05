"""Runner for passive checks only."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, SafetyCategory
from bb_assistant.core.checks.cookies import CookieFlagsCheck
from bb_assistant.core.checks.cors import CorsHeadersCheck
from bb_assistant.core.checks.csp import ContentSecurityPolicyCheck
from bb_assistant.core.checks.robots_txt import RobotsTxtCheck
from bb_assistant.core.checks.security_headers import SecurityHeadersCheck
from bb_assistant.core.checks.security_txt import SecurityTxtCheck
from bb_assistant.core.checks.tls_basics import TLSBasicsCheck
from bb_assistant.core.http_client import SafeHttpClient

PASSIVE_CHECKS = (
    TLSBasicsCheck(),
    SecurityHeadersCheck(),
    CorsHeadersCheck(),
    ContentSecurityPolicyCheck(),
    CookieFlagsCheck(),
    SecurityTxtCheck(),
    RobotsTxtCheck(),
)


def run_passive_checks(target_url: str, client: SafeHttpClient) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in PASSIVE_CHECKS:
        if check.safety_category != SafetyCategory.PASSIVE:
            continue
        results.append(check.run(target_url, client))
    return results

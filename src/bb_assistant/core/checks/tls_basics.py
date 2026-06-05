"""MVP passive TLS basics check."""

from __future__ import annotations

from urllib.parse import urlparse

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.http_client import SafeHttpClient


class TLSBasicsCheck:
    name = "tls_basics"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        del client
        scheme = urlparse(target_url).scheme.lower()
        is_https = scheme == "https"
        details = {
            "scheme": scheme,
            "is_https": is_https,
        }

        if is_https:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.PASS,
                summary="Target URL uses HTTPS",
                details=details,
                affected_url=target_url,
                needs_manual_review=False,
            )

        return CheckResult(
            check_name=self.name,
            status=CheckStatus.FAIL,
            summary="Target URL does not use HTTPS",
            details=details,
            affected_url=target_url,
            severity_hint="medium",
            needs_manual_review=True,
        )

"""Passive security header presence check."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.http_client import SafeHttpClient

REQUIRED_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


class SecurityHeadersCheck:
    name = "security_headers"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        response = client.head(target_url, check_type=self.name)
        present_headers = [
            header for header in REQUIRED_SECURITY_HEADERS if header.lower() in response.headers
        ]
        missing_headers = [
            header for header in REQUIRED_SECURITY_HEADERS if header not in present_headers
        ]
        observed_headers = {
            header: response.headers.get(header)
            for header in present_headers
            if response.headers.get(header) is not None
        }

        if not missing_headers:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.PASS,
                summary="All expected security headers observed",
                details={
                    "present_headers": present_headers,
                    "missing_headers": [],
                    "observed_headers": observed_headers,
                },
                affected_url=str(response.url),
                needs_manual_review=False,
            )

        return CheckResult(
            check_name=self.name,
            status=CheckStatus.INFO,
            summary=f"Missing security headers: {', '.join(missing_headers)}",
            details={
                "present_headers": present_headers,
                "missing_headers": missing_headers,
                "observed_headers": observed_headers,
            },
            affected_url=str(response.url),
            severity_hint="low",
            needs_manual_review=True,
        )

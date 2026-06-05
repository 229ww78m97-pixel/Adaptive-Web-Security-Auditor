"""Passive check for /robots.txt."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.checks.url_utils import origin_url
from bb_assistant.core.http_client import SafeHttpClient


class RobotsTxtCheck:
    name = "robots_txt"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        url_checked = f"{origin_url(target_url)}/robots.txt"
        response = client.get(url_checked, check_type=self.name)
        details = {
            "status_code": response.status_code,
            "url_checked": url_checked,
        }

        if response.status_code == 200:
            details["disallow_count"] = _count_disallow_lines(response.text)
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.INFO,
                summary="robots.txt found",
                details=details,
                affected_url=url_checked,
                needs_manual_review=False,
            )

        if response.status_code == 404:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.INFO,
                summary="robots.txt not found",
                details=details,
                affected_url=url_checked,
                needs_manual_review=False,
            )

        return CheckResult(
            check_name=self.name,
            status=CheckStatus.INFO,
            summary=f"robots.txt returned status {response.status_code}",
            details=details,
            affected_url=url_checked,
            needs_manual_review=True,
        )


def _count_disallow_lines(body: str) -> int:
    return sum(1 for line in body.splitlines() if line.strip().lower().startswith("disallow:"))

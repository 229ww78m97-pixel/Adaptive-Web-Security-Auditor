"""Passive check for /.well-known/security.txt."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.checks.url_utils import origin_url
from bb_assistant.core.http_client import SafeHttpClient


class SecurityTxtCheck:
    name = "security_txt"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        url_checked = f"{origin_url(target_url)}/.well-known/security.txt"
        response = client.get(url_checked, check_type=self.name)
        details: dict[str, object] = {
            "status_code": response.status_code,
            "url_checked": url_checked,
        }
        content_type = response.headers.get("Content-Type")
        if content_type:
            details["content_type"] = content_type

        contacts = _extract_contacts(response.text) if response.status_code == 200 else []
        if contacts:
            details["contacts_found"] = contacts

        if response.status_code == 200:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.PASS,
                summary="security.txt found",
                details=details,
                affected_url=url_checked,
                needs_manual_review=False,
            )

        if response.status_code == 404:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.INFO,
                summary="security.txt not found",
                details=details,
                affected_url=url_checked,
                needs_manual_review=False,
            )

        return CheckResult(
            check_name=self.name,
            status=CheckStatus.INFO,
            summary=f"security.txt returned status {response.status_code}",
            details=details,
            affected_url=url_checked,
            needs_manual_review=True,
        )


def _extract_contacts(body: str) -> list[str]:
    contacts: list[str] = []
    for line in body.splitlines():
        if line.lower().startswith("contact:"):
            contacts.append(line.split(":", 1)[1].strip())
    return contacts

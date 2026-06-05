"""Passive CORS response header observation."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.http_client import SafeHttpClient

CORS_HEADERS = (
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Vary",
)
PASSIVE_CORS_NOTE = (
    "Passive CORS observation only. No origin reflection or bypass testing was performed."
)


class CorsHeadersCheck:
    name = "cors_headers"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        response = client.head(target_url, check_type=self.name)
        observed_headers = {
            header: response.headers.get(header)
            for header in CORS_HEADERS
            if response.headers.get(header) is not None
        }
        issues: list[str] = []
        notes = [PASSIVE_CORS_NOTE]

        acao = response.headers.get("Access-Control-Allow-Origin")
        credentials = response.headers.get("Access-Control-Allow-Credentials")
        vary = response.headers.get("Vary")

        if acao is None:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.INFO,
                summary="No CORS headers observed",
                details={
                    "observed_headers": observed_headers,
                    "issues": [],
                    "notes": notes,
                    "passive_only": True,
                },
                affected_url=str(response.url),
                needs_manual_review=False,
            )

        if acao.strip() == "*":
            issues.append("Access-Control-Allow-Origin allows any origin")
            if credentials and credentials.lower().strip() == "true":
                issues.append("Access-Control-Allow-Origin '*' is combined with credentials=true")
                return _cors_result(
                    response_url=str(response.url),
                    observed_headers=observed_headers,
                    issues=issues,
                    notes=notes,
                    status=CheckStatus.INFO,
                    severity_hint="medium",
                    needs_manual_review=True,
                    summary=(
                        "CORS allows wildcard origin with credentials; manual review required"
                    ),
                )

            return _cors_result(
                response_url=str(response.url),
                observed_headers=observed_headers,
                issues=issues,
                notes=notes,
                status=CheckStatus.INFO,
                severity_hint="low",
                needs_manual_review=True,
                summary="CORS allows wildcard origin without credentials",
            )

        if vary is None or "origin" not in {part.strip().lower() for part in vary.split(",")}:
            issues.append("Specific Access-Control-Allow-Origin observed without Vary: Origin")
            return _cors_result(
                response_url=str(response.url),
                observed_headers=observed_headers,
                issues=issues,
                notes=notes,
                status=CheckStatus.INFO,
                severity_hint="low",
                needs_manual_review=True,
                summary="Specific CORS origin observed without Vary: Origin",
            )

        return _cors_result(
            response_url=str(response.url),
            observed_headers=observed_headers,
            issues=issues,
            notes=notes,
            status=CheckStatus.PASS,
            severity_hint=None,
            needs_manual_review=False,
            summary="CORS headers observed without obvious passive issues",
        )


def _cors_result(
    *,
    response_url: str,
    observed_headers: dict[str, str | None],
    issues: list[str],
    notes: list[str],
    status: CheckStatus,
    severity_hint: str | None,
    needs_manual_review: bool,
    summary: str,
) -> CheckResult:
    return CheckResult(
        check_name=CorsHeadersCheck.name,
        status=status,
        summary=summary,
        details={
            "observed_headers": observed_headers,
            "issues": issues,
            "notes": notes,
            "passive_only": True,
        },
        affected_url=response_url,
        severity_hint=severity_hint,
        needs_manual_review=needs_manual_review,
    )

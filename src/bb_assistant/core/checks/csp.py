"""Passive Content-Security-Policy header analyzer."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.http_client import SafeHttpClient

PASSIVE_CSP_NOTE = "Passive CSP observation only. No CSP bypass or payload testing was performed."
RECOMMENDED_DIRECTIVES = ("default-src", "object-src", "base-uri", "frame-ancestors")


class ContentSecurityPolicyCheck:
    name = "content_security_policy"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        response = client.head(target_url, check_type=self.name)
        csp = response.headers.get("Content-Security-Policy")
        if csp is None:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.INFO,
                summary="Content-Security-Policy header not observed",
                details={
                    "directives": {},
                    "issues": ["Content-Security-Policy header is missing"],
                    "missing_recommended_directives": list(RECOMMENDED_DIRECTIVES),
                    "notes": [PASSIVE_CSP_NOTE],
                    "passive_only": True,
                },
                affected_url=str(response.url),
                severity_hint="low",
                needs_manual_review=True,
            )

        directives = parse_csp_directives(csp)
        issues = _csp_issues(directives)
        missing_recommended = [
            directive for directive in RECOMMENDED_DIRECTIVES if directive not in directives
        ]
        severity_hint = _severity_hint(issues)

        if not issues and not missing_recommended:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.PASS,
                summary="Content-Security-Policy baseline directives observed",
                details={
                    "directives": directives,
                    "issues": [],
                    "missing_recommended_directives": [],
                    "notes": [PASSIVE_CSP_NOTE],
                    "passive_only": True,
                },
                affected_url=str(response.url),
                needs_manual_review=False,
            )

        return CheckResult(
            check_name=self.name,
            status=CheckStatus.INFO,
            summary="Content-Security-Policy needs manual review",
            details={
                "directives": directives,
                "issues": issues,
                "missing_recommended_directives": missing_recommended,
                "notes": [PASSIVE_CSP_NOTE],
                "passive_only": True,
            },
            affected_url=str(response.url),
            severity_hint=severity_hint,
            needs_manual_review=True,
        )


def parse_csp_directives(header_value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_directive in header_value.split(";"):
        parts = raw_directive.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        directives[name] = parts[1:]
    return directives


def _csp_issues(directives: dict[str, list[str]]) -> list[str]:
    issues: list[str] = []
    script_src = directives.get("script-src", [])
    default_src = directives.get("default-src", [])
    all_sources = [source for sources in directives.values() for source in sources]

    if "default-src" not in directives:
        issues.append("default-src directive is missing")
    if "'unsafe-inline'" in script_src:
        issues.append("script-src contains 'unsafe-inline'")
    if "'unsafe-eval'" in script_src:
        issues.append("script-src contains 'unsafe-eval'")
    if "*" in all_sources:
        issues.append("CSP contains wildcard source '*'")
    object_src = directives.get("object-src")
    if object_src != ["'none'"]:
        issues.append("object-src is missing or not set to 'none'")
    if "base-uri" not in directives:
        issues.append("base-uri directive is missing")
    if "frame-ancestors" not in directives:
        issues.append("frame-ancestors directive is missing")
    if "'unsafe-inline'" in default_src:
        issues.append("default-src contains 'unsafe-inline'")
    if "'unsafe-eval'" in default_src:
        issues.append("default-src contains 'unsafe-eval'")
    return issues


def _severity_hint(issues: list[str]) -> str:
    medium_markers = ("'unsafe-eval'", "wildcard source", "default-src contains")
    if any(any(marker in issue for marker in medium_markers) for issue in issues):
        return "medium"
    return "low"

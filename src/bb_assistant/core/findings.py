"""Finding workflow helpers for human-in-the-loop review."""

from __future__ import annotations

import json
from typing import Any, Protocol, cast

from pydantic import AnyHttpUrl

from bb_assistant.core.checks.base import CheckResult, CheckStatus
from bb_assistant.core.models import Finding, FindingStatus, Severity


class FindingDraftNotAllowedError(ValueError):
    """Raised when a check result should not become a finding draft."""


class FindingVerificationError(ValueError):
    """Raised when a finding verification request is not explicit enough."""


class ReportableCandidate(Protocol):
    human_verified: bool


def create_finding_draft_from_check_result(
    check_result: CheckResult,
    program_id: str,
    target_id: str,
    affected_url: str,
) -> Finding:
    """Create a manual-review finding draft from a passive check result."""

    if check_result.status == CheckStatus.PASS:
        raise FindingDraftNotAllowedError("Passing check results cannot create finding drafts")
    if not check_result.needs_manual_review:
        raise FindingDraftNotAllowedError(
            "Only check results that need manual review can create finding drafts"
        )

    return Finding(
        program_id=program_id,
        target_id=target_id,
        title=_draft_title(check_result),
        severity=_severity_from_hint(check_result.severity_hint),
        finding_type=check_result.check_name,
        description=_draft_description(check_result),
        steps_to_reproduce=_draft_steps(affected_url, check_result),
        impact=_draft_impact(check_result),
        recommendation=_draft_recommendation(check_result),
        affected_url=cast(AnyHttpUrl, affected_url),
        status=FindingStatus.DRAFT,
        human_verified=False,
    )


def verify_finding(
    finding: Finding,
    *,
    human_confirmed: bool,
    status: FindingStatus = FindingStatus.READY,
) -> Finding:
    """Mark a finding as human verified after explicit confirmation."""

    if not human_confirmed:
        raise FindingVerificationError("Finding verification requires explicit human confirmation")
    if status == FindingStatus.DRAFT:
        raise FindingVerificationError("Verified findings must move out of draft status")

    return finding.model_copy(update={"human_verified": True, "status": status})


def is_reportable(finding: ReportableCandidate) -> bool:
    return bool(finding.human_verified)


def _draft_title(check_result: CheckResult) -> str:
    readable_check_name = check_result.check_name.replace("_", " ").title()
    return f"Manual review needed: {readable_check_name}"


def _severity_from_hint(severity_hint: str | None) -> Severity:
    if severity_hint is None:
        return Severity.INFO
    normalized = severity_hint.lower().strip()
    for severity in Severity:
        if severity.value == normalized:
            return severity
    return Severity.INFO


def _draft_description(check_result: CheckResult) -> str:
    details = _details_as_markdown(check_result.details)
    return (
        f"A passive check produced a result that requires human review.\n\n"
        f"Check summary: {check_result.summary}\n\n"
        f"Check details:\n\n{details}"
    )


def _draft_steps(affected_url: str, check_result: CheckResult) -> str:
    return (
        f"1. Confirm the target is authorized and in scope.\n"
        f"2. Send a safe GET or HEAD request to `{affected_url}`.\n"
        f"3. Manually verify the observation from `{check_result.check_name}`.\n"
        f"4. Decide whether the behavior is reportable under the program policy."
    )


def _draft_impact(check_result: CheckResult) -> str:
    severity = check_result.severity_hint or "informational"
    return (
        f"Potential impact is currently a {severity} hint from a passive check. "
        "A human reviewer must validate real-world impact before reporting."
    )


def _draft_recommendation(check_result: CheckResult) -> str:
    return (
        "Manually validate the observation, confirm applicability to the target, "
        f"and document evidence before changing this draft from `{check_result.status}` "
        "to a verified finding."
    )


def _details_as_markdown(details: dict[str, Any]) -> str:
    if not details:
        return "- No structured details were provided."
    rendered = json.dumps(details, indent=2, sort_keys=True, default=str)
    return f"```json\n{rendered}\n```"

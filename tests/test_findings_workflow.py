from __future__ import annotations

import pytest

from bb_assistant.core.checks.base import CheckResult, CheckStatus
from bb_assistant.core.findings import (
    FindingDraftNotAllowedError,
    FindingVerificationError,
    create_finding_draft_from_check_result,
    is_reportable,
    verify_finding,
)
from bb_assistant.core.models import FindingStatus, Severity


def reviewable_check_result(
    *,
    status: CheckStatus = CheckStatus.INFO,
    severity_hint: str | None = "low",
    needs_manual_review: bool = True,
) -> CheckResult:
    return CheckResult(
        check_name="security_headers",
        status=status,
        summary="Missing security headers: Content-Security-Policy",
        details={
            "missing_headers": ["Content-Security-Policy"],
            "present_headers": ["Strict-Transport-Security"],
        },
        affected_url="https://example.com",
        severity_hint=severity_hint,
        needs_manual_review=needs_manual_review,
    )


def make_draft():
    return create_finding_draft_from_check_result(
        reviewable_check_result(),
        program_id="program-1",
        target_id="target-1",
        affected_url="https://example.com",
    )


def test_create_finding_draft_from_manual_review_check_result() -> None:
    finding = make_draft()

    assert finding.program_id == "program-1"
    assert finding.target_id == "target-1"
    assert finding.title == "Manual review needed: Security Headers"
    assert finding.severity == Severity.LOW
    assert finding.finding_type == "security_headers"
    assert str(finding.affected_url) == "https://example.com/"
    assert finding.status == FindingStatus.DRAFT
    assert finding.human_verified is False
    assert "Content-Security-Policy" in finding.description
    assert "human reviewer must validate" in finding.impact


def test_create_finding_draft_does_not_make_result_reportable() -> None:
    finding = make_draft()

    assert is_reportable(finding) is False


def test_passing_check_result_cannot_create_finding_draft() -> None:
    check_result = reviewable_check_result(status=CheckStatus.PASS)

    with pytest.raises(FindingDraftNotAllowedError, match="Passing check results"):
        create_finding_draft_from_check_result(
            check_result,
            program_id="program-1",
            target_id="target-1",
            affected_url="https://example.com",
        )


def test_check_result_without_manual_review_cannot_create_finding_draft() -> None:
    check_result = reviewable_check_result(needs_manual_review=False)

    with pytest.raises(FindingDraftNotAllowedError, match="need manual review"):
        create_finding_draft_from_check_result(
            check_result,
            program_id="program-1",
            target_id="target-1",
            affected_url="https://example.com",
        )


def test_unknown_severity_hint_defaults_to_info() -> None:
    finding = create_finding_draft_from_check_result(
        reviewable_check_result(severity_hint="unexpected"),
        program_id="program-1",
        target_id="target-1",
        affected_url="https://example.com",
    )

    assert finding.severity == Severity.INFO


def test_verify_finding_requires_explicit_human_confirmation() -> None:
    finding = make_draft()

    with pytest.raises(FindingVerificationError, match="explicit human confirmation"):
        verify_finding(finding, human_confirmed=False)


def test_verify_finding_marks_finding_reportable() -> None:
    finding = make_draft()

    verified = verify_finding(finding, human_confirmed=True)

    assert finding.human_verified is False
    assert finding.status == FindingStatus.DRAFT
    assert verified.human_verified is True
    assert verified.status == FindingStatus.READY
    assert is_reportable(verified) is True


def test_verified_finding_cannot_remain_draft_status() -> None:
    finding = make_draft()

    with pytest.raises(FindingVerificationError, match="move out of draft"):
        verify_finding(
            finding,
            human_confirmed=True,
            status=FindingStatus.DRAFT,
        )

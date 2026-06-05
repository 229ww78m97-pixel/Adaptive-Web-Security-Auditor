from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus
from bb_assistant.core.models import FindingStatus, Severity
from bb_assistant.interfaces.ui_helpers import (
    check_result_from_orm,
    check_result_to_orm,
    finding_to_orm,
    scope_rules_from_orm,
    verify_finding_orm,
)
from bb_assistant.persistence.models import ScopeRuleORM


def test_check_result_round_trip_preserves_manual_review_metadata() -> None:
    result = CheckResult(
        check_name="security_headers",
        status=CheckStatus.INFO,
        summary="Missing security headers: Content-Security-Policy",
        details={"missing_headers": ["Content-Security-Policy"]},
        affected_url="https://example.com",
        severity_hint="low",
        needs_manual_review=True,
    )

    stored = check_result_to_orm(result, target_id="target-1")
    restored = check_result_from_orm(stored)

    assert stored.target_id == "target-1"
    assert restored.check_name == result.check_name
    assert restored.status == result.status
    assert restored.details == result.details
    assert restored.affected_url == result.affected_url
    assert restored.severity_hint == result.severity_hint
    assert restored.needs_manual_review is True


def test_scope_rules_from_orm_converts_to_core_scope_rules() -> None:
    stored = [
        ScopeRuleORM(
            id="scope-1",
            program_id="program-1",
            asset_type="domain",
            value="example.com",
            in_scope=True,
        )
    ]

    converted = scope_rules_from_orm(stored)

    assert converted[0].id == "scope-1"
    assert converted[0].value == "example.com"
    assert converted[0].asset_type.value == "domain"
    assert converted[0].in_scope is True


def test_finding_to_orm_keeps_draft_unverified() -> None:
    from bb_assistant.core.models import Finding

    finding = Finding(
        id="finding-1",
        program_id="program-1",
        target_id="target-1",
        title="Manual review needed",
        severity=Severity.LOW,
        finding_type="security_headers",
        description="Draft description",
        steps_to_reproduce="Manual steps",
        impact="Needs validation",
        recommendation="Validate manually",
        affected_url="https://example.com",
        status=FindingStatus.DRAFT,
        human_verified=False,
    )

    stored = finding_to_orm(finding)

    assert stored.id == "finding-1"
    assert stored.status == "draft"
    assert stored.human_verified is False


def test_verify_finding_orm_marks_ready_and_keeps_manual_note() -> None:
    from bb_assistant.persistence.models import FindingORM

    finding = FindingORM(
        program_id="program-1",
        target_id="target-1",
        title="Manual review needed",
        severity="low",
        finding_type="security_headers",
        description="Draft description",
        steps_to_reproduce="Manual steps",
        impact="Needs validation",
        recommendation="Validate manually",
        affected_url="https://example.com",
        status="draft",
        human_verified=False,
    )

    verified = verify_finding_orm(
        finding,
        verified_by="researcher",
        verification_note="Confirmed with response evidence.",
    )

    assert verified.human_verified is True
    assert verified.status == "ready"
    assert "researcher" in verified.description
    assert "Confirmed with response evidence." in verified.description

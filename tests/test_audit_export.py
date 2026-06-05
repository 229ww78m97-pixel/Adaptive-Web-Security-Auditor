from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from bb_assistant.core.audit import AuditExportError, AuditTrailExporter
from bb_assistant.core.evidence import create_evidence_note
from bb_assistant.persistence.db import create_engine_for_url, create_session_factory, init_db
from bb_assistant.persistence.models import (
    AuthorizationORM,
    CheckResultORM,
    EvidenceORM,
    FindingORM,
    ProgramORM,
    ReportORM,
    RequestLogORM,
    ScopeRuleORM,
    TargetORM,
)
from bb_assistant.persistence.repositories import (
    AuthorizationRepository,
    CheckResultRepository,
    EvidenceRepository,
    FindingRepository,
    ProgramRepository,
    ReportRepository,
    RequestLogRepository,
    ScopeRepository,
    TargetRepository,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine_for_url("sqlite+pysqlite:///:memory:")
    init_db(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as db_session:
        yield db_session
    engine.dispose()


@pytest.fixture
def exporter(session: Session) -> AuditTrailExporter:
    return AuditTrailExporter(
        program_repository=ProgramRepository(session),
        authorization_repository=AuthorizationRepository(session),
        scope_repository=ScopeRepository(session),
        target_repository=TargetRepository(session),
        request_log_repository=RequestLogRepository(session),
        check_result_repository=CheckResultRepository(session),
        finding_repository=FindingRepository(session),
        evidence_repository=EvidenceRepository(session),
        report_repository=ReportRepository(session),
    )


def seed_audit_records(session: Session) -> tuple[ProgramORM, TargetORM, FindingORM]:
    program = ProgramRepository(session).create(
        ProgramORM(
            name="Example Program",
            platform="HackerOne",
            policy_url="https://example.test/policy?token=policy-secret",
            identification_header_name="X-Bug-Bounty-Contact",
            identification_header_value="researcher@example.test",
        )
    )
    ScopeRepository(session).create(
        ScopeRuleORM(
            program_id=program.id,
            asset_type="domain",
            value="example.test",
            in_scope=True,
            notes="Authorization: Bearer scope-secret",
        )
    )
    AuthorizationRepository(session).create(
        AuthorizationORM(
            program_id=program.id,
            confirmed_by="researcher@example.test",
            authorization_text=(
                "Authorization: Bearer auth-secret\n"
                "Cookie: sessionid=cookie-secret\n"
                "Approved passive checks only."
            ),
        )
    )
    target = TargetRepository(session).create(
        TargetORM(
            program_id=program.id,
            base_url="https://example.test?access_token=target-secret",
            host="example.test",
            notes="password=target-password",
        )
    )
    RequestLogRepository(session).create(
        RequestLogORM(
            program_id=program.id,
            target_id=target.id,
            method="GET",
            url="https://example.test/path?token=request-secret",
            check_type="security_headers",
            in_scope_validated=True,
            response_status=200,
            response_size=123,
            identifying_header="X-Bug-Bounty-Contact: researcher@example.test",
            notes="secret=request-note-secret",
        )
    )
    CheckResultRepository(session).create(
        CheckResultORM(
            target_id=target.id,
            check_name="security_headers",
            status="info",
            summary="Observed headers for researcher@example.test",
            details_json='{"token": "check-token", "password": "check-password"}',
        )
    )
    finding = FindingRepository(session).create(
        FindingORM(
            program_id=program.id,
            target_id=target.id,
            title="Missing Content-Security-Policy",
            severity="low",
            finding_type="security_headers",
            description="Manual note contains password=hunter2",
            steps_to_reproduce="Send a safe GET request.",
            impact="Defense-in-depth is reduced.",
            recommendation="Set a suitable CSP.",
            affected_url="https://example.test?session=finding-session",
            human_verified=True,
        )
    )
    evidence = create_evidence_note(
        finding_id=finding.id,
        text=(
            "Authorization: Bearer evidence-secret\n"
            "Cookie: sessionid=evidence-cookie\n"
            "api_key=evidence-api-key"
        ),
        caption="Evidence from researcher@example.test",
    )
    EvidenceRepository(session).create(
        EvidenceORM(
            finding_id=evidence.finding_id,
            type=evidence.type,
            content_text=evidence.content_text,
            caption=evidence.caption,
            sha256=evidence.sha256,
        )
    )
    ReportRepository(session).create(
        ReportORM(
            finding_id=finding.id,
            title="Technical report for researcher@example.test",
            content_path="/tmp/report.md",
            content_md="# Report\naccess_token=report-token\nsecret: report-secret",
        )
    )
    return program, target, finding


def test_program_audit_json_contains_redacted_audit_sections(
    session: Session,
    exporter: AuditTrailExporter,
) -> None:
    program, _, _ = seed_audit_records(session)

    payload = exporter.build_program_audit_json(program.id)

    assert payload["export_type"] == "program_audit_trail"
    assert payload["program"]["name"] == "Example Program"
    assert payload["program"]["identification_header_value"] == "[REDACTED]"
    assert len(payload["scope_rules"]) == 1
    assert len(payload["authorizations"]) == 1
    assert len(payload["targets"]) == 1
    assert len(payload["request_logs"]) == 1
    assert len(payload["check_results"]) == 1
    assert len(payload["findings"]) == 1
    assert len(payload["evidence"]) == 1
    assert len(payload["reports"]) == 1


def test_program_audit_json_does_not_export_sensitive_values(
    session: Session,
    exporter: AuditTrailExporter,
) -> None:
    program, _, _ = seed_audit_records(session)

    serialized = json.dumps(exporter.build_program_audit_json(program.id))

    assert "policy-secret" not in serialized
    assert "researcher@example.test" not in serialized
    assert "auth-secret" not in serialized
    assert "cookie-secret" not in serialized
    assert "request-secret" not in serialized
    assert "hunter2" not in serialized
    assert "check-token" not in serialized
    assert "check-password" not in serialized
    assert "evidence-secret" not in serialized
    assert "evidence-cookie" not in serialized
    assert "report-token" not in serialized
    assert "report-secret" not in serialized
    assert "[REDACTED]" in serialized


def test_request_logs_keep_safe_metadata(session: Session, exporter: AuditTrailExporter) -> None:
    program, _, _ = seed_audit_records(session)

    request_log = exporter.build_program_audit_json(program.id)["request_logs"][0]

    assert request_log["method"] == "GET"
    assert request_log["response_status"] == 200
    assert request_log["response_size"] == 123
    assert request_log["in_scope_validated"] is True
    assert request_log["identifying_header"] == "X-Bug-Bounty-Contact: [REDACTED]"


def test_program_audit_markdown_contains_redacted_sections(
    session: Session,
    exporter: AuditTrailExporter,
) -> None:
    program, _, _ = seed_audit_records(session)

    markdown = exporter.build_program_audit_markdown(program.id)

    assert "# Audit Trail: Example Program" in markdown
    assert "## Scope Rules" in markdown
    assert "## Request Logs" in markdown
    assert "## Evidence" in markdown
    assert "Missing Content-Security-Policy" in markdown
    assert "auth-secret" not in markdown
    assert "[REDACTED]" in markdown


def test_target_audit_json_filters_to_selected_target(
    session: Session,
    exporter: AuditTrailExporter,
) -> None:
    program, target, finding = seed_audit_records(session)
    other_target = TargetRepository(session).create(
        TargetORM(
            program_id=program.id,
            base_url="https://other.example.test",
            host="other.example.test",
        )
    )
    FindingRepository(session).create(
        FindingORM(
            program_id=program.id,
            target_id=other_target.id,
            title="Other finding",
            severity="info",
            finding_type="documentation",
            description="Only documentation.",
            steps_to_reproduce="n/a",
            impact="n/a",
            recommendation="n/a",
            affected_url="https://other.example.test",
            human_verified=False,
        )
    )

    payload = exporter.build_target_audit_json(target.id)

    assert payload["export_type"] == "target_audit_trail"
    assert [record["id"] for record in payload["targets"]] == [target.id]
    assert [record["id"] for record in payload["findings"]] == [finding.id]


def test_missing_program_raises_clear_error(exporter: AuditTrailExporter) -> None:
    with pytest.raises(AuditExportError, match="Program 'missing-program' was not found"):
        exporter.build_program_audit_json("missing-program")


def test_missing_target_raises_clear_error(exporter: AuditTrailExporter) -> None:
    with pytest.raises(AuditExportError, match="Target 'missing-target' was not found"):
        exporter.build_target_audit_json("missing-target")


def test_export_markdown_and_json_write_files(
    session: Session,
    exporter: AuditTrailExporter,
    tmp_path: Path,
) -> None:
    program, _, _ = seed_audit_records(session)
    payload = exporter.build_program_audit_json(program.id)
    markdown = exporter.build_program_audit_markdown(program.id)

    markdown_path = exporter.export_markdown(markdown, tmp_path / "audit" / "trail.md")
    json_path = exporter.export_json(payload, tmp_path / "audit" / "trail.json")

    assert markdown_path.read_text(encoding="utf-8") == markdown
    assert json.loads(json_path.read_text(encoding="utf-8"))["program"]["id"] == program.id


def test_audit_export_does_not_create_findings(
    session: Session,
    exporter: AuditTrailExporter,
) -> None:
    program, _, _ = seed_audit_records(session)
    repository = FindingRepository(session)
    before = len(repository.list_for_program(program.id))

    exporter.build_program_audit_json(program.id)
    exporter.build_program_audit_markdown(program.id)

    assert len(repository.list_for_program(program.id)) == before

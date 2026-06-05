from __future__ import annotations

import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import Session

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
    FindingRepository,
    ProgramRepository,
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


def create_program(session: Session) -> ProgramORM:
    return ProgramRepository(session).create(
        ProgramORM(
            name="Example Program",
            platform="HackerOne",
            policy_url="https://example.com/policy",
            identification_header_name="X-Bug-Bounty-Contact",
            identification_header_value="researcher@example.test",
        )
    )


def create_target(session: Session, program: ProgramORM) -> TargetORM:
    return TargetRepository(session).create(
        TargetORM(
            program_id=program.id,
            base_url="https://example.com",
            host="example.com",
        )
    )


def make_finding(
    program: ProgramORM,
    target: TargetORM,
    *,
    human_verified: bool,
    title: str = "Missing security header",
) -> FindingORM:
    return FindingORM(
        program_id=program.id,
        target_id=target.id,
        title=title,
        severity="low",
        finding_type="security_headers",
        description="A passive check observed a missing header.",
        steps_to_reproduce="Send a GET request to the affected URL.",
        impact="Defense-in-depth control is absent.",
        recommendation="Set the missing header after manual validation.",
        affected_url="https://example.com",
        human_verified=human_verified,
    )


def test_database_can_be_initialized() -> None:
    engine = create_engine_for_url("sqlite+pysqlite:///:memory:")
    init_db(engine)

    table_names = set(inspect(engine).get_table_names())

    assert {
        "programs",
        "authorizations",
        "scopes",
        "targets",
        "scan_runs",
        "requests_log",
        "check_results",
        "findings",
        "evidence",
        "reports",
        "settings",
    }.issubset(table_names)
    engine.dispose()


def test_program_can_be_created_and_read(session: Session) -> None:
    program = create_program(session)
    repository = ProgramRepository(session)

    loaded = repository.get_by_id(program.id)

    assert loaded is not None
    assert loaded.name == "Example Program"
    assert repository.list_all() == [program]


def test_scope_rules_can_be_associated_with_program(session: Session) -> None:
    program = create_program(session)
    repository = ScopeRepository(session)

    scope = repository.create(
        ScopeRuleORM(
            program_id=program.id,
            asset_type="domain",
            value="example.com",
            in_scope=True,
        )
    )

    assert repository.list_for_program(program.id) == [scope]
    assert program.scopes == [scope]


def test_target_can_be_associated_with_program(session: Session) -> None:
    program = create_program(session)
    target = create_target(session, program)

    targets = TargetRepository(session).list_for_program(program.id)

    assert targets == [target]
    assert program.targets == [target]


def test_active_authorization_can_be_loaded_for_program(session: Session) -> None:
    program = create_program(session)
    repository = AuthorizationRepository(session)
    repository.create(
        AuthorizationORM(
            program_id=program.id,
            confirmed_by="researcher",
            authorization_text="I confirm the target is in scope.",
            active=False,
        )
    )
    active = repository.create(
        AuthorizationORM(
            program_id=program.id,
            confirmed_by="researcher",
            authorization_text="I confirm active authorization.",
            active=True,
        )
    )

    assert repository.get_active_for_program(program.id) == active


def test_request_log_can_be_saved(session: Session) -> None:
    program = create_program(session)
    target = create_target(session, program)
    repository = RequestLogRepository(session)

    log = repository.create(
        RequestLogORM(
            program_id=program.id,
            target_id=target.id,
            method="GET",
            url="https://example.com",
            check_type="security_headers",
            in_scope_validated=True,
            response_status=200,
            response_size=42,
            identifying_header="X-Bug-Bounty-Contact: researcher@example.test",
        )
    )

    assert repository.list_for_program(program.id) == [log]
    assert target.request_logs == [log]


def test_check_result_can_be_saved(session: Session) -> None:
    program = create_program(session)
    target = create_target(session, program)
    repository = CheckResultRepository(session)

    result = repository.create(
        CheckResultORM(
            target_id=target.id,
            check_name="security_headers",
            status="info",
            summary="Header is absent.",
            details_json='{"missing": ["content-security-policy"]}',
        )
    )

    assert repository.list_for_target(target.id) == [result]
    assert target.check_results == [result]


def test_unverified_finding_is_not_reportable(session: Session) -> None:
    program = create_program(session)
    target = create_target(session, program)
    repository = FindingRepository(session)
    repository.create(make_finding(program, target, human_verified=False))

    assert repository.list_reportable_for_program(program.id) == []


def test_verified_finding_is_reportable(session: Session) -> None:
    program = create_program(session)
    target = create_target(session, program)
    repository = FindingRepository(session)
    finding = repository.create(make_finding(program, target, human_verified=True))

    assert repository.list_reportable_for_program(program.id) == [finding]


def test_relationships_work_for_findings_evidence_and_reports(session: Session) -> None:
    program = create_program(session)
    target = create_target(session, program)
    finding = FindingRepository(session).create(make_finding(program, target, human_verified=True))
    evidence = EvidenceORM(
        finding_id=finding.id,
        type="request_log",
        caption="Observed response metadata",
    )
    report = ReportORM(
        finding_id=finding.id,
        title="Technical report",
        content_md="# Technical report",
    )

    session.add_all([evidence, report])
    session.commit()
    session.refresh(finding)

    assert program.findings == [finding]
    assert target.findings == [finding]
    assert finding.evidence == [evidence]
    assert finding.reports == [report]

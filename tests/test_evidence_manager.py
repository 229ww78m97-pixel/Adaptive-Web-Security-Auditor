from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from bb_assistant.core.evidence import (
    EvidenceValidationError,
    calculate_sha256_for_text,
    create_evidence_from_request_log,
    create_evidence_note,
    sanitize_evidence_text,
)
from bb_assistant.core.models import Finding, FindingStatus, Severity
from bb_assistant.core.reporting import ReportGenerator
from bb_assistant.persistence.db import create_engine_for_url, create_session_factory, init_db
from bb_assistant.persistence.models import EvidenceORM, FindingORM, ProgramORM, TargetORM
from bb_assistant.persistence.repositories import (
    EvidenceRepository,
    FindingRepository,
    ProgramRepository,
    TargetRepository,
)


def test_empty_evidence_note_is_rejected() -> None:
    with pytest.raises(EvidenceValidationError, match="must not be empty"):
        create_evidence_note(finding_id="finding-1", text="   ")


def test_authorization_header_is_redacted() -> None:
    sanitized = sanitize_evidence_text("Authorization: Bearer abc123")

    assert sanitized == "Authorization: [REDACTED]"
    assert "abc123" not in sanitized


def test_cookie_headers_are_redacted() -> None:
    sanitized = sanitize_evidence_text("Cookie: sessionid=abc\nSet-Cookie: auth=secret; HttpOnly")

    assert "Cookie: [REDACTED]" in sanitized
    assert "Set-Cookie: [REDACTED]" in sanitized
    assert "sessionid=abc" not in sanitized
    assert "auth=secret" not in sanitized


def test_token_password_and_secret_values_are_redacted() -> None:
    sanitized = sanitize_evidence_text(
        "token=abc access_token=def refresh_token=ghi password=hunter2 "
        "secret=sauce api_key=key session=sid"
    )

    assert sanitized == (
        "token=[REDACTED] access_token=[REDACTED] refresh_token=[REDACTED] "
        "password=[REDACTED] secret=[REDACTED] api_key=[REDACTED] session=[REDACTED]"
    )


def test_jwt_like_tokens_are_redacted() -> None:
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    sanitized = sanitize_evidence_text(f"Observed token {token}")

    assert sanitized == "Observed token [REDACTED_JWT]"
    assert token not in sanitized


def test_sha256_is_deterministic() -> None:
    first = calculate_sha256_for_text("redacted evidence")
    second = calculate_sha256_for_text("redacted evidence")

    assert first == second
    assert len(first) == 64


def test_evidence_note_is_created_with_redacted_text_and_hash() -> None:
    evidence = create_evidence_note(
        finding_id="finding-1",
        text="password=hunter2\nObserved missing header",
        caption="Screenshot note",
    )

    assert evidence.type == "note"
    assert evidence.finding_id == "finding-1"
    assert evidence.content_text == "password=[REDACTED]\nObserved missing header"
    assert evidence.caption == "Screenshot note"
    assert evidence.sha256 == calculate_sha256_for_text(evidence.content_text)
    assert evidence.request_log_id is None


def test_evidence_from_request_log_sets_request_log_id() -> None:
    evidence = create_evidence_from_request_log(
        finding_id="finding-1",
        request_log_id="request-log-1",
        caption="GET metadata only",
    )

    assert evidence.type == "request_reference"
    assert evidence.finding_id == "finding-1"
    assert evidence.request_log_id == "request-log-1"
    assert evidence.content_text is None
    assert evidence.sha256 is None


@pytest.fixture
def session() -> Session:
    engine = create_engine_for_url("sqlite+pysqlite:///:memory:")
    init_db(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as db_session:
        yield db_session
    engine.dispose()


def create_persisted_finding(session: Session) -> FindingORM:
    program = ProgramRepository(session).create(
        ProgramORM(name="Example Program", platform="HackerOne")
    )
    target = TargetRepository(session).create(
        TargetORM(
            program_id=program.id,
            base_url="https://example.com",
            host="example.com",
        )
    )
    return FindingRepository(session).create(
        FindingORM(
            program_id=program.id,
            target_id=target.id,
            title="Missing Content-Security-Policy",
            severity="low",
            finding_type="security_headers",
            description="Missing header was manually reviewed.",
            steps_to_reproduce="Send a safe GET request and inspect headers.",
            impact="Defense-in-depth is reduced.",
            recommendation="Set a suitable policy.",
            affected_url="https://example.com",
            status="ready",
            human_verified=True,
        )
    )


def test_evidence_repository_saves_and_lists_evidence(session: Session) -> None:
    finding = create_persisted_finding(session)
    note = create_evidence_note(
        finding_id=finding.id,
        text="Authorization: Bearer abc123\nMissing CSP observed",
    )
    repository = EvidenceRepository(session)

    stored = repository.create(
        EvidenceORM(
            finding_id=note.finding_id,
            type=note.type,
            content_text=note.content_text,
            caption=note.caption,
            sha256=note.sha256,
            request_log_id=note.request_log_id,
            storage_path=note.storage_path,
        )
    )

    evidence = repository.list_for_finding(finding.id)
    assert evidence == [stored]
    assert evidence[0].content_text == "Authorization: [REDACTED]\nMissing CSP observed"
    assert evidence[0].sha256 == note.sha256


def test_report_generator_can_render_evidence_context() -> None:
    finding = Finding(
        program_id="program-1",
        target_id="target-1",
        title="Missing Content-Security-Policy",
        severity=Severity.LOW,
        finding_type="security_headers",
        description="Missing header was manually reviewed.",
        steps_to_reproduce="Send a safe GET request and inspect headers.",
        impact="Defense-in-depth is reduced.",
        recommendation="Set a suitable policy.",
        affected_url="https://example.com",
        status=FindingStatus.READY,
        human_verified=True,
    )
    evidence = create_evidence_note(
        finding_id=finding.id,
        text="Cookie: sessionid=abc\nMissing CSP observed",
    )
    generator = ReportGenerator("templates")

    report = generator.render_technical_report(
        finding,
        context={"evidence": evidence.content_text},
    )

    assert "Cookie: [REDACTED]" in report
    assert "sessionid=abc" not in report
    assert "Missing CSP observed" in report

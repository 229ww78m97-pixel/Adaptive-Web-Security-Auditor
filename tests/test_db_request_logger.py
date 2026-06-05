from __future__ import annotations

import httpx
import pytest
from sqlalchemy.orm import Session

from bb_assistant.core.http_client import LoggedRequest, SafeHttpClient
from bb_assistant.core.models import AssetType, ScopeRule
from bb_assistant.core.rate_limiter import RateLimiter
from bb_assistant.core.scope_guard import OutOfScopeError, ScopeGuard
from bb_assistant.persistence.db import create_engine_for_url, create_session_factory, init_db
from bb_assistant.persistence.logging import DBRequestLogger
from bb_assistant.persistence.models import ProgramORM, TargetORM
from bb_assistant.persistence.repositories import (
    ProgramRepository,
    RequestLogRepository,
    TargetRepository,
)


class NoSleepClock:
    def __init__(self) -> None:
        self.current = 0.0

    def now(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.current += seconds


@pytest.fixture
def session() -> Session:
    engine = create_engine_for_url("sqlite+pysqlite:///:memory:")
    init_db(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as db_session:
        yield db_session
    engine.dispose()


def create_program_and_target(session: Session) -> tuple[ProgramORM, TargetORM]:
    program = ProgramRepository(session).create(
        ProgramORM(
            name="Example Program",
            platform="HackerOne",
            policy_url="https://example.com/policy",
            identification_header_name="X-Bug-Bounty-Contact",
            identification_header_value="researcher@example.test",
        )
    )
    target = TargetRepository(session).create(
        TargetORM(
            program_id=program.id,
            base_url="https://example.com",
            host="example.com",
        )
    )
    return program, target


def scope_guard() -> ScopeGuard:
    return ScopeGuard(
        [
            ScopeRule(
                program_id="program-1",
                asset_type=AssetType.DOMAIN,
                value="example.com",
                in_scope=True,
            )
        ]
    )


def rate_limiter() -> RateLimiter:
    clock = NoSleepClock()
    return RateLimiter(100.0, clock=clock.now, sleeper=clock.sleep)


def test_db_request_logger_saves_successful_request_log(session: Session) -> None:
    program, target = create_program_and_target(session)
    logger = DBRequestLogger(session, program_id=program.id, target_id=target.id)

    logger.log(
        LoggedRequest(
            method="GET",
            url="https://example.com/",
            check_type="security_headers",
            in_scope_validated=True,
            response_status=200,
            response_size=42,
            identifying_header="X-Bug-Bounty-Contact: researcher@example.test",
            notes="Safe passive request",
        )
    )

    logs = RequestLogRepository(session).list_for_program(program.id)

    assert len(logs) == 1
    assert logs[0].program_id == program.id
    assert logs[0].target_id == target.id
    assert logs[0].method == "GET"
    assert logs[0].url == "https://example.com/"
    assert logs[0].check_type == "security_headers"
    assert logs[0].in_scope_validated is True
    assert logs[0].response_status == 200
    assert logs[0].response_size == 42
    assert logs[0].identifying_header == "X-Bug-Bounty-Contact: researcher@example.test"
    assert logs[0].notes == "Safe passive request"
    assert logs[0].timestamp_utc is not None


def test_safe_http_client_can_use_db_request_logger(session: Session) -> None:
    program, target = create_program_and_target(session)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello")

    client = SafeHttpClient(
        scope_guard=scope_guard(),
        rate_limiter=rate_limiter(),
        request_logger=DBRequestLogger(session, program_id=program.id, target_id=target.id),
        transport=httpx.MockTransport(handler),
    )

    response = client.get("https://example.com/", check_type="security_txt")

    logs = RequestLogRepository(session).list_for_program(program.id)
    assert response.status_code == 200
    assert len(logs) == 1
    assert logs[0].url == "https://example.com/"
    assert logs[0].check_type == "security_txt"
    assert logs[0].response_size == 5


def test_oos_blocked_request_is_not_logged_as_sent_request(session: Session) -> None:
    program, target = create_program_and_target(session)
    sent_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        return httpx.Response(200)

    client = SafeHttpClient(
        scope_guard=scope_guard(),
        rate_limiter=rate_limiter(),
        request_logger=DBRequestLogger(session, program_id=program.id, target_id=target.id),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(OutOfScopeError):
        client.get("https://evil.com/", check_type="security_headers")

    assert sent_urls == []
    assert RequestLogRepository(session).list_for_program(program.id) == []


def test_db_request_logger_redacts_sensitive_notes(session: Session) -> None:
    program, target = create_program_and_target(session)
    logger = DBRequestLogger(session, program_id=program.id, target_id=target.id)

    logger.log(
        LoggedRequest(
            method="GET",
            url="https://example.com/",
            check_type="manual",
            in_scope_validated=True,
            response_status=200,
            response_size=0,
            identifying_header=None,
            notes=(
                "Cookie: sessionid=super-secret-cookie\n"
                "Authorization: Bearer secret-token\n"
                "Safe note"
            ),
        )
    )

    logs = RequestLogRepository(session).list_for_program(program.id)

    assert len(logs) == 1
    assert "super-secret-cookie" not in str(logs[0].notes)
    assert "secret-token" not in str(logs[0].notes)
    assert "Cookie: [REDACTED]" in str(logs[0].notes)
    assert "Authorization: [REDACTED]" in str(logs[0].notes)
    assert "Safe note" in str(logs[0].notes)


def test_streamlit_safe_client_builder_uses_db_request_logger(session: Session) -> None:
    from bb_assistant.interfaces.streamlit_app import build_safe_client

    program, target = create_program_and_target(session)
    client = build_safe_client(session, program, target)

    assert isinstance(client._request_logger, DBRequestLogger)

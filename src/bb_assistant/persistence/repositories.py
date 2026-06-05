"""Small repository classes for local persistence operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

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


class ProgramRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, program: ProgramORM) -> ProgramORM:
        self._session.add(program)
        self._session.commit()
        self._session.refresh(program)
        return program

    def get_by_id(self, program_id: str) -> ProgramORM | None:
        return self._session.get(ProgramORM, program_id)

    def list_all(self) -> list[ProgramORM]:
        return list(self._session.scalars(select(ProgramORM).order_by(ProgramORM.created_at)))


class ScopeRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, scope: ScopeRuleORM) -> ScopeRuleORM:
        self._session.add(scope)
        self._session.commit()
        self._session.refresh(scope)
        return scope

    def list_for_program(self, program_id: str) -> list[ScopeRuleORM]:
        statement = select(ScopeRuleORM).where(ScopeRuleORM.program_id == program_id)
        return list(self._session.scalars(statement.order_by(ScopeRuleORM.value)))


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, target: TargetORM) -> TargetORM:
        self._session.add(target)
        self._session.commit()
        self._session.refresh(target)
        return target

    def get_by_id(self, target_id: str) -> TargetORM | None:
        return self._session.get(TargetORM, target_id)

    def list_for_program(self, program_id: str) -> list[TargetORM]:
        statement = select(TargetORM).where(TargetORM.program_id == program_id)
        return list(self._session.scalars(statement.order_by(TargetORM.host)))


class AuthorizationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, auth: AuthorizationORM) -> AuthorizationORM:
        self._session.add(auth)
        self._session.commit()
        self._session.refresh(auth)
        return auth

    def get_active_for_program(self, program_id: str) -> AuthorizationORM | None:
        statement = (
            select(AuthorizationORM)
            .where(AuthorizationORM.program_id == program_id, AuthorizationORM.active.is_(True))
            .order_by(AuthorizationORM.confirmed_at.desc())
        )
        return self._session.scalars(statement).first()

    def list_for_program(self, program_id: str) -> list[AuthorizationORM]:
        statement = select(AuthorizationORM).where(AuthorizationORM.program_id == program_id)
        return list(self._session.scalars(statement.order_by(AuthorizationORM.confirmed_at)))


class RequestLogRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, log: RequestLogORM) -> RequestLogORM:
        self._session.add(log)
        self._session.commit()
        self._session.refresh(log)
        return log

    def list_for_program(self, program_id: str) -> list[RequestLogORM]:
        statement = select(RequestLogORM).where(RequestLogORM.program_id == program_id)
        return list(self._session.scalars(statement.order_by(RequestLogORM.timestamp_utc)))


class CheckResultRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, result: CheckResultORM) -> CheckResultORM:
        self._session.add(result)
        self._session.commit()
        self._session.refresh(result)
        return result

    def list_for_target(self, target_id: str) -> list[CheckResultORM]:
        statement = select(CheckResultORM).where(CheckResultORM.target_id == target_id)
        return list(self._session.scalars(statement.order_by(CheckResultORM.created_at)))


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, finding: FindingORM) -> FindingORM:
        self._session.add(finding)
        self._session.commit()
        self._session.refresh(finding)
        return finding

    def get_by_id(self, finding_id: str) -> FindingORM | None:
        return self._session.get(FindingORM, finding_id)

    def list_for_program(self, program_id: str) -> list[FindingORM]:
        statement = select(FindingORM).where(FindingORM.program_id == program_id)
        return list(self._session.scalars(statement.order_by(FindingORM.created_at)))

    def list_reportable_for_program(self, program_id: str) -> list[FindingORM]:
        statement = select(FindingORM).where(
            FindingORM.program_id == program_id,
            FindingORM.human_verified.is_(True),
        )
        return list(self._session.scalars(statement.order_by(FindingORM.created_at)))


class EvidenceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, evidence: EvidenceORM) -> EvidenceORM:
        self._session.add(evidence)
        self._session.commit()
        self._session.refresh(evidence)
        return evidence

    def list_for_finding(self, finding_id: str) -> list[EvidenceORM]:
        statement = select(EvidenceORM).where(EvidenceORM.finding_id == finding_id)
        return list(self._session.scalars(statement.order_by(EvidenceORM.created_at)))


class ReportRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, report: ReportORM) -> ReportORM:
        self._session.add(report)
        self._session.commit()
        self._session.refresh(report)
        return report

    def list_for_finding(self, finding_id: str) -> list[ReportORM]:
        statement = select(ReportORM).where(ReportORM.finding_id == finding_id)
        return list(self._session.scalars(statement.order_by(ReportORM.created_at)))

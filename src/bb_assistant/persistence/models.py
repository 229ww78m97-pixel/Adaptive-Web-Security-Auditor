"""SQLAlchemy ORM models for local bb-assistant storage."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ProgramORM(Base):
    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String, nullable=False)
    platform: Mapped[str] = mapped_column(String, nullable=False)
    policy_url: Mapped[str | None] = mapped_column(String)
    identification_header_name: Mapped[str | None] = mapped_column(String)
    identification_header_value: Mapped[str | None] = mapped_column(String)
    rate_limit_rps: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    safe_mode_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    authorizations: Mapped[list[AuthorizationORM]] = relationship(
        back_populates="program",
        cascade="all, delete-orphan",
    )
    scopes: Mapped[list[ScopeRuleORM]] = relationship(
        back_populates="program",
        cascade="all, delete-orphan",
    )
    targets: Mapped[list[TargetORM]] = relationship(
        back_populates="program",
        cascade="all, delete-orphan",
    )
    scan_runs: Mapped[list[ScanRunORM]] = relationship(
        back_populates="program",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list[FindingORM]] = relationship(
        back_populates="program",
        cascade="all, delete-orphan",
    )


class AuthorizationORM(Base):
    __tablename__ = "authorizations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    confirmed_by: Mapped[str] = mapped_column(String, nullable=False)
    authorization_text: Mapped[str] = mapped_column(Text, nullable=False)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    program: Mapped[ProgramORM] = relationship(back_populates="authorizations")
    scan_runs: Mapped[list[ScanRunORM]] = relationship(back_populates="authorization")


class ScopeRuleORM(Base):
    __tablename__ = "scopes"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=False)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    program: Mapped[ProgramORM] = relationship(back_populates="scopes")


class TargetORM(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    base_url: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    program: Mapped[ProgramORM] = relationship(back_populates="targets")
    scan_runs: Mapped[list[ScanRunORM]] = relationship(back_populates="target")
    request_logs: Mapped[list[RequestLogORM]] = relationship(back_populates="target")
    check_results: Mapped[list[CheckResultORM]] = relationship(back_populates="target")
    findings: Mapped[list[FindingORM]] = relationship(back_populates="target")


class ScanRunORM(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("authorizations.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String, nullable=False, default="passive")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String, nullable=False, default="created")
    summary: Mapped[str | None] = mapped_column(Text)

    program: Mapped[ProgramORM] = relationship(back_populates="scan_runs")
    target: Mapped[TargetORM] = relationship(back_populates="scan_runs")
    authorization: Mapped[AuthorizationORM] = relationship(back_populates="scan_runs")
    request_logs: Mapped[list[RequestLogORM]] = relationship(back_populates="scan_run")
    check_results: Mapped[list[CheckResultORM]] = relationship(back_populates="scan_run")


class RequestLogORM(Base):
    __tablename__ = "requests_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    scan_run_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id"))
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id"))
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    method: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    check_type: Mapped[str] = mapped_column(String, nullable=False)
    in_scope_validated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_size: Mapped[int | None] = mapped_column(Integer)
    identifying_header: Mapped[str | None] = mapped_column(String)
    notes: Mapped[str | None] = mapped_column(Text)

    program: Mapped[ProgramORM] = relationship()
    target: Mapped[TargetORM | None] = relationship(back_populates="request_logs")
    scan_run: Mapped[ScanRunORM | None] = relationship(back_populates="request_logs")
    evidence_items: Mapped[list[EvidenceORM]] = relationship(back_populates="request_log")


class CheckResultORM(Base):
    __tablename__ = "check_results"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    scan_run_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    check_name: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    target: Mapped[TargetORM] = relationship(back_populates="check_results")
    scan_run: Mapped[ScanRunORM | None] = relationship(back_populates="check_results")


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    finding_type: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    steps_to_reproduce: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    affected_url: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="draft")
    human_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    program: Mapped[ProgramORM] = relationship(back_populates="findings")
    target: Mapped[TargetORM] = relationship(back_populates="findings")
    evidence: Mapped[list[EvidenceORM]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    reports: Mapped[list[ReportORM]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class EvidenceORM(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    content_text: Mapped[str | None] = mapped_column(Text)
    storage_path: Mapped[str | None] = mapped_column(String)
    sha256: Mapped[str | None] = mapped_column(String)
    caption: Mapped[str | None] = mapped_column(Text)
    request_log_id: Mapped[str | None] = mapped_column(ForeignKey("requests_log.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[FindingORM] = relationship(back_populates="evidence")
    request_log: Mapped[RequestLogORM | None] = relationship(back_populates="evidence_items")


class ReportORM(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    report_format: Mapped[str] = mapped_column(String, nullable=False, default="markdown")
    title: Mapped[str] = mapped_column(String, nullable=False)
    content_path: Mapped[str | None] = mapped_column(String)
    content_md: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[FindingORM] = relationship(back_populates="reports")


class SettingORM(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

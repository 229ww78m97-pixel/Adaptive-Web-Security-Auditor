"""Domain models for the defensive bb-assistant core."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator, model_validator


def _new_id() -> str:
    return str(uuid4())


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AssetType(StrEnum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INFO = "info"
    ERROR = "error"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    REJECTED = "rejected"


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Program(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    name: str
    platform: str
    policy_url: AnyHttpUrl
    identification_header_name: str | None = None
    identification_header_value: str | None = None
    rate_limit_rps: float = Field(default=1.0, gt=0)
    safe_mode_default: bool = True

    @model_validator(mode="after")
    def validate_identification_header_pair(self) -> Program:
        name_set = bool(self.identification_header_name)
        value_set = bool(self.identification_header_value)
        if name_set != value_set:
            raise ValueError("identification header name and value must be set together")
        return self


class Authorization(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    program_id: str
    confirmed_by: str
    authorization_text: str
    confirmed_at: datetime = Field(default_factory=_utc_now)
    active: bool = True


class ScopeRule(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    program_id: str
    asset_type: AssetType
    value: str
    in_scope: bool
    notes: str | None = None

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("scope rule value must not be empty")
        return normalized


class Target(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    program_id: str
    base_url: AnyHttpUrl
    host: str | None = None
    notes: str | None = None

    @model_validator(mode="after")
    def default_host_from_base_url(self) -> Target:
        if self.host is None:
            object.__setattr__(self, "host", self.base_url.host)
        return self


class RequestLog(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    timestamp_utc: datetime = Field(default_factory=_utc_now)
    program_id: str
    target_id: str
    method: str
    url: AnyHttpUrl
    check_type: str
    in_scope_validated: bool
    response_status: int | None = None
    response_size: int | None = Field(default=None, ge=0)
    identifying_header: str | None = None
    notes: str | None = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, method: str) -> str:
        normalized = method.upper().strip()
        if not normalized:
            raise ValueError("method must not be empty")
        return normalized


class Finding(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    program_id: str
    target_id: str
    title: str
    severity: Severity
    finding_type: str
    description: str
    steps_to_reproduce: str
    impact: str
    recommendation: str
    affected_url: AnyHttpUrl
    status: FindingStatus = FindingStatus.DRAFT
    human_verified: bool = False


class CheckResult(StrictBaseModel):
    id: str = Field(default_factory=_new_id)
    target_id: str
    check_name: str
    status: CheckStatus
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utc_now)

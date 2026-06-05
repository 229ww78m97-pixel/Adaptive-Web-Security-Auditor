"""Redacted audit-trail exports for local documentation."""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any, Protocol

from bb_assistant.core.evidence import sanitize_evidence_text


class AuditExportError(Exception):
    """Raised when an audit export cannot be built or written."""


class ProgramRecord(Protocol):
    id: str
    name: str
    platform: str
    policy_url: str | None
    identification_header_name: str | None
    identification_header_value: str | None
    rate_limit_rps: float
    safe_mode_default: bool
    created_at: datetime
    updated_at: datetime


class AuthorizationRecord(Protocol):
    id: str
    program_id: str
    confirmed_by: str
    authorization_text: str
    confirmed_at: datetime
    active: bool


class ScopeRuleRecord(Protocol):
    id: str
    program_id: str
    asset_type: str
    value: str
    in_scope: bool
    notes: str | None


class TargetRecord(Protocol):
    id: str
    program_id: str
    base_url: str
    host: str
    notes: str | None


class RequestLogRecord(Protocol):
    id: str
    scan_run_id: str | None
    program_id: str
    target_id: str | None
    timestamp_utc: datetime
    method: str
    url: str
    check_type: str
    in_scope_validated: bool
    response_status: int | None
    response_size: int | None
    identifying_header: str | None
    notes: str | None


class CheckResultRecord(Protocol):
    id: str
    scan_run_id: str | None
    target_id: str
    check_name: str
    status: str
    summary: str
    details_json: str | None
    created_at: datetime


class FindingRecord(Protocol):
    id: str
    program_id: str
    target_id: str
    title: str
    severity: str
    finding_type: str
    description: str
    steps_to_reproduce: str
    impact: str
    recommendation: str
    affected_url: str
    status: str
    human_verified: bool
    created_at: datetime
    updated_at: datetime


class EvidenceRecord(Protocol):
    id: str
    finding_id: str
    type: str
    content_text: str | None
    storage_path: str | None
    sha256: str | None
    caption: str | None
    request_log_id: str | None
    created_at: datetime


class ReportRecord(Protocol):
    id: str
    finding_id: str
    report_format: str
    title: str
    content_path: str | None
    content_md: str | None
    created_at: datetime


class ProgramRepository(Protocol):
    def get_by_id(self, program_id: str) -> ProgramRecord | None: ...


class AuthorizationRepository(Protocol):
    def list_for_program(self, program_id: str) -> list[AuthorizationRecord]: ...


class ScopeRepository(Protocol):
    def list_for_program(self, program_id: str) -> list[ScopeRuleRecord]: ...


class TargetRepository(Protocol):
    def get_by_id(self, target_id: str) -> TargetRecord | None: ...
    def list_for_program(self, program_id: str) -> list[TargetRecord]: ...


class RequestLogRepository(Protocol):
    def list_for_program(self, program_id: str) -> list[RequestLogRecord]: ...


class CheckResultRepository(Protocol):
    def list_for_target(self, target_id: str) -> list[CheckResultRecord]: ...


class FindingRepository(Protocol):
    def list_for_program(self, program_id: str) -> list[FindingRecord]: ...


class EvidenceRepository(Protocol):
    def list_for_finding(self, finding_id: str) -> list[EvidenceRecord]: ...


class ReportRepository(Protocol):
    def list_for_finding(self, finding_id: str) -> list[ReportRecord]: ...


JSON_SECRET_PATTERN = re.compile(
    r'(?i)("?(?:token|access_token|refresh_token|password|secret|api_key|session)"?\s*:\s*)"[^"]*"'
)
COLON_SECRET_PATTERN = re.compile(
    r"(?i)\b(token|access_token|refresh_token|password|secret|api_key|session)\s*:\s*[^\s,;]+"
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


class AuditTrailExporter:
    """Build redacted local audit-trail exports from persisted records."""

    def __init__(
        self,
        *,
        program_repository: ProgramRepository,
        authorization_repository: AuthorizationRepository,
        scope_repository: ScopeRepository,
        target_repository: TargetRepository,
        request_log_repository: RequestLogRepository,
        check_result_repository: CheckResultRepository,
        finding_repository: FindingRepository,
        evidence_repository: EvidenceRepository,
        report_repository: ReportRepository,
    ) -> None:
        self._program_repository = program_repository
        self._authorization_repository = authorization_repository
        self._scope_repository = scope_repository
        self._target_repository = target_repository
        self._request_log_repository = request_log_repository
        self._check_result_repository = check_result_repository
        self._finding_repository = finding_repository
        self._evidence_repository = evidence_repository
        self._report_repository = report_repository

    def build_program_audit_markdown(self, program_id: str) -> str:
        payload = self.build_program_audit_json(program_id)
        return self._build_markdown(payload)

    def build_program_audit_json(self, program_id: str) -> dict[str, Any]:
        program = self._program_repository.get_by_id(program_id)
        if program is None:
            raise AuditExportError(f"Program '{program_id}' was not found")
        return self._build_payload(program)

    def build_target_audit_markdown(self, target_id: str) -> str:
        payload = self.build_target_audit_json(target_id)
        return self._build_markdown(payload)

    def build_target_audit_json(self, target_id: str) -> dict[str, Any]:
        target = self._target_repository.get_by_id(target_id)
        if target is None:
            raise AuditExportError(f"Target '{target_id}' was not found")

        program = self._program_repository.get_by_id(target.program_id)
        if program is None:
            raise AuditExportError(f"Program '{target.program_id}' was not found")
        return self._build_payload(program, target_id=target_id)

    def export_markdown(self, content: str, output_path: Path | str) -> Path:
        path = Path(output_path)
        self._ensure_parent(path)
        path.write_text(content, encoding="utf-8")
        return path

    def export_json(self, payload: dict[str, Any], output_path: Path | str) -> Path:
        path = Path(output_path)
        self._ensure_parent(path)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        return path

    def _build_payload(
        self, program: ProgramRecord, target_id: str | None = None
    ) -> dict[str, Any]:
        targets = self._target_repository.list_for_program(program.id)
        if target_id is not None:
            targets = [target for target in targets if target.id == target_id]

        target_ids = {target.id for target in targets}
        request_logs = [
            log
            for log in self._request_log_repository.list_for_program(program.id)
            if target_id is None or log.target_id in target_ids
        ]
        check_results = [
            result
            for target in targets
            for result in self._check_result_repository.list_for_target(target.id)
        ]
        findings = [
            finding
            for finding in self._finding_repository.list_for_program(program.id)
            if target_id is None or finding.target_id in target_ids
        ]

        evidence = [
            item
            for finding in findings
            for item in self._evidence_repository.list_for_finding(finding.id)
        ]
        reports = [
            report
            for finding in findings
            for report in self._report_repository.list_for_finding(finding.id)
        ]

        return {
            "export_type": "target_audit_trail" if target_id else "program_audit_trail",
            "redaction": "Sensitive values are redacted. Export is documentation only.",
            "program": self._program_to_dict(program),
            "scope_rules": [
                self._scope_to_dict(scope)
                for scope in self._scope_repository.list_for_program(program.id)
                if target_id is None or scope.value in {target.host for target in targets}
            ],
            "authorizations": [
                self._authorization_to_dict(auth)
                for auth in self._authorization_repository.list_for_program(program.id)
            ],
            "targets": [self._target_to_dict(target) for target in targets],
            "request_logs": [self._request_log_to_dict(log) for log in request_logs],
            "check_results": [self._check_result_to_dict(result) for result in check_results],
            "findings": [self._finding_to_dict(finding) for finding in findings],
            "evidence": [self._evidence_to_dict(item) for item in evidence],
            "reports": [self._report_to_dict(report) for report in reports],
        }

    def _program_to_dict(self, program: ProgramRecord) -> dict[str, Any]:
        return {
            "id": program.id,
            "name": _redact_text(program.name),
            "platform": _redact_text(program.platform),
            "policy_url": _redact_text(program.policy_url),
            "identification_header_name": _redact_text(program.identification_header_name),
            "identification_header_value": _redact_presence(program.identification_header_value),
            "rate_limit_rps": program.rate_limit_rps,
            "safe_mode_default": program.safe_mode_default,
            "created_at": _format_value(program.created_at),
            "updated_at": _format_value(program.updated_at),
        }

    def _scope_to_dict(self, scope: ScopeRuleRecord) -> dict[str, Any]:
        return {
            "id": scope.id,
            "program_id": scope.program_id,
            "asset_type": _redact_text(scope.asset_type),
            "value": _redact_text(scope.value),
            "in_scope": scope.in_scope,
            "notes": _redact_text(scope.notes),
        }

    def _authorization_to_dict(self, auth: AuthorizationRecord) -> dict[str, Any]:
        return {
            "id": auth.id,
            "program_id": auth.program_id,
            "confirmed_by": _redact_text(auth.confirmed_by),
            "authorization_text": _redact_text(auth.authorization_text),
            "confirmed_at": _format_value(auth.confirmed_at),
            "active": auth.active,
        }

    def _target_to_dict(self, target: TargetRecord) -> dict[str, Any]:
        return {
            "id": target.id,
            "program_id": target.program_id,
            "base_url": _redact_text(target.base_url),
            "host": _redact_text(target.host),
            "notes": _redact_text(target.notes),
        }

    def _request_log_to_dict(self, log: RequestLogRecord) -> dict[str, Any]:
        return {
            "id": log.id,
            "scan_run_id": log.scan_run_id,
            "program_id": log.program_id,
            "target_id": log.target_id,
            "timestamp_utc": _format_value(log.timestamp_utc),
            "method": _redact_text(log.method),
            "url": _redact_text(log.url),
            "check_type": _redact_text(log.check_type),
            "in_scope_validated": log.in_scope_validated,
            "response_status": log.response_status,
            "response_size": log.response_size,
            "identifying_header": _redact_header(log.identifying_header),
            "notes": _redact_text(log.notes),
        }

    def _check_result_to_dict(self, result: CheckResultRecord) -> dict[str, Any]:
        return {
            "id": result.id,
            "scan_run_id": result.scan_run_id,
            "target_id": result.target_id,
            "check_name": _redact_text(result.check_name),
            "status": _redact_text(result.status),
            "summary": _redact_text(result.summary),
            "details_json": _redact_text(result.details_json),
            "created_at": _format_value(result.created_at),
        }

    def _finding_to_dict(self, finding: FindingRecord) -> dict[str, Any]:
        return {
            "id": finding.id,
            "program_id": finding.program_id,
            "target_id": finding.target_id,
            "title": _redact_text(finding.title),
            "severity": _redact_text(finding.severity),
            "finding_type": _redact_text(finding.finding_type),
            "description": _redact_text(finding.description),
            "steps_to_reproduce": _redact_text(finding.steps_to_reproduce),
            "impact": _redact_text(finding.impact),
            "recommendation": _redact_text(finding.recommendation),
            "affected_url": _redact_text(finding.affected_url),
            "status": _redact_text(finding.status),
            "human_verified": finding.human_verified,
            "created_at": _format_value(finding.created_at),
            "updated_at": _format_value(finding.updated_at),
        }

    def _evidence_to_dict(self, evidence: EvidenceRecord) -> dict[str, Any]:
        return {
            "id": evidence.id,
            "finding_id": evidence.finding_id,
            "type": _redact_text(evidence.type),
            "content_text": _redact_text(evidence.content_text),
            "storage_path": _redact_text(evidence.storage_path),
            "sha256": evidence.sha256,
            "caption": _redact_text(evidence.caption),
            "request_log_id": evidence.request_log_id,
            "created_at": _format_value(evidence.created_at),
        }

    def _report_to_dict(self, report: ReportRecord) -> dict[str, Any]:
        return {
            "id": report.id,
            "finding_id": report.finding_id,
            "report_format": _redact_text(report.report_format),
            "title": _redact_text(report.title),
            "content_path": _redact_text(report.content_path),
            "content_md": _redact_text(report.content_md),
            "created_at": _format_value(report.created_at),
        }

    def _build_markdown(self, payload: dict[str, Any]) -> str:
        program = payload["program"]
        lines = [
            f"# Audit Trail: {program['name']}",
            "",
            "> Sensitive values are redacted. This export is documentation only and does not "
            "create or submit findings.",
            "",
            "## Program",
            f"- ID: {program['id']}",
            f"- Platform: {program['platform']}",
            f"- Policy URL: {program['policy_url'] or 'n/a'}",
            f"- Safe Mode Default: {program['safe_mode_default']}",
            f"- Rate Limit RPS: {program['rate_limit_rps']}",
            f"- Identification Header: {program['identification_header_name'] or 'n/a'}",
            "",
        ]

        lines.extend(
            _section(
                "Scope Rules", payload["scope_rules"], ("value", "asset_type", "in_scope", "notes")
            )
        )
        lines.extend(
            _section(
                "Authorizations",
                payload["authorizations"],
                ("confirmed_by", "active", "authorization_text"),
            )
        )
        lines.extend(_section("Targets", payload["targets"], ("base_url", "host", "notes")))
        lines.extend(
            _section(
                "Request Logs",
                payload["request_logs"],
                ("method", "url", "response_status", "response_size", "notes"),
            )
        )
        lines.extend(
            _section("Check Results", payload["check_results"], ("check_name", "status", "summary"))
        )
        lines.extend(
            _section(
                "Findings",
                payload["findings"],
                ("title", "severity", "status", "human_verified", "affected_url"),
            )
        )
        lines.extend(
            _section(
                "Evidence",
                payload["evidence"],
                ("type", "caption", "content_text", "request_log_id"),
            )
        )
        lines.extend(
            _section("Reports", payload["reports"], ("title", "report_format", "content_path"))
        )
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _ensure_parent(path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise AuditExportError(f"Could not create export directory for '{path}'") from error


def _section(title: str, records: list[dict[str, Any]], fields: tuple[str, ...]) -> list[str]:
    lines = [f"## {title}"]
    if not records:
        return [*lines, "", "_No records._", ""]

    for record in records:
        lines.append(f"- ID: {record['id']}")
        for field in fields:
            value = record.get(field)
            if value is not None:
                lines.append(f"  - {field}: {value}")
    lines.append("")
    return lines


def _redact_text(value: object | None) -> str | None:
    if value is None:
        return None

    sanitized = sanitize_evidence_text(str(value))
    sanitized = JSON_SECRET_PATTERN.sub(lambda match: f'{match.group(1)}"[REDACTED]"', sanitized)
    sanitized = COLON_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}: [REDACTED]", sanitized)
    return EMAIL_PATTERN.sub("[REDACTED_EMAIL]", sanitized)


def _redact_header(value: str | None) -> str | None:
    if value is None:
        return None
    if ":" in value:
        name = value.split(":", 1)[0].strip()
        return f"{_redact_text(name)}: [REDACTED]"
    return "[REDACTED]"


def _redact_presence(value: object | None) -> str | None:
    if value is None:
        return None
    return "[REDACTED]"


def _format_value(value: object | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime | date):
        return value.isoformat()
    return _redact_text(value)

"""Small UI orchestration helpers with no Streamlit dependency."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bb_assistant.core.checks.base import CheckResult, CheckStatus
from bb_assistant.core.evidence import EvidenceItem
from bb_assistant.core.models import AssetType, Finding, FindingStatus, ScopeRule, Severity
from bb_assistant.persistence.models import CheckResultORM, EvidenceORM, FindingORM, ScopeRuleORM

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "bb_assistant.sqlite3"
DEFAULT_DB_URL = f"sqlite+pysqlite:///{DEFAULT_DB_PATH}"
TEMPLATE_DIR = PROJECT_ROOT / "templates"
REPORTS_DIR = PROJECT_ROOT / "reports"


def ensure_local_dirs() -> None:
    DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def scope_rules_from_orm(scope_rules: list[ScopeRuleORM]) -> list[ScopeRule]:
    return [
        ScopeRule(
            id=scope.id,
            program_id=scope.program_id,
            asset_type=AssetType(scope.asset_type),
            value=scope.value,
            in_scope=scope.in_scope,
            notes=scope.notes,
        )
        for scope in scope_rules
    ]


def check_result_to_orm(
    check_result: CheckResult,
    *,
    target_id: str,
    scan_run_id: str | None = None,
) -> CheckResultORM:
    payload = {
        "details": check_result.details,
        "affected_url": check_result.affected_url,
        "severity_hint": check_result.severity_hint,
        "needs_manual_review": check_result.needs_manual_review,
    }
    return CheckResultORM(
        scan_run_id=scan_run_id,
        target_id=target_id,
        check_name=check_result.check_name,
        status=check_result.status.value,
        summary=check_result.summary,
        details_json=json.dumps(payload, sort_keys=True, default=str),
    )


def check_result_from_orm(check_result: CheckResultORM) -> CheckResult:
    payload = _load_details_payload(check_result.details_json)
    return CheckResult(
        check_name=check_result.check_name,
        status=CheckStatus(check_result.status),
        summary=check_result.summary,
        details=payload.get("details", {}),
        affected_url=payload.get("affected_url"),
        severity_hint=payload.get("severity_hint"),
        needs_manual_review=bool(payload.get("needs_manual_review", False)),
    )


def finding_to_orm(finding: Finding) -> FindingORM:
    return FindingORM(
        id=finding.id,
        program_id=finding.program_id,
        target_id=finding.target_id,
        title=finding.title,
        severity=finding.severity.value,
        finding_type=finding.finding_type,
        description=finding.description,
        steps_to_reproduce=finding.steps_to_reproduce,
        impact=finding.impact,
        recommendation=finding.recommendation,
        affected_url=str(finding.affected_url),
        status=finding.status.value,
        human_verified=finding.human_verified,
    )


def evidence_item_to_orm(evidence: EvidenceItem) -> EvidenceORM:
    return EvidenceORM(
        finding_id=evidence.finding_id,
        type=evidence.type,
        content_text=evidence.content_text,
        caption=evidence.caption,
        sha256=evidence.sha256,
        request_log_id=evidence.request_log_id,
        storage_path=evidence.storage_path,
    )


def evidence_notes_as_markdown(evidence_items: list[EvidenceORM]) -> str:
    notes = [item for item in evidence_items if item.type == "note" and item.content_text]
    if not notes:
        return "Evidence should be reviewed and attached by the researcher."

    lines: list[str] = []
    for index, item in enumerate(notes, start=1):
        title = item.caption or f"Evidence note {index}"
        lines.append(f"### {title}")
        lines.append("")
        lines.append(item.content_text or "")
        if item.sha256:
            lines.append("")
            lines.append(f"SHA256: `{item.sha256}`")
        lines.append("")
    return "\n".join(lines).strip()


def verify_finding_orm(
    finding: FindingORM,
    *,
    verified_by: str,
    verification_note: str,
) -> FindingORM:
    finding.human_verified = True
    finding.status = FindingStatus.READY.value
    note = verification_note.strip() or "No additional verification note provided."
    finding.description = (
        f"{finding.description}\n\nManual verification by {verified_by.strip()}:\n\n{note}"
    )
    return finding


def severity_label(value: Any) -> str:
    if isinstance(value, Severity):
        return value.value
    return str(value)


def _load_details_payload(details_json: str | None) -> dict[str, Any]:
    if not details_json:
        return {
            "details": {},
            "affected_url": None,
            "severity_hint": None,
            "needs_manual_review": False,
        }
    loaded = json.loads(details_json)
    if not isinstance(loaded, dict):
        return {
            "details": {},
            "affected_url": None,
            "severity_hint": None,
            "needs_manual_review": False,
        }
    if "details" in loaded:
        return dict(loaded)
    return {
        "details": loaded,
        "affected_url": None,
        "severity_hint": None,
        "needs_manual_review": False,
    }

"""Request logging adapters for persistence."""

from __future__ import annotations

from sqlalchemy.orm import Session

from bb_assistant.core.http_client import LoggedRequest
from bb_assistant.persistence.models import RequestLogORM
from bb_assistant.persistence.repositories import RequestLogRepository

SENSITIVE_NOTE_LABELS = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "password",
    "secret",
)


class DBRequestLogger:
    """Persist SafeHttpClient request logs to SQLite via SQLAlchemy."""

    def __init__(
        self,
        session: Session,
        *,
        program_id: str,
        target_id: str | None = None,
        scan_run_id: str | None = None,
    ) -> None:
        self._repository = RequestLogRepository(session)
        self._program_id = program_id
        self._target_id = target_id
        self._scan_run_id = scan_run_id

    def log(self, entry: LoggedRequest) -> None:
        self._repository.create(
            RequestLogORM(
                scan_run_id=self._scan_run_id,
                program_id=self._program_id,
                target_id=self._target_id,
                method=entry.method,
                url=entry.url,
                check_type=entry.check_type,
                in_scope_validated=entry.in_scope_validated,
                response_status=entry.response_status,
                response_size=entry.response_size,
                identifying_header=entry.identifying_header,
                notes=_redact_sensitive_note(entry.notes),
            )
        )


def _redact_sensitive_note(note: str | None) -> str | None:
    if note is None:
        return None

    redacted_lines: list[str] = []
    for line in note.splitlines():
        lowered = line.lower()
        if any(label in lowered for label in SENSITIVE_NOTE_LABELS):
            redacted_lines.append(_redact_line_value(line))
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines)


def _redact_line_value(line: str) -> str:
    for separator in (":", "="):
        if separator in line:
            key = line.split(separator, 1)[0].strip()
            return f"{key}{separator} [REDACTED]"
    return "[REDACTED]"

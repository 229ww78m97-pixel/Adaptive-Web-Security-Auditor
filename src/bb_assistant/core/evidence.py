"""Evidence helpers for safe finding documentation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


class EvidenceValidationError(ValueError):
    """Raised when evidence input is not safe or complete enough to store."""


@dataclass(frozen=True)
class EvidenceItem:
    finding_id: str
    type: str
    content_text: str | None = None
    caption: str | None = None
    sha256: str | None = None
    request_log_id: str | None = None
    storage_path: str | None = None


HEADER_REDACTION_PATTERNS = (
    re.compile(r"(?im)^(Authorization)\s*:\s*.+$"),
    re.compile(r"(?im)^(Cookie)\s*:\s*.+$"),
    re.compile(r"(?im)^(Set-Cookie)\s*:\s*.+$"),
)

KEY_VALUE_REDACTION_PATTERN = re.compile(
    r"(?i)\b(token|access_token|refresh_token|password|secret|api_key|session)\s*=\s*[^&\s;]+"
)
JWT_LIKE_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b")


def sanitize_evidence_text(text: str) -> str:
    sanitized = text
    for pattern in HEADER_REDACTION_PATTERNS:
        sanitized = pattern.sub(lambda match: f"{match.group(1)}: [REDACTED]", sanitized)
    sanitized = KEY_VALUE_REDACTION_PATTERN.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        sanitized,
    )
    return JWT_LIKE_PATTERN.sub("[REDACTED_JWT]", sanitized)


def calculate_sha256_for_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def create_evidence_note(
    *,
    finding_id: str,
    text: str,
    caption: str | None = None,
) -> EvidenceItem:
    if not text.strip():
        raise EvidenceValidationError("Evidence note text must not be empty")

    sanitized_text = sanitize_evidence_text(text.strip())
    sanitized_caption = sanitize_evidence_text(caption.strip()) if caption else None
    return EvidenceItem(
        finding_id=finding_id,
        type="note",
        content_text=sanitized_text,
        caption=sanitized_caption,
        sha256=calculate_sha256_for_text(sanitized_text),
    )


def create_evidence_from_request_log(
    *,
    finding_id: str,
    request_log_id: str,
    caption: str | None = None,
) -> EvidenceItem:
    if not request_log_id.strip():
        raise EvidenceValidationError("request_log_id must not be empty")

    sanitized_caption = sanitize_evidence_text(caption.strip()) if caption else None
    return EvidenceItem(
        finding_id=finding_id,
        type="request_reference",
        request_log_id=request_log_id,
        caption=sanitized_caption,
    )

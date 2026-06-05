from __future__ import annotations

from pathlib import Path

import pytest

from bb_assistant.core.models import Finding, FindingStatus, Severity
from bb_assistant.core.reporting import (
    ReportGenerator,
    ReportNotAllowedError,
    ReportTemplateError,
)
from bb_assistant.persistence.models import FindingORM

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"


def make_finding(*, human_verified: bool = True) -> Finding:
    return Finding(
        program_id="program-1",
        target_id="target-1",
        title="Missing Content-Security-Policy",
        severity=Severity.LOW,
        finding_type="security_headers",
        description="The affected endpoint does not return a Content-Security-Policy header.",
        steps_to_reproduce="Send a GET request to https://example.com and inspect headers.",
        impact="Browser-side defense-in-depth is reduced.",
        recommendation="Define a Content-Security-Policy appropriate for the application.",
        affected_url="https://example.com",
        status=FindingStatus.READY,
        human_verified=human_verified,
    )


def make_finding_orm(*, human_verified: bool = True) -> FindingORM:
    return FindingORM(
        program_id="program-1",
        target_id="target-1",
        title="Missing Referrer-Policy",
        severity="low",
        finding_type="security_headers",
        description="The affected endpoint does not return a Referrer-Policy header.",
        steps_to_reproduce="Send a GET request to https://example.com and inspect headers.",
        impact="Referrer data may be exposed more broadly than intended.",
        recommendation="Set a suitable Referrer-Policy header.",
        affected_url="https://example.com",
        status="ready",
        human_verified=human_verified,
    )


def test_technical_report_renders_verified_domain_finding() -> None:
    generator = ReportGenerator(TEMPLATE_DIR)

    report = generator.render_technical_report(
        make_finding(),
        context={
            "program_name": "Example Bug Bounty",
            "asset": "example.com",
            "scope_proof": "example.com is listed as in scope in the program policy.",
            "evidence": "- Response header review completed by researcher.",
        },
    )

    assert "# Missing Content-Security-Policy" in report
    assert "## Scope Proof" in report
    assert "Example Bug Bounty" in report
    assert "example.com is listed as in scope" in report
    assert "Content-Security-Policy" in report


def test_management_summary_renders_verified_orm_finding() -> None:
    generator = ReportGenerator(TEMPLATE_DIR)

    report = generator.render_management_summary(
        make_finding_orm(),
        context={"affected_system": "example.com web application"},
    )

    assert "# Management Summary" in report
    assert "Missing Referrer-Policy" in report
    assert "example.com web application" in report
    assert "Set a suitable Referrer-Policy header." in report


def test_unverified_finding_is_blocked() -> None:
    generator = ReportGenerator(TEMPLATE_DIR)

    with pytest.raises(ReportNotAllowedError, match="Only human-verified findings"):
        generator.render_technical_report(make_finding(human_verified=False))


def test_unverified_orm_finding_is_blocked() -> None:
    generator = ReportGenerator(TEMPLATE_DIR)

    with pytest.raises(ReportNotAllowedError, match="Only human-verified findings"):
        generator.render_management_summary(make_finding_orm(human_verified=False))


def test_missing_template_has_clear_error(tmp_path: Path) -> None:
    generator = ReportGenerator(tmp_path)

    with pytest.raises(ReportTemplateError, match=r"report_technical\.md\.j2"):
        generator.render_technical_report(make_finding())


def test_export_markdown_writes_file(tmp_path: Path) -> None:
    generator = ReportGenerator(TEMPLATE_DIR)
    output_path = tmp_path / "reports" / "finding.md"

    written_path = generator.export_markdown("# Report\n", output_path)

    assert written_path == output_path
    assert output_path.read_text(encoding="utf-8") == "# Report\n"


def test_report_generator_does_not_render_check_results_as_findings() -> None:
    generator = ReportGenerator(TEMPLATE_DIR)
    check_result = {
        "check_name": "security_headers",
        "human_verified": False,
        "summary": "Missing header observed",
    }

    with pytest.raises(AttributeError):
        generator.render_technical_report(check_result)  # type: ignore[arg-type]

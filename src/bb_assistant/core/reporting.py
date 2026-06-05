"""Markdown report rendering for human-verified findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape


class ReportNotAllowedError(Exception):
    """Raised when a finding is not eligible for report rendering."""


class ReportTemplateError(FileNotFoundError):
    """Raised when a configured report template cannot be found."""


class ReportableFinding(Protocol):
    title: Any
    program_id: Any
    target_id: Any
    severity: Any
    finding_type: Any
    description: Any
    steps_to_reproduce: Any
    impact: Any
    recommendation: Any
    affected_url: Any
    status: Any
    human_verified: bool


class ReportGenerator:
    def __init__(self, template_dir: Path | str) -> None:
        self._template_dir = Path(template_dir)
        self._environment = Environment(
            loader=FileSystemLoader(self._template_dir),
            autoescape=select_autoescape(default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_technical_report(
        self,
        finding: ReportableFinding,
        context: dict[str, Any] | None = None,
    ) -> str:
        return self._render("report_technical.md.j2", finding, context)

    def render_management_summary(
        self,
        finding: ReportableFinding,
        context: dict[str, Any] | None = None,
    ) -> str:
        return self._render("report_management.md.j2", finding, context)

    def export_markdown(self, content: str, output_path: Path | str) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _render(
        self,
        template_name: str,
        finding: ReportableFinding,
        context: dict[str, Any] | None,
    ) -> str:
        self._ensure_report_allowed(finding)
        try:
            template = self._environment.get_template(template_name)
        except TemplateNotFound as error:
            raise ReportTemplateError(
                f"Report template '{template_name}' was not found in {self._template_dir}"
            ) from error

        render_context = dict(context or {})
        render_context["finding"] = finding
        return template.render(**render_context).strip() + "\n"

    @staticmethod
    def _ensure_report_allowed(finding: ReportableFinding) -> None:
        if not finding.human_verified:
            raise ReportNotAllowedError("Only human-verified findings can be rendered as reports")

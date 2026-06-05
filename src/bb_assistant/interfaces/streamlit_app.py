"""Minimal Streamlit UI for the passive-first bb-assistant workflow."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from pydantic import AnyHttpUrl

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

import streamlit as st
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from bb_assistant.core.checks.cookies import CookieFlagsCheck
from bb_assistant.core.checks.robots_txt import RobotsTxtCheck
from bb_assistant.core.checks.security_headers import SecurityHeadersCheck
from bb_assistant.core.checks.security_txt import SecurityTxtCheck
from bb_assistant.core.checks.tls_basics import TLSBasicsCheck
from bb_assistant.core.findings import (
    FindingDraftNotAllowedError,
    create_finding_draft_from_check_result,
    verify_finding,
)
from bb_assistant.core.http_client import SafeHttpClient
from bb_assistant.core.models import Finding, FindingStatus, Severity
from bb_assistant.core.rate_limiter import RateLimiter
from bb_assistant.core.reporting import ReportGenerator, ReportNotAllowedError
from bb_assistant.core.scope_guard import OutOfScopeError, ScopeGuard
from bb_assistant.interfaces.ui_helpers import (
    DEFAULT_DB_URL,
    REPORTS_DIR,
    TEMPLATE_DIR,
    check_result_from_orm,
    check_result_to_orm,
    ensure_local_dirs,
    finding_to_orm,
    scope_rules_from_orm,
    verify_finding_orm,
)
from bb_assistant.persistence.db import create_engine_for_url, create_session_factory, init_db
from bb_assistant.persistence.logging import DBRequestLogger
from bb_assistant.persistence.models import (
    AuthorizationORM,
    CheckResultORM,
    FindingORM,
    ProgramORM,
    ScopeRuleORM,
    TargetORM,
)
from bb_assistant.persistence.repositories import (
    AuthorizationRepository,
    CheckResultRepository,
    FindingRepository,
    ProgramRepository,
    ScopeRepository,
    TargetRepository,
)

PASSIVE_CHECKS = (
    TLSBasicsCheck(),
    SecurityHeadersCheck(),
    CookieFlagsCheck(),
    SecurityTxtCheck(),
    RobotsTxtCheck(),
)


@st.cache_resource
def session_factory() -> sessionmaker[Session]:
    ensure_local_dirs()
    engine = create_engine_for_url(DEFAULT_DB_URL)
    init_db(engine)
    return create_session_factory(engine)


def main() -> None:
    st.set_page_config(page_title="bb-assistant", layout="wide")
    st.title("bb-assistant")
    st.caption("Passive-first Bug Bounty Analysis & Findings Assistant")

    page = st.sidebar.radio(
        "Navigation",
        [
            "Dashboard",
            "Programs",
            "Scope",
            "Targets",
            "Authorization",
            "Passive Checks",
            "Findings",
            "Reports",
        ],
    )

    with session_factory()() as session:
        if page == "Dashboard":
            render_dashboard(session)
        elif page == "Programs":
            render_programs(session)
        elif page == "Scope":
            render_scope(session)
        elif page == "Targets":
            render_targets(session)
        elif page == "Authorization":
            render_authorization(session)
        elif page == "Passive Checks":
            render_passive_checks(session)
        elif page == "Findings":
            render_findings(session)
        elif page == "Reports":
            render_reports(session)


def render_dashboard(session: Session) -> None:
    st.header("Dashboard")
    program_count = session.scalar(select(func.count(ProgramORM.id))) or 0
    target_count = session.scalar(select(func.count(TargetORM.id))) or 0
    finding_count = session.scalar(select(func.count(FindingORM.id))) or 0
    reportable_count = (
        session.scalar(select(func.count(FindingORM.id)).where(FindingORM.human_verified.is_(True)))
        or 0
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Programs", program_count)
    col2.metric("Targets", target_count)
    col3.metric("Findings", finding_count)
    col4.metric("Reportable Findings", reportable_count)
    st.info("Safe Mode is enabled. Only passive checks are available.")


def render_programs(session: Session) -> None:
    st.header("Programs")
    repository = ProgramRepository(session)

    with st.form("create_program"):
        name = st.text_input("Name")
        platform = st.text_input("Platform")
        policy_url = st.text_input("Policy URL")
        header_name = st.text_input("Identification header name")
        header_value = st.text_input("Identification header value")
        rate_limit = st.number_input("Rate limit RPS", min_value=0.1, value=1.0, step=0.1)
        safe_mode = st.checkbox("Safe mode default", value=True)
        submitted = st.form_submit_button("Create Program")

    if submitted:
        if not name or not platform:
            st.error("Name and platform are required.")
        else:
            repository.create(
                ProgramORM(
                    name=name,
                    platform=platform,
                    policy_url=policy_url or None,
                    identification_header_name=header_name or None,
                    identification_header_value=header_value or None,
                    rate_limit_rps=float(rate_limit),
                    safe_mode_default=safe_mode,
                )
            )
            st.success("Program created.")
            st.rerun()

    st.subheader("Existing Programs")
    st.dataframe([program_row(program) for program in repository.list_all()])


def render_scope(session: Session) -> None:
    st.header("Scope")
    program = select_program(session)
    if program is None:
        return

    repository = ScopeRepository(session)
    with st.form("create_scope"):
        asset_type = st.selectbox("Asset type", ["domain", "wildcard", "url", "ip", "cidr"])
        value = st.text_input("Value")
        in_scope = st.checkbox("In scope", value=True)
        notes = st.text_area("Notes")
        submitted = st.form_submit_button("Create Scope Rule")

    if submitted:
        if not value:
            st.error("Scope value is required.")
        else:
            repository.create(
                ScopeRuleORM(
                    program_id=program.id,
                    asset_type=asset_type,
                    value=value,
                    in_scope=in_scope,
                    notes=notes or None,
                )
            )
            st.success("Scope rule created.")
            st.rerun()

    st.subheader("Scope Rules")
    rows = repository.list_for_program(program.id)
    st.dataframe([scope_row(scope) for scope in rows])


def render_targets(session: Session) -> None:
    st.header("Targets")
    program = select_program(session)
    if program is None:
        return

    scope_guard = build_scope_guard(session, program.id)
    repository = TargetRepository(session)
    with st.form("create_target"):
        base_url = st.text_input("Base URL")
        default_host = urlparse(base_url).hostname if base_url else ""
        host = st.text_input("Host", value=default_host or "")
        notes = st.text_area("Notes")
        submitted = st.form_submit_button("Create Target")

    if submitted:
        if not base_url or not host:
            st.error("Base URL and host are required.")
        else:
            show_scope_decision(scope_guard, base_url)
            repository.create(
                TargetORM(
                    program_id=program.id,
                    base_url=base_url,
                    host=host,
                    notes=notes or None,
                )
            )
            st.success("Target created. SafeHttpClient will validate scope again later.")

    st.subheader("Existing Targets")
    targets = repository.list_for_program(program.id)
    st.dataframe([target_row(target) for target in targets])


def render_authorization(session: Session) -> None:
    st.header("Authorization")
    program = select_program(session)
    if program is None:
        return

    repository = AuthorizationRepository(session)
    active = repository.get_active_for_program(program.id)
    if active is not None:
        st.success(f"Active authorization confirmed by {active.confirmed_by}.")
        st.write(active.authorization_text)

    st.info("Read the program policy and confirm authorization before running checks.")
    with st.form("create_authorization"):
        confirmed = st.checkbox(
            "Ich bestätige, dass ich die Programmpolicy gelesen habe, "
            "das Target im Scope liegt und nur autorisierte Tests durchgeführt werden."
        )
        confirmed_by = st.text_input("Confirmed by")
        authorization_text = st.text_area("Authorization text")
        submitted = st.form_submit_button("Save Active Authorization")

    if submitted:
        if not confirmed:
            st.error("You must explicitly confirm authorization.")
        elif not confirmed_by or not authorization_text:
            st.error("Confirmed by and authorization text are required.")
        else:
            repository.create(
                AuthorizationORM(
                    program_id=program.id,
                    confirmed_by=confirmed_by,
                    authorization_text=authorization_text,
                    active=True,
                )
            )
            st.success("Authorization saved.")
            st.rerun()


def render_passive_checks(session: Session) -> None:
    st.header("Passive Checks")
    program = select_program(session)
    if program is None:
        return
    target = select_target(session, program.id)
    if target is None:
        return

    authorization = AuthorizationRepository(session).get_active_for_program(program.id)
    if authorization is None:
        st.warning("Checks are blocked until an active authorization exists.")
        return

    st.write("Planned checks:", ", ".join(check.name for check in PASSIVE_CHECKS))
    if not st.button("Run Passive Checks"):
        render_check_results(session, target.id)
        return

    client = build_safe_client(session, program, target)
    result_repository = CheckResultRepository(session)
    for check in PASSIVE_CHECKS:
        try:
            result = check.run(target.base_url, client)
            result_repository.create(check_result_to_orm(result, target_id=target.id))
            st.success(f"{check.name}: {result.summary}")
        except OutOfScopeError as error:
            st.error(f"{check.name}: blocked as out of scope: {error}")
        except Exception as error:  # pragma: no cover - UI defensive boundary
            st.error(f"{check.name}: {error}")

    render_check_results(session, target.id)


def render_findings(session: Session) -> None:
    st.header("Findings")
    program = select_program(session)
    if program is None:
        return

    targets = TargetRepository(session).list_for_program(program.id)
    target_by_id = {target.id: target for target in targets}
    result_repository = CheckResultRepository(session)
    finding_repository = FindingRepository(session)

    st.subheader("Check Results")
    for target in targets:
        for stored_result in result_repository.list_for_target(target.id):
            result = check_result_from_orm(stored_result)
            with st.expander(f"{target.host} - {result.check_name} - {result.status}"):
                st.write(result.summary)
                st.json(result.details)
                st.write(f"Needs manual review: {result.needs_manual_review}")
                if result.needs_manual_review and st.button(
                    "Create Finding Draft",
                    key=f"draft-{stored_result.id}",
                ):
                    create_finding_draft(session, result, program.id, target.id)

    st.subheader("Findings")
    for finding in finding_repository.list_for_program(program.id):
        finding_target = target_by_id.get(finding.target_id)
        with st.expander(f"{finding.title} - {finding.status}"):
            st.write(f"Target: {finding_target.host if finding_target else finding.target_id}")
            st.write(f"Severity: {finding.severity}")
            st.write(f"Human verified: {finding.human_verified}")
            st.write(finding.description)
            if not finding.human_verified:
                render_verify_finding_form(session, finding)


def render_reports(session: Session) -> None:
    st.header("Reports")
    program = select_program(session)
    if program is None:
        return

    findings = FindingRepository(session).list_reportable_for_program(program.id)
    if not findings:
        st.info("No reportable findings yet. Verify a finding first.")
        return

    finding = select_finding("Reportable Finding", findings)
    if finding is None:
        return

    generator = ReportGenerator(TEMPLATE_DIR)
    context = {
        "program_name": program.name,
        "asset": finding.affected_url,
        "scope_proof": "Human verified as authorized and in scope before report generation.",
    }
    try:
        technical = generator.render_technical_report(finding, context=context)
        management = generator.render_management_summary(finding, context=context)
    except ReportNotAllowedError as error:
        st.error(str(error))
        return

    tab_technical, tab_management = st.tabs(["Technical Report", "Management Summary"])
    with tab_technical:
        st.markdown(technical)
        export_report(generator, technical, f"{finding.id}_technical.md")
    with tab_management:
        st.markdown(management)
        export_report(generator, management, f"{finding.id}_management.md")


def select_program(session: Session) -> ProgramORM | None:
    programs = ProgramRepository(session).list_all()
    if not programs:
        st.warning("Create a program first.")
        return None
    selected_id = st.selectbox(
        "Program",
        [program.id for program in programs],
        format_func=lambda program_id: next(
            program.name for program in programs if program.id == program_id
        ),
    )
    return next(program for program in programs if program.id == selected_id)


def select_target(session: Session, program_id: str) -> TargetORM | None:
    targets = TargetRepository(session).list_for_program(program_id)
    if not targets:
        st.warning("Create a target first.")
        return None
    selected_id = st.selectbox(
        "Target",
        [target.id for target in targets],
        format_func=lambda target_id: next(
            target.base_url for target in targets if target.id == target_id
        ),
    )
    return next(target for target in targets if target.id == selected_id)


def select_finding(label: str, findings: list[FindingORM]) -> FindingORM | None:
    selected_id = st.selectbox(
        label,
        [finding.id for finding in findings],
        format_func=lambda finding_id: next(
            finding.title for finding in findings if finding.id == finding_id
        ),
    )
    return next(finding for finding in findings if finding.id == selected_id)


def build_scope_guard(session: Session, program_id: str) -> ScopeGuard:
    scopes = ScopeRepository(session).list_for_program(program_id)
    return ScopeGuard(scope_rules_from_orm(scopes))


def build_safe_client(session: Session, program: ProgramORM, target: TargetORM) -> SafeHttpClient:
    identification_header = None
    if program.identification_header_name and program.identification_header_value:
        identification_header = (
            program.identification_header_name,
            program.identification_header_value,
        )
    return SafeHttpClient(
        scope_guard=build_scope_guard(session, program.id),
        rate_limiter=RateLimiter(program.rate_limit_rps),
        request_logger=DBRequestLogger(session, program_id=program.id, target_id=target.id),
        identification_header=identification_header,
        safe_mode=program.safe_mode_default,
    )


def show_scope_decision(scope_guard: ScopeGuard, base_url: str) -> None:
    try:
        decision = scope_guard.validate(base_url)
        st.success(f"In scope: {decision.reason}")
    except OutOfScopeError as error:
        st.warning(f"Out of scope: {error}")


def render_check_results(session: Session, target_id: str) -> None:
    results = CheckResultRepository(session).list_for_target(target_id)
    if not results:
        st.info("No check results stored for this target yet.")
        return
    st.subheader("Stored Check Results")
    st.dataframe([check_result_row(result) for result in results])


def create_finding_draft(
    session: Session,
    result: Any,
    program_id: str,
    target_id: str,
) -> None:
    affected_url = result.affected_url or "https://example.invalid"
    try:
        finding = create_finding_draft_from_check_result(
            result,
            program_id=program_id,
            target_id=target_id,
            affected_url=affected_url,
        )
    except FindingDraftNotAllowedError as error:
        st.error(str(error))
        return
    FindingRepository(session).create(finding_to_orm(finding))
    st.success("Finding draft created.")
    st.rerun()


def render_verify_finding_form(session: Session, finding: FindingORM) -> None:
    with st.form(f"verify-{finding.id}"):
        verified_by = st.text_input("Verified by")
        verification_note = st.text_area("Verification note")
        human_confirmed = st.checkbox("I manually verified this finding.")
        submitted = st.form_submit_button("Verify Finding")

    if submitted:
        if not human_confirmed:
            st.error("Manual confirmation is required.")
            return
        if not verified_by:
            st.error("Verified by is required.")
            return

        domain_finding = verify_finding(
            _finding_orm_to_domain(finding),
            human_confirmed=True,
        )
        finding.human_verified = domain_finding.human_verified
        finding.status = domain_finding.status.value
        verify_finding_orm(
            finding,
            verified_by=verified_by,
            verification_note=verification_note,
        )
        session.commit()
        st.success("Finding verified.")
        st.rerun()


def export_report(generator: ReportGenerator, content: str, filename: str) -> None:
    output_path = REPORTS_DIR / filename
    if st.button(f"Export {filename}", key=f"export-{filename}"):
        written_path = generator.export_markdown(content, output_path)
        st.success(f"Exported to {written_path}")
    st.download_button(
        f"Download {filename}",
        data=content,
        file_name=filename,
        mime="text/markdown",
        key=f"download-{filename}",
    )


def program_row(program: ProgramORM) -> dict[str, Any]:
    return {
        "id": program.id,
        "name": program.name,
        "platform": program.platform,
        "policy_url": program.policy_url,
        "rate_limit_rps": program.rate_limit_rps,
        "safe_mode_default": program.safe_mode_default,
    }


def scope_row(scope: ScopeRuleORM) -> dict[str, Any]:
    return {
        "asset_type": scope.asset_type,
        "value": scope.value,
        "in_scope": scope.in_scope,
        "notes": scope.notes,
    }


def target_row(target: TargetORM) -> dict[str, Any]:
    return {
        "base_url": target.base_url,
        "host": target.host,
        "notes": target.notes,
    }


def check_result_row(result: CheckResultORM) -> dict[str, Any]:
    restored = check_result_from_orm(result)
    return {
        "check_name": restored.check_name,
        "status": restored.status.value,
        "summary": restored.summary,
        "needs_manual_review": restored.needs_manual_review,
        "severity_hint": restored.severity_hint,
        "affected_url": restored.affected_url,
    }


def _finding_orm_to_domain(finding: FindingORM) -> Finding:
    return Finding(
        id=finding.id,
        program_id=finding.program_id,
        target_id=finding.target_id,
        title=finding.title,
        severity=Severity(finding.severity),
        finding_type=finding.finding_type,
        description=finding.description,
        steps_to_reproduce=finding.steps_to_reproduce,
        impact=finding.impact,
        recommendation=finding.recommendation,
        affected_url=cast(AnyHttpUrl, finding.affected_url),
        status=FindingStatus(finding.status),
        human_verified=finding.human_verified,
    )


if __name__ == "__main__":
    main()

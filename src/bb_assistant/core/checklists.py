"""Human-in-the-loop checklist generation from passive technology profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

from bb_assistant.core.profiler import TechProfile

CHECKLIST_CATEGORIES = {"passive", "manual", "explicit_permission_required"}


@dataclass(frozen=True)
class ChecklistItem:
    id: str
    title: str
    description: str
    category: str
    tags: list[str]
    rationale: str
    safety_note: str
    references: list[str] = field(default_factory=list)
    auto_executable: bool = False

    def __post_init__(self) -> None:
        if self.category not in CHECKLIST_CATEGORIES:
            raise ValueError(f"Unknown checklist category: {self.category}")
        if self.auto_executable:
            raise ValueError("Checklist items must not be auto-executable")
        if not self.safety_note.strip():
            raise ValueError("Checklist items must include a safety_note")


@dataclass(frozen=True)
class Checklist:
    id: str
    title: str
    target_url: str
    items: list[ChecklistItem]
    generated_from_tags: list[str]
    passive_only: bool = True

    def items_by_category(self, category: str) -> list[ChecklistItem]:
        return [item for item in self.items if item.category == category]

    def has_items(self) -> bool:
        return bool(self.items)


class ChecklistEngine:
    """Generate non-executable manual checklists from passive profile tags."""

    def generate(self, profile: TechProfile) -> Checklist:
        tags = set(profile.tags)
        items = _generic_items()

        if "wordpress" in tags or _has_category_tag(tags, "cms"):
            items.extend(_wordpress_items())
        if "api_route" in tags or "openapi" in tags or _has_category_tag(tags, "api"):
            items.extend(_api_items())
        if "auth_surface" in tags:
            items.extend(_auth_items())
        if "cloudflare" in tags or "cloudfront" in tags or "cdn" in tags:
            items.extend(_cdn_items())
        if "azure" in tags or "aws" in tags or "cloud" in tags:
            items.extend(_cloud_items())
        if "next.js" in tags or "nextjs" in tags or "react" in tags:
            items.extend(_frontend_items())

        return Checklist(
            id=_new_id(),
            title="Suggested manual security checklist",
            target_url=profile.target_url,
            items=_dedupe_items(items),
            generated_from_tags=sorted(tags),
        )


def _generic_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review program policy and target scope before testing",
            description="Confirm that the target and intended review activities are in scope.",
            category="manual",
            tags=["scope", "policy"],
            rationale="Scope and policy review prevents accidental out-of-scope work.",
        ),
        _item(
            title="Confirm authorization and safe harbor before manual checks",
            description=(
                "Verify that authorization is active and recorded before reviewing results."
            ),
            category="manual",
            tags=["authorization", "safe_harbor"],
            rationale="Human confirmation is required before any manual security review.",
        ),
        _item(
            title="Review security headers results",
            description=(
                "Review passive header observations and decide whether they matter in context."
            ),
            category="passive",
            tags=["security_headers"],
            rationale="Header observations are hints and require context before reporting.",
        ),
        _item(
            title="Review cookie flags and session-related cookie names",
            description="Review cookie flag observations without storing cookie values.",
            category="passive",
            tags=["cookies", "session"],
            rationale="Cookie metadata can guide manual review without collecting secrets.",
        ),
        _item(
            title="Review TLS and HTTPS baseline",
            description="Confirm that the target uses HTTPS and review passive TLS baseline notes.",
            category="passive",
            tags=["tls", "https"],
            rationale="HTTPS baseline review is useful context for defensive assessment.",
        ),
        _item(
            title="Document evidence with redaction",
            description=(
                "Record notes and request references while redacting secrets and personal data."
            ),
            category="manual",
            tags=["evidence", "redaction"],
            rationale="Clean evidence supports reporting without exposing sensitive data.",
        ),
    ]


def _wordpress_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review publicly exposed WordPress REST API information",
            description="Manually review visible REST API metadata that is already public.",
            category="manual",
            tags=["wordpress", "cms", "api"],
            rationale="Public REST metadata may help understand the site surface.",
        ),
        _item(
            title="Review visible plugin and theme references in page source",
            description="Inspect public HTML for plugin and theme references without crawling.",
            category="passive",
            tags=["wordpress", "plugins", "themes"],
            rationale="Visible references can inform manual context review.",
        ),
        _item(
            title="Check whether WordPress version exposure is visible",
            description="Review existing HTML or headers for version disclosure.",
            category="passive",
            tags=["wordpress", "version_exposure"],
            rationale="Version exposure is informational until impact is manually validated.",
        ),
        _item(
            title="Avoid account enumeration and login abuse",
            description="Treat user-related observations as policy-sensitive and non-automated.",
            category="explicit_permission_required",
            tags=["wordpress", "safety"],
            rationale="Account-related testing can affect users and program rules.",
            safety_note=(
                "Do not perform user enumeration, credential testing, lockout testing, "
                "or brute force activity unless the program explicitly permits it."
            ),
        ),
    ]


def _api_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review public API documentation for authentication requirements",
            description=(
                "Read visible API documentation and note documented authentication expectations."
            ),
            category="manual",
            tags=["api", "openapi", "auth"],
            rationale="Documentation can clarify intended access boundaries.",
        ),
        _item(
            title="Map documented endpoints manually",
            description="Create a human-reviewed map from public documentation only.",
            category="manual",
            tags=["api", "documentation"],
            rationale="Manual mapping helps organize review without automated endpoint discovery.",
        ),
        _item(
            title="Check whether sensitive endpoints are documented publicly",
            description=(
                "Review whether public docs describe administrative or sensitive operations."
            ),
            category="manual",
            tags=["api", "documentation"],
            rationale="Public documentation can reveal review priorities.",
        ),
        _item(
            title="Review CORS findings in context",
            description="Compare passive CORS observations with documented API usage.",
            category="manual",
            tags=["api", "cors"],
            rationale="CORS observations require application context before reporting.",
        ),
        _item(
            title="Avoid automated endpoint discovery unless explicitly allowed",
            description="Do not run automated endpoint discovery from this checklist.",
            category="explicit_permission_required",
            tags=["api", "safety"],
            rationale="Endpoint discovery can exceed passive review boundaries.",
            safety_note=(
                "Do not perform automated endpoint fuzzing, crawling, or enumeration unless "
                "the program explicitly permits it."
            ),
        ),
    ]


def _auth_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review login page security headers and cookie behavior",
            description="Review passive observations for the visible authentication surface.",
            category="manual",
            tags=["auth_surface", "headers", "cookies"],
            rationale="Login surfaces often require careful manual context review.",
        ),
        _item(
            title="Check whether MFA is documented or visible",
            description="Record whether public UI or docs mention MFA support.",
            category="passive",
            tags=["auth_surface", "mfa"],
            rationale="Visible MFA information can inform manual assessment notes.",
        ),
        _item(
            title="Review password reset flow only within program rules",
            description=(
                "Review documented reset behavior only after confirming explicit permission."
            ),
            category="explicit_permission_required",
            tags=["auth_surface", "password_reset"],
            rationale="Password reset review can affect accounts and must stay within policy.",
            safety_note=(
                "Do not perform credential stuffing, password spraying, brute force, lockout "
                "testing, or account-impacting actions."
            ),
        ),
        _item(
            title="Avoid credential abuse and lockout testing",
            description=(
                "Keep authentication review limited to authorized, documented manual checks."
            ),
            category="explicit_permission_required",
            tags=["auth_surface", "safety"],
            rationale="Authentication testing is sensitive and can harm users.",
            safety_note=(
                "Do not perform credential stuffing, password spraying, brute force, or "
                "lockout testing."
            ),
        ),
    ]


def _cdn_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review CDN and security header interaction",
            description="Compare passive CDN signals with observed security headers.",
            category="manual",
            tags=["cdn", "headers"],
            rationale="CDNs can influence visible response headers.",
        ),
        _item(
            title="Review caching-related response headers",
            description="Review cache headers already observed in responses.",
            category="passive",
            tags=["cdn", "cache"],
            rationale="Caching metadata can affect security and privacy context.",
        ),
        _item(
            title="Avoid origin or WAF circumvention attempts",
            description="Do not attempt to route around CDN or security controls.",
            category="explicit_permission_required",
            tags=["cdn", "safety"],
            rationale="Circumvention attempts are outside passive review.",
            safety_note=(
                "Do not attempt origin bypass, WAF bypass, or protection circumvention unless "
                "the program explicitly permits it."
            ),
        ),
    ]


def _cloud_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review public cloud metadata and identity hints",
            description="Review visible cloud headers, URLs, and service names already observed.",
            category="passive",
            tags=["cloud"],
            rationale="Cloud indicators can guide safe documentation and scoping questions.",
        ),
        _item(
            title="Review exposed storage or service URLs only if in scope",
            description="Check whether observed public URLs are listed as in scope before review.",
            category="manual",
            tags=["cloud", "scope"],
            rationale="Cloud service URLs may belong to separate assets or tenants.",
        ),
        _item(
            title="Avoid tenant or token manipulation",
            description="Do not modify cloud identity, tenant, or token values.",
            category="explicit_permission_required",
            tags=["cloud", "safety"],
            rationale="Identity manipulation can cross authorization boundaries.",
            safety_note=(
                "Do not test tenant manipulation, token manipulation, or identity boundary "
                "changes unless explicitly authorized."
            ),
        ),
    ]


def _frontend_items() -> list[ChecklistItem]:
    return [
        _item(
            title="Review exposed client-side routes and JavaScript bundle references",
            description="Inspect already visible client-side routes and script references.",
            category="passive",
            tags=["frontend", "javascript"],
            rationale="Public client-side assets can reveal application structure.",
        ),
        _item(
            title="Review whether sensitive values are exposed in public JavaScript",
            description=(
                "Manually review visible JavaScript references for accidental sensitive values."
            ),
            category="manual",
            tags=["frontend", "javascript", "redaction"],
            rationale="Sensitive data exposure requires careful manual validation and redaction.",
        ),
        _item(
            title="Avoid automated bundle scraping beyond allowed scope",
            description="Keep bundle review within visible, authorized assets.",
            category="explicit_permission_required",
            tags=["frontend", "safety"],
            rationale="Automated collection can exceed intended review scope.",
            safety_note=(
                "Do not perform automated bundle scraping, crawling, or broad collection beyond "
                "the program's allowed scope."
            ),
        ),
    ]


def _item(
    *,
    title: str,
    description: str,
    category: str,
    tags: list[str],
    rationale: str,
    safety_note: str | None = None,
    references: list[str] | None = None,
) -> ChecklistItem:
    return ChecklistItem(
        id=_new_id(),
        title=title,
        description=description,
        category=category,
        tags=tags,
        rationale=rationale,
        safety_note=safety_note
        or "This item is for human review only and is not automatically executed.",
        references=references or [],
        auto_executable=False,
    )


def _has_category_tag(tags: set[str], category: str) -> bool:
    return category in tags


def _dedupe_items(items: list[ChecklistItem]) -> list[ChecklistItem]:
    seen: set[str] = set()
    deduped: list[ChecklistItem] = []
    for item in items:
        if item.title in seen:
            continue
        seen.add(item.title)
        deduped.append(item)
    return deduped


def _new_id() -> str:
    return str(uuid4())

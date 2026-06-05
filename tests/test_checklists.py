from __future__ import annotations

from bb_assistant.core.checklists import ChecklistEngine
from bb_assistant.core.models import Finding
from bb_assistant.core.profiler import TechProfile


def profile(tags: list[str] | None = None) -> TechProfile:
    return TechProfile(
        target_url="https://example.com",
        signals=[],
        summary="Test profile",
        tags=tags or [],
    )


def titles(tags: list[str]) -> list[str]:
    checklist = ChecklistEngine().generate(profile(tags))
    return [item.title for item in checklist.items]


def test_generic_checklist_is_always_generated() -> None:
    checklist = ChecklistEngine().generate(profile(["nginx"]))

    assert checklist.title == "Suggested manual security checklist"
    assert checklist.target_url == "https://example.com"
    assert "Review program policy and target scope before testing" in [
        item.title for item in checklist.items
    ]


def test_all_items_are_not_auto_executable() -> None:
    checklist = ChecklistEngine().generate(profile(["wordpress", "api_route", "auth_surface"]))

    assert all(item.auto_executable is False for item in checklist.items)


def test_all_items_have_safety_note() -> None:
    checklist = ChecklistEngine().generate(profile(["cloudflare", "aws", "react"]))

    assert all(item.safety_note for item in checklist.items)


def test_wordpress_tag_generates_wordpress_items() -> None:
    generated_titles = titles(["wordpress"])

    assert "Review publicly exposed WordPress REST API information" in generated_titles
    assert "Review visible plugin and theme references in page source" in generated_titles
    assert "Avoid account enumeration and login abuse" in generated_titles


def test_api_openapi_tag_generates_api_items() -> None:
    generated_titles = titles(["openapi"])

    assert "Review public API documentation for authentication requirements" in generated_titles
    assert "Map documented endpoints manually" in generated_titles
    assert "Avoid automated endpoint discovery unless explicitly allowed" in generated_titles


def test_auth_surface_generates_auth_items() -> None:
    generated_titles = titles(["auth_surface"])

    assert "Review login page security headers and cookie behavior" in generated_titles
    assert "Check whether MFA is documented or visible" in generated_titles


def test_password_reset_item_requires_explicit_permission() -> None:
    checklist = ChecklistEngine().generate(profile(["auth_surface"]))
    password_reset_items = [
        item for item in checklist.items if "password reset" in item.title.lower()
    ]

    assert password_reset_items
    assert password_reset_items[0].category == "explicit_permission_required"


def test_cloudflare_cdn_tag_generates_cdn_items() -> None:
    generated_titles = titles(["cloudflare"])

    assert "Review CDN and security header interaction" in generated_titles
    assert "Review caching-related response headers" in generated_titles
    assert "Avoid origin or WAF circumvention attempts" in generated_titles


def test_azure_aws_cloud_tag_generates_cloud_items() -> None:
    generated_titles = titles(["azure", "aws"])

    assert "Review public cloud metadata and identity hints" in generated_titles
    assert "Review exposed storage or service URLs only if in scope" in generated_titles
    assert "Avoid tenant or token manipulation" in generated_titles


def test_nextjs_react_tag_generates_frontend_items() -> None:
    generated_titles = titles(["next.js", "react"])

    assert "Review exposed client-side routes and JavaScript bundle references" in generated_titles
    assert "Review whether sensitive values are exposed in public JavaScript" in generated_titles


def test_no_special_tags_generates_only_generic_items() -> None:
    checklist = ChecklistEngine().generate(profile(["nginx"]))

    assert len(checklist.items) == 6


def test_checklist_has_items() -> None:
    checklist = ChecklistEngine().generate(profile())

    assert checklist.has_items() is True


def test_items_by_category() -> None:
    checklist = ChecklistEngine().generate(profile(["auth_surface"]))

    explicit_items = checklist.items_by_category("explicit_permission_required")

    assert explicit_items
    assert all(item.category == "explicit_permission_required" for item in explicit_items)


def test_no_items_are_auto_executable() -> None:
    checklist = ChecklistEngine().generate(
        profile(["wordpress", "openapi", "auth_surface", "cloudflare", "aws", "react"])
    )

    assert not any(item.auto_executable for item in checklist.items)


def test_no_findings_are_created() -> None:
    checklist = ChecklistEngine().generate(profile(["wordpress"]))

    assert not isinstance(checklist, Finding)
    assert all(not isinstance(item, Finding) for item in checklist.items)


def test_no_networkrequests_are_needed() -> None:
    checklist = ChecklistEngine().generate(profile(["api_route"]))

    assert checklist.passive_only is True
    assert checklist.has_items()


def test_safety_terms_only_appear_in_safety_or_avoid_context() -> None:
    checklist = ChecklistEngine().generate(profile(["auth_surface", "cloudflare"]))
    risky_terms = ("exploit", "bruteforce", "bypass", "spraying")

    for item in checklist.items:
        positive_text = f"{item.title} {item.description} {item.rationale}".lower()
        for term in risky_terms:
            assert term not in positive_text
        if any(term in item.safety_note.lower() for term in risky_terms):
            assert "do not" in item.safety_note.lower() or "unless" in item.safety_note.lower()

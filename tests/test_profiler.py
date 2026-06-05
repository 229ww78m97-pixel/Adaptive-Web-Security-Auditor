from __future__ import annotations

import httpx

from bb_assistant.core.models import Finding
from bb_assistant.core.profiler import PassiveTechProfiler, TechSignal


def profile(
    *,
    target_url: str = "https://example.com",
    headers: dict[str, str] | None = None,
    body: str | None = None,
):
    return PassiveTechProfiler().profile_from_response(
        target_url=target_url,
        headers=headers or {},
        body=body,
    )


def test_detects_nginx_from_server_header() -> None:
    result = profile(headers={"Server": "nginx"})

    assert result.has_tag("nginx")
    assert result.signals_by_category("server")[0].confidence == 0.9


def test_detects_cloudflare_from_headers() -> None:
    result = profile(headers={"cf-ray": "abc", "Server": "cloudflare"})

    assert result.has_tag("cloudflare")
    assert result.signals_by_category("cdn")[0].name == "Cloudflare"


def test_detects_azure_from_header() -> None:
    result = profile(headers={"x-azure-ref": "abc"})

    assert result.has_tag("azure")
    assert result.signals_by_category("cloud")[0].name == "Azure"


def test_detects_aws_cloudfront_from_headers() -> None:
    result = profile(headers={"x-amz-cf-id": "abc", "Via": "CloudFront"})

    assert result.has_tag("aws")
    assert result.has_tag("cloudfront")


def test_detects_vercel() -> None:
    result = profile(headers={"x-vercel-id": "fra1::abc"})

    assert result.has_tag("vercel")


def test_detects_netlify() -> None:
    result = profile(headers={"x-nf-request-id": "abc"})

    assert result.has_tag("netlify")


def test_detects_wordpress_from_html() -> None:
    result = profile(body='<script src="/wp-content/theme.js"></script>')

    assert result.has_tag("wordpress")
    assert result.signals_by_category("cms")[0].evidence == "WordPress HTML indicator observed"


def test_detects_nextjs_from_next_data() -> None:
    result = profile(body='<script id="__NEXT_DATA__" type="application/json">{}</script>')

    assert result.has_tag("next.js")


def test_detects_react_root() -> None:
    result = profile(body='<div id="root"></div>')

    assert result.has_tag("react")


def test_detects_api_and_openapi_hints() -> None:
    result = profile(
        target_url="https://example.com/api/users",
        headers={"Content-Type": "application/json"},
        body='<a href="/openapi.json">OpenAPI</a><span>swagger</span>',
    )

    assert result.has_tag("json_api")
    assert result.has_tag("openapi")
    assert result.has_tag("swagger")
    assert result.has_tag("api_route")


def test_detects_login_auth_surface_from_password_input() -> None:
    result = profile(body='<form><input type="password" name="password">Sign in</form>')

    assert result.has_tag("password_form")
    assert result.has_tag("auth_surface")


def test_cookie_values_are_not_stored_only_names() -> None:
    result = profile(headers={"Set-Cookie": "laravel_session=super-secret-value; HttpOnly"})

    assert result.has_tag("laravel")
    assert "super-secret-value" not in str(result.signals)
    assert "laravel_session" in result.signals[0].evidence


def test_confidence_is_between_zero_and_one() -> None:
    result = profile(headers={"Server": "Apache"})

    assert all(0.0 <= signal.confidence <= 1.0 for signal in result.signals)


def test_tech_signal_rejects_invalid_confidence() -> None:
    try:
        TechSignal(
            name="bad",
            category="unknown",
            confidence=1.5,
            evidence="test",
            source="header",
        )
    except ValueError as error:
        assert "confidence" in str(error)
    else:
        raise AssertionError("Expected invalid confidence to be rejected")


def test_passive_only_is_true() -> None:
    result = profile(headers={"Server": "IIS"})

    assert result.passive_only is True
    assert all(signal.passive_only is True for signal in result.signals)


def test_profile_from_http_result_uses_existing_response_without_network() -> None:
    response = httpx.Response(
        200,
        headers={"Server": "nginx"},
        text="<html></html>",
    )

    result = PassiveTechProfiler().profile_from_http_result("https://example.com", response)

    assert result.has_tag("nginx")


def test_no_findings_are_created() -> None:
    result = profile(headers={"Server": "nginx"})

    assert not isinstance(result, Finding)
    assert not hasattr(result, "human_verified")


def test_summary_contains_detected_tags() -> None:
    result = profile(headers={"Server": "nginx", "cf-ray": "abc"})

    assert "Cloudflare" in result.summary
    assert "nginx" in result.summary


def test_no_strong_signals_summary() -> None:
    result = profile()

    assert result.summary == "No strong passive technology signals detected."

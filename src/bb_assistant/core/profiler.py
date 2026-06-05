"""Passive technology profiling from already observed response data."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from html import unescape
from re import IGNORECASE, search
from typing import Protocol
from urllib.parse import urlparse


@dataclass(frozen=True)
class TechSignal:
    name: str
    category: str
    confidence: float
    evidence: str
    source: str
    passive_only: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class TechProfile:
    target_url: str
    signals: list[TechSignal]
    summary: str
    tags: list[str]
    passive_only: bool = True

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def signals_by_category(self, category: str) -> list[TechSignal]:
        return [signal for signal in self.signals if signal.category == category]


class PassiveTechProfiler:
    """Infer conservative technology hints from passive response observations."""

    def profile_from_response(
        self,
        target_url: str,
        headers: Mapping[str, str],
        body: str | None = None,
        status_code: int | None = None,
    ) -> TechProfile:
        normalized_headers = _normalize_headers(headers)
        body_text = body or ""
        lower_body = body_text.lower()
        haystack = " ".join([target_url, *normalized_headers.values()]).lower()
        signals: list[TechSignal] = []

        signals.extend(_server_signals(normalized_headers))
        signals.extend(_cdn_cloud_signals(target_url, normalized_headers, haystack))
        signals.extend(_html_signals(body_text, lower_body))
        signals.extend(_cookie_name_signals(normalized_headers))
        signals.extend(_api_signals(target_url, normalized_headers, lower_body))
        signals.extend(_auth_signals(lower_body))
        if status_code is not None:
            signals.append(
                TechSignal(
                    name=f"HTTP {status_code}",
                    category="unknown",
                    confidence=0.3,
                    evidence=f"Observed response status {status_code}",
                    source="status",
                )
            )

        deduped_signals = _dedupe_signals(signals)
        tags = _tags_from_signals(deduped_signals)
        return TechProfile(
            target_url=target_url,
            signals=deduped_signals,
            summary=_summary(deduped_signals),
            tags=tags,
        )

    def profile_from_http_result(self, target_url: str, response: HttpResponseLike) -> TechProfile:
        headers = response.headers
        body = response.text
        status_code = response.status_code
        return self.profile_from_response(
            target_url=target_url,
            headers=headers,
            body=body,
            status_code=status_code,
        )


class HttpResponseLike(Protocol):
    headers: Mapping[str, str]
    text: str
    status_code: int


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def _server_signals(headers: dict[str, str]) -> list[TechSignal]:
    signals: list[TechSignal] = []
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    for marker, name in (("nginx", "nginx"), ("apache", "Apache"), ("iis", "IIS")):
        if marker in server.lower():
            signals.append(
                TechSignal(
                    name=name,
                    category="server",
                    confidence=0.9,
                    evidence=f"Server header contains {name}",
                    source="header",
                )
            )

    for marker, name, category in (
        ("express", "Express", "framework"),
        ("php", "PHP", "framework"),
        ("asp.net", "ASP.NET", "framework"),
    ):
        if marker in powered_by.lower():
            signals.append(
                TechSignal(
                    name=name,
                    category=category,
                    confidence=0.9,
                    evidence=f"X-Powered-By header contains {name}",
                    source="header",
                )
            )
    return signals


def _cdn_cloud_signals(
    target_url: str,
    headers: dict[str, str],
    haystack: str,
) -> list[TechSignal]:
    signals: list[TechSignal] = []
    server = headers.get("server", "").lower()

    if "cf-ray" in headers or "cf-cache-status" in headers or "cloudflare" in server:
        signals.append(_signal("Cloudflare", "cdn", 0.9, "Cloudflare response header observed"))
    if any(key in headers for key in ("x-azure-ref", "x-ms-request-id", "x-msedge-ref")) or (
        "azurewebsites.net" in haystack
    ):
        signals.append(_signal("Azure", "cloud", 0.9, "Azure response indicator observed"))
    if any(key.startswith("x-amz-") for key in headers) or "cloudfront" in haystack:
        signals.append(_signal("AWS", "cloud", 0.9, "AWS or CloudFront header observed"))
        if "cloudfront" in haystack:
            signals.append(_signal("CloudFront", "cdn", 0.9, "CloudFront indicator observed"))
    if "amazonaws.com" in haystack:
        signals.append(_signal("AWS", "cloud", 0.6, "amazonaws.com observed in URL or header"))
    if "x-vercel-id" in headers or "vercel" in server:
        signals.append(_signal("Vercel", "cloud", 0.9, "Vercel response header observed"))
    if "x-nf-request-id" in headers or "netlify" in server:
        signals.append(_signal("Netlify", "cloud", 0.9, "Netlify response header observed"))
    if "azurewebsites.net" in urlparse(target_url).netloc.lower():
        signals.append(_signal("Azure", "cloud", 0.6, "azurewebsites.net observed in URL"))
    return signals


def _html_signals(body: str, lower_body: str) -> list[TechSignal]:
    signals: list[TechSignal] = []
    if (
        "wp-content" in lower_body
        or "wp-includes" in lower_body
        or "generator wordpress" in lower_body
    ):
        signals.append(
            _signal("WordPress", "cms", 0.8, "WordPress HTML indicator observed", "html")
        )
    if "__next_data__" in lower_body or "/_next/" in lower_body:
        signals.append(
            _signal("Next.js", "framework", 0.8, "Next.js HTML indicator observed", "html")
        )
    if 'id="root"' in lower_body or ("react" in lower_body and ".js" in lower_body):
        signals.append(_signal("React", "framework", 0.6, "React HTML indicator observed", "html"))
    if search(r"<meta[^>]+generator[^>]+wordpress", body, IGNORECASE):
        signals.append(
            _signal("WordPress", "cms", 0.8, "WordPress generator meta tag observed", "html")
        )
    return signals


def _cookie_name_signals(headers: dict[str, str]) -> list[TechSignal]:
    cookie_header = headers.get("set-cookie", "")
    cookie_names = _cookie_names(cookie_header)
    signals: list[TechSignal] = []
    for cookie_name in cookie_names:
        lowered = cookie_name.lower()
        if lowered == "laravel_session":
            signals.append(
                _signal("Laravel", "framework", 0.8, "Cookie name laravel_session observed")
            )
        elif lowered == "csrftoken":
            signals.append(_signal("Django", "framework", 0.8, "Cookie name csrftoken observed"))
        elif lowered.startswith("asp.net") or lowered == ".aspxauth":
            signals.append(
                _signal("ASP.NET", "framework", 0.8, f"Cookie name {cookie_name} observed")
            )
    return signals


def _api_signals(target_url: str, headers: dict[str, str], lower_body: str) -> list[TechSignal]:
    signals: list[TechSignal] = []
    content_type = headers.get("content-type", "").lower()
    url_path = urlparse(target_url).path.lower()
    if "application/json" in content_type:
        signals.append(_signal("JSON API", "api", 0.9, "application/json Content-Type observed"))
    if "openapi.json" in lower_body or "openapi.json" in url_path:
        signals.append(_signal("OpenAPI", "api", 0.8, "openapi.json indicator observed", "html"))
    if "swagger" in lower_body:
        signals.append(_signal("Swagger", "api", 0.8, "Swagger indicator observed", "html"))
    if "/api/" in lower_body or "/api/" in url_path:
        signals.append(_signal("API route", "api", 0.6, "/api/ indicator observed", "url"))
    return signals


def _auth_signals(lower_body: str) -> list[TechSignal]:
    signals: list[TechSignal] = []
    if 'type="password"' in lower_body or "type='password'" in lower_body:
        signals.append(_signal("Password form", "auth", 0.8, "Password input observed", "html"))
    for marker in ("login", "sign in", "oauth", "sso"):
        if marker in lower_body:
            signals.append(
                _signal("Auth surface", "auth", 0.5, f"Text marker '{marker}' observed", "html")
            )
            break
    return signals


def _cookie_names(set_cookie_header: str) -> list[str]:
    if not set_cookie_header:
        return []
    names: list[str] = []
    for raw_cookie in set_cookie_header.split("\n"):
        first_part = raw_cookie.split(";", 1)[0].strip()
        if "=" in first_part:
            names.append(unescape(first_part.split("=", 1)[0].strip()))
    return names


def _signal(
    name: str,
    category: str,
    confidence: float,
    evidence: str,
    source: str = "header",
) -> TechSignal:
    return TechSignal(
        name=name,
        category=category,
        confidence=confidence,
        evidence=evidence,
        source=source,
    )


def _dedupe_signals(signals: list[TechSignal]) -> list[TechSignal]:
    by_key: dict[tuple[str, str], TechSignal] = {}
    for signal in signals:
        key = (signal.name.lower(), signal.category)
        existing = by_key.get(key)
        if existing is None or signal.confidence > existing.confidence:
            by_key[key] = signal
    return list(by_key.values())


def _tags_from_signals(signals: list[TechSignal]) -> list[str]:
    tags = {signal.name.lower().replace(" ", "_") for signal in signals}
    if any(signal.category == "auth" for signal in signals):
        tags.add("auth_surface")
    return sorted(tags)


def _summary(signals: list[TechSignal]) -> str:
    if not signals:
        return "No strong passive technology signals detected."

    prioritized = sorted(signals, key=lambda signal: signal.confidence, reverse=True)[:5]
    names = ", ".join(signal.name for signal in prioritized)
    return f"Detected passive technology signals: {names}."

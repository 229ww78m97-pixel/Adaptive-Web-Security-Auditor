"""Passive Set-Cookie flag check that avoids storing cookie values."""

from __future__ import annotations

from bb_assistant.core.checks.base import CheckResult, CheckStatus, SafetyCategory
from bb_assistant.core.http_client import SafeHttpClient

REQUIRED_COOKIE_FLAGS = ("Secure", "HttpOnly", "SameSite")


class CookieFlagsCheck:
    name = "cookie_flags"
    safety_category = SafetyCategory.PASSIVE

    def run(self, target_url: str, client: SafeHttpClient) -> CheckResult:
        response = client.get(target_url, check_type=self.name)
        cookie_headers = response.headers.get_list("set-cookie")
        if not cookie_headers:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.INFO,
                summary="No Set-Cookie headers observed",
                details={
                    "cookies_checked": 0,
                    "missing_flags_by_cookie": {},
                    "raw_cookie_names_only": [],
                },
                affected_url=str(response.url),
                needs_manual_review=False,
            )

        missing_flags_by_cookie: dict[str, list[str]] = {}
        cookie_names: list[str] = []
        for raw_cookie in cookie_headers:
            cookie_name, observed_flags = _parse_cookie_metadata(raw_cookie)
            cookie_names.append(cookie_name)
            missing_flags = [
                flag for flag in REQUIRED_COOKIE_FLAGS if flag.lower() not in observed_flags
            ]
            if missing_flags:
                missing_flags_by_cookie[cookie_name] = missing_flags

        details = {
            "cookies_checked": len(cookie_headers),
            "missing_flags_by_cookie": missing_flags_by_cookie,
            "raw_cookie_names_only": cookie_names,
        }
        if not missing_flags_by_cookie:
            return CheckResult(
                check_name=self.name,
                status=CheckStatus.PASS,
                summary="All observed cookies include Secure, HttpOnly, and SameSite",
                details=details,
                affected_url=str(response.url),
                needs_manual_review=False,
            )

        return CheckResult(
            check_name=self.name,
            status=CheckStatus.INFO,
            summary="Some cookies are missing recommended flags",
            details=details,
            affected_url=str(response.url),
            severity_hint="low",
            needs_manual_review=True,
        )


def _parse_cookie_metadata(raw_cookie: str) -> tuple[str, set[str]]:
    parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"
    flags: set[str] = set()
    for attribute in parts[1:]:
        key = attribute.split("=", 1)[0].strip().lower()
        if key:
            flags.add(key)
    return name, flags

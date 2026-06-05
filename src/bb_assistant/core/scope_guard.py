"""Default-deny scope validation for all outbound target access."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from urllib.parse import urljoin, urlparse

from bb_assistant.core.models import AssetType, ScopeRule


class OutOfScopeError(ValueError):
    """Raised when a URL is not explicitly allowed by the program scope."""


@dataclass(frozen=True)
class ScopeDecision:
    url: str
    in_scope: bool
    matched_rule: ScopeRule | None
    reason: str


class ScopeGuard:
    """Validate URLs against in-scope and out-of-scope rules.

    Matching is intentionally conservative:
    * out-of-scope rules win over in-scope rules
    * missing rules mean deny
    * wildcard domains match subdomains only, not the apex domain
    """

    def __init__(self, rules: list[ScopeRule]) -> None:
        self._rules = rules

    def validate(self, url: str) -> ScopeDecision:
        decision = self.evaluate(url)
        if not decision.in_scope:
            raise OutOfScopeError(decision.reason)
        return decision

    def validate_redirect(self, source_url: str, location: str) -> ScopeDecision:
        redirect_url = urljoin(source_url, location)
        return self.validate(redirect_url)

    def evaluate(self, url: str) -> ScopeDecision:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ScopeDecision(url=url, in_scope=False, matched_rule=None, reason="invalid URL")

        out_of_scope_rule = self._first_matching_rule(url, want_in_scope=False)
        if out_of_scope_rule is not None:
            return ScopeDecision(
                url=url,
                in_scope=False,
                matched_rule=out_of_scope_rule,
                reason=f"blocked by out-of-scope rule: {out_of_scope_rule.value}",
            )

        in_scope_rule = self._first_matching_rule(url, want_in_scope=True)
        if in_scope_rule is None:
            return ScopeDecision(
                url=url,
                in_scope=False,
                matched_rule=None,
                reason="no in-scope rule matched",
            )

        return ScopeDecision(
            url=url,
            in_scope=True,
            matched_rule=in_scope_rule,
            reason=f"allowed by in-scope rule: {in_scope_rule.value}",
        )

    def _first_matching_rule(self, url: str, *, want_in_scope: bool) -> ScopeRule | None:
        for rule in self._rules:
            if rule.in_scope is want_in_scope and self._matches(rule, url):
                return rule
        return None

    def _matches(self, rule: ScopeRule, url: str) -> bool:
        parsed = urlparse(url)
        host = _normalize_hostname(parsed.hostname)
        if host is None:
            return False

        match rule.asset_type:
            case AssetType.DOMAIN:
                return host == _normalize_scope_host(rule.value)
            case AssetType.WILDCARD:
                return _matches_wildcard(host, rule.value)
            case AssetType.URL:
                return _normalize_url_prefix(url).startswith(_normalize_url_prefix(rule.value))
            case AssetType.IP:
                return _matches_ip(host, rule.value)
            case AssetType.CIDR:
                return _matches_cidr(host, rule.value)


def _normalize_hostname(hostname: str | None) -> str | None:
    if hostname is None:
        return None
    return hostname.lower().rstrip(".")


def _normalize_scope_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    return host.lower().rstrip(".")


def _matches_wildcard(host: str, pattern: str) -> bool:
    normalized = pattern.strip().lower().rstrip(".")
    if not normalized.startswith("*."):
        return False

    suffix = normalized[1:]
    apex = normalized[2:]
    return host != apex and host.endswith(suffix)


def _normalize_url_prefix(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return value.rstrip("/")

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower().rstrip(".")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def _matches_ip(host: str, value: str) -> bool:
    try:
        return ip_address(host) == ip_address(value.strip())
    except ValueError:
        return False


def _matches_cidr(host: str, value: str) -> bool:
    try:
        return ip_address(host) in ip_network(value.strip(), strict=False)
    except ValueError:
        return False

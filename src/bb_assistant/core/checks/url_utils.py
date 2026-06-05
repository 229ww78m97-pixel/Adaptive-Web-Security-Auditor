"""URL helpers for passive checks."""

from __future__ import annotations

from urllib.parse import urlparse


def origin_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("target_url must be an absolute URL")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

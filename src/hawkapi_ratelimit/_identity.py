"""Identity functions — how to derive a rate-limit key from a Request."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any


def _parse_xff(raw: str) -> str:
    """Return the left-most ``X-Forwarded-For`` token, IP-only."""
    first = raw.split(",", 1)[0].strip()
    if not first:
        return ""
    # Strip [::1]:8080 → ::1; 192.0.2.1:443 → 192.0.2.1
    if first.startswith("[") and "]" in first:
        first = first.split("]", 1)[0][1:]
    elif first.count(":") == 1:
        first = first.split(":", 1)[0]
    return _normalize_ip(first)


def _normalize_ip(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return raw  # leave malformed strings as-is; caller can still key on them
    return str(ip)


def ip_key(*, trusted_proxy: bool = False) -> Callable[[Any], str]:
    """Identity = client IP.

    When ``trusted_proxy=True``, the left-most token of ``X-Forwarded-For`` is
    used (the original client). When ``False``, the socket peer address is used.
    Documented: only enable ``trusted_proxy=True`` if your edge sets a single
    canonical ``X-Forwarded-For`` and strips any inbound value.
    """

    def _fn(request: Any) -> str:
        if trusted_proxy:
            raw = ""
            headers = getattr(request, "headers", None)
            if headers is not None:
                try:
                    raw = headers.get("x-forwarded-for", "") or ""
                except Exception:
                    raw = ""
            if raw:
                return f"ip:{_parse_xff(raw)}"
        # Fall back to peer address.
        client = getattr(request, "client", None)
        host = ""
        if client is not None:
            host = getattr(client, "host", "") or ""
        if not host:
            scope = getattr(request, "scope", None)
            if scope is not None:
                client_pair = scope.get("client")
                if client_pair:
                    host = str(client_pair[0])
        return f"ip:{_normalize_ip(host)}"

    return _fn


def user_key(*, attribute: str = "user_id", scope_key: str = "user") -> Callable[[Any], str]:
    """Identity = post-auth user identifier.

    WARNING: unauthenticated requests (``user is None``) all map to the shared
    key ``"user:anon"``. A single attacker can exhaust the anonymous budget,
    denying service to all other unauthenticated users on that endpoint.
    Mitigate by combining with :func:`ip_key` via :func:`composite_key`, or
    by restricting the endpoint to authenticated users only.
    """

    def _fn(request: Any) -> str:
        scope = getattr(request, "scope", {}) or {}
        user = scope.get(scope_key)
        if user is None:
            return "user:anon"
        if isinstance(user, dict):
            return f"user:{user.get(attribute, 'anon')}"
        return f"user:{getattr(user, attribute, 'anon')}"

    return _fn


def header_key(header: str, *, prefix: str = "h") -> Callable[[Any], str]:
    """Identity = a header value (e.g. API key)."""

    h = header.lower()

    def _fn(request: Any) -> str:
        headers = getattr(request, "headers", None)
        value = ""
        if headers is not None:
            try:
                value = headers.get(h, "") or ""
            except Exception:
                value = ""
        return f"{prefix}:{value}"

    return _fn


def api_key() -> Callable[[Any], str]:
    """Convenience — read ``Authorization: Bearer <token>`` and use the token."""

    def _fn(request: Any) -> str:
        headers = getattr(request, "headers", None)
        value = ""
        if headers is not None:
            try:
                value = headers.get("authorization", "") or ""
            except Exception:
                value = ""
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        return f"apikey:{value}"

    return _fn


def composite_key(*identities: Callable[[Any], str]) -> Callable[[Any], str]:
    """Combine multiple identities into one key (e.g. ``ip+user``)."""

    def _fn(request: Any) -> str:
        return "|".join(fn(request) for fn in identities)

    return _fn


__all__ = [
    "api_key",
    "composite_key",
    "header_key",
    "ip_key",
    "user_key",
]

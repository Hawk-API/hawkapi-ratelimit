"""Global rate-limit middleware applying a default policy."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ._base import IdentityFn, RateLimit
from ._identity import ip_key
from ._plugin import resolve_limiter


@dataclass
class RateLimitMiddleware:
    app: Any
    limit: RateLimit | None = None
    identity: IdentityFn = field(default_factory=ip_key)
    exclude_paths: Iterable[str] = field(default_factory=tuple)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        # Exact-match OR true sub-path. Plain ``startswith()`` would let
        # ``/healthz`` bypass an ``/health`` exclusion (CWE-284).
        if any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.exclude_paths):
            await self.app(scope, receive, send)
            return
        if self.limit is None:
            await self.app(scope, receive, send)
            return
        # The middleware has no Request object; build a thin shim for identity().
        shim = _RequestShim(scope)
        limiter = resolve_limiter(scope.get("app"))
        if limiter is None:
            await self.app(scope, receive, send)
            return
        key = self.identity(shim)
        result = await limiter.hit(key, self.limit)
        if not result.allowed:
            payload = json.dumps(
                {"detail": "rate limit exceeded", "retry_after": result.retry_after}
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"x-ratelimit-limit", str(self.limit.rate).encode()),
                        (b"x-ratelimit-remaining", b"0"),
                        (b"x-ratelimit-reset", str(int(result.reset_at)).encode()),
                        (b"retry-after", str(int(result.retry_after) or 1).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return
        await self.app(scope, receive, send)


@dataclass(slots=True)
class _RequestShim:
    """Minimal Request-like object so :class:`IdentityFn` can read headers + client."""

    scope: dict[str, Any]

    @property
    def headers(self) -> dict[str, str]:
        raw = self.scope.get("headers", []) or []
        return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw}

    @property
    def client(self) -> Any:
        pair = self.scope.get("client")
        if pair is None:
            return None
        return _Client(host=str(pair[0]))


@dataclass(slots=True)
class _Client:
    host: str


__all__ = ["RateLimitMiddleware"]

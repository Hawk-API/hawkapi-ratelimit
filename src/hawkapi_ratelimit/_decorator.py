"""@rate_limit decorator for individual handlers."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from hawkapi import Request
from hawkapi.responses import JSONResponse, Response

from ._base import IdentityFn, LimitResult, RateLimit
from ._identity import ip_key
from ._plugin import resolve_limiter


def _rl_headers(result: LimitResult, limit: RateLimit) -> dict[str, str]:
    headers: dict[str, str] = {
        "x-ratelimit-limit": str(limit.rate),
        "x-ratelimit-remaining": str(max(0, result.remaining)),
        "x-ratelimit-reset": str(int(result.reset_at)),
    }
    if not result.allowed:
        headers["retry-after"] = str(int(result.retry_after) or 1)
    return headers


def _attach_headers(resp: Any, extra: dict[str, str]) -> None:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return
    try:
        for k, v in extra.items():
            headers[k] = v
    except Exception:
        pass


def rate_limit(
    *,
    rate: int,
    per: float,
    burst: int = 0,
    identity: IdentityFn | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a handler with a rate budget.

    Identity defaults to ``ip_key(trusted_proxy=False)``. Use ``user_key()`` or
    ``composite_key(ip_key(), user_key())`` for per-user / per-IP+user limits.
    """
    limit = RateLimit(rate=rate, per=per, burst=burst)
    identity_fn = identity or ip_key()

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)
        request_param = next(
            (
                p.name
                for p in sig.parameters.values()
                if p.annotation is Request or p.name == "request"
            ),
            None,
        )
        if request_param is None:
            # Surface this loudly at decoration time so a developer who forgot
            # the ``Request`` parameter discovers it during import, not when an
            # attacker discovers their endpoint has no real rate limit.
            import warnings

            warnings.warn(
                f"@rate_limit on {fn.__qualname__!r} has no Request parameter — "
                "rate limiting will be silently skipped for every call.",
                UserWarning,
                stacklevel=2,
            )

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request = kwargs.get(request_param) if request_param else None
            if request is None:
                # Find the Request positionally.
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            if request is None:
                # No Request available — skip the check (we can't key on it).
                return await fn(*args, **kwargs)
            limiter = resolve_limiter(request.scope.get("app"))
            if limiter is None:
                return await fn(*args, **kwargs)
            key = identity_fn(request)
            result = await limiter.hit(key, limit)
            extra = _rl_headers(result, limit)
            if not result.allowed:
                return JSONResponse(
                    {"detail": "rate limit exceeded", "retry_after": result.retry_after},
                    status_code=429,
                    headers=extra,
                )
            response = await fn(*args, **kwargs)
            # Wrap raw dict / list / scalar returns so we can attach headers.
            if not isinstance(response, Response):
                response = JSONResponse(response, headers=extra)
            else:
                _attach_headers(response, extra)
            return response

        return wrapper

    return decorator


__all__ = ["rate_limit"]

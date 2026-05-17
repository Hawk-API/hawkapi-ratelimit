"""hawkapi-ratelimit — rate limiting for HawkAPI.

Two algorithms (token bucket + sliding window), two backends (in-memory +
Redis Lua). Identity strategies: IP / user / API-key / composite. Decorator
or middleware. Standard ``X-RateLimit-*`` + ``Retry-After`` headers.
"""

from __future__ import annotations

from ._base import IdentityFn, Limiter, LimitResult, RateLimit
from ._decorator import rate_limit
from ._identity import api_key, composite_key, header_key, ip_key, user_key
from ._memory import MemoryLimiter
from ._middleware import RateLimitMiddleware
from ._plugin import get_limiter, init_ratelimit, resolve_limiter
from ._redis import RedisLimiter

__version__ = "0.1.0"

__all__ = [
    "IdentityFn",
    "LimitResult",
    "Limiter",
    "MemoryLimiter",
    "RateLimit",
    "RateLimitMiddleware",
    "RedisLimiter",
    "__version__",
    "api_key",
    "composite_key",
    "get_limiter",
    "header_key",
    "init_ratelimit",
    "ip_key",
    "rate_limit",
    "resolve_limiter",
    "user_key",
]

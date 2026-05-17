"""Base types for rate-limiting."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(slots=True)
class RateLimit:
    """A rate budget. ``rate`` requests per ``per`` seconds, with optional burst."""

    rate: int
    per: float
    burst: int = 0

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be > 0")
        if self.per <= 0:
            raise ValueError("per must be > 0")
        if self.burst < 0:
            raise ValueError("burst must be >= 0")
        if self.burst == 0:
            # Default burst = rate (token bucket interpretation).
            object.__setattr__(self, "burst", self.rate)


@dataclass(slots=True)
class LimitResult:
    """Outcome of a single rate-limit check."""

    allowed: bool
    remaining: int
    reset_at: float
    """Unix timestamp when the budget resets."""

    retry_after: float = 0.0
    """Suggested ``Retry-After`` value in seconds; 0 when ``allowed``."""


# Identity functions take a HawkAPI Request and return an opaque key string.
IdentityFn = Callable[[Any], str]


class Limiter(Protocol):
    """The minimal contract every backend implements."""

    name: str

    async def hit(self, key: str, limit: RateLimit, *, now: float | None = None) -> LimitResult: ...

    async def reset(self, key: str) -> None: ...

    async def close(self) -> None: ...


# Type alias used by decorator + middleware.
LimitFn = Callable[[Any], Awaitable[LimitResult]]


__all__ = ["IdentityFn", "LimitFn", "LimitResult", "Limiter", "RateLimit"]

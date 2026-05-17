"""In-memory limiter — token bucket + sliding window."""

from __future__ import annotations

import asyncio
import heapq
import time
from collections import deque
from dataclasses import dataclass, field

from ._base import LimitResult, RateLimit


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass
class MemoryLimiter:
    """Single-process limiter. Two strategies share the same store."""

    name: str = "memory"
    strategy: str = "token_bucket"
    """``"token_bucket"`` (smoothed) or ``"sliding_window"`` (precise)."""

    max_keys: int = 100_000
    """Prune oldest keys when the store grows beyond this."""

    _buckets: dict[str, _Bucket] = field(default_factory=dict, init=False)
    _windows: dict[str, deque[float]] = field(default_factory=dict, init=False)
    _last_access: dict[str, float] = field(default_factory=dict, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        if self.strategy not in {"token_bucket", "sliding_window"}:
            raise ValueError(
                f"strategy must be 'token_bucket' or 'sliding_window'; got {self.strategy!r}"
            )

    async def hit(self, key: str, limit: RateLimit, *, now: float | None = None) -> LimitResult:
        now = now if now is not None else time.time()
        # Cap key length to bound memory; a 256-char limit is more than enough
        # for any realistic identity (IP + user_id + route).
        if len(key) > 256:
            key = key[:256]
        async with self._lock:
            self._last_access[key] = now
            if len(self._last_access) > self.max_keys:
                self._evict_locked(now, limit)
            if self.strategy == "token_bucket":
                return self._token_bucket_locked(key, limit, now)
            return self._sliding_window_locked(key, limit, now)

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._buckets.pop(key, None)
            self._windows.pop(key, None)
            self._last_access.pop(key, None)

    async def close(self) -> None:
        return None

    # ----- helpers ---------------------------------------------------------- #

    def _token_bucket_locked(self, key: str, limit: RateLimit, now: float) -> LimitResult:
        refill_rate = limit.rate / limit.per
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=float(limit.burst), last_refill=now)
            self._buckets[key] = bucket
        elapsed = max(0.0, now - bucket.last_refill)
        bucket.tokens = min(float(limit.burst), bucket.tokens + elapsed * refill_rate)
        bucket.last_refill = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            remaining = int(bucket.tokens)
            return LimitResult(
                allowed=True,
                remaining=remaining,
                reset_at=now + ((limit.burst - bucket.tokens) / refill_rate),
                retry_after=0.0,
            )
        retry_after = (1.0 - bucket.tokens) / refill_rate
        return LimitResult(
            allowed=False,
            remaining=0,
            reset_at=now + retry_after,
            retry_after=retry_after,
        )

    def _sliding_window_locked(self, key: str, limit: RateLimit, now: float) -> LimitResult:
        window = self._windows.get(key)
        if window is None:
            window = deque()
            self._windows[key] = window
        cutoff = now - limit.per
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= limit.rate:
            oldest = window[0]
            retry_after = max(0.0, oldest + limit.per - now)
            return LimitResult(
                allowed=False,
                remaining=0,
                reset_at=oldest + limit.per,
                retry_after=retry_after,
            )
        window.append(now)
        return LimitResult(
            allowed=True,
            remaining=limit.rate - len(window),
            reset_at=window[0] + limit.per,
            retry_after=0.0,
        )

    def _evict_locked(self, now: float, limit: RateLimit) -> None:
        # Drop the oldest 10% of entries to make room. ``heapq.nsmallest`` is
        # O(N + drop·log N) — avoids the O(N log N) full sort that would
        # block the limiter's global lock for tens of milliseconds at the
        # ``max_keys=100_000`` ceiling.
        drop = max(1, len(self._last_access) // 10)
        oldest = heapq.nsmallest(drop, self._last_access.items(), key=lambda kv: kv[1])
        for k, _ts in oldest:
            self._buckets.pop(k, None)
            self._windows.pop(k, None)
            self._last_access.pop(k, None)
        _ = (now, limit)  # signature parity; not used in eviction.


__all__ = ["MemoryLimiter"]

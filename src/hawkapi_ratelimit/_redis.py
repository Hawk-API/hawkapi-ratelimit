"""Redis-backed limiter — atomic check-and-increment via Lua."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from ._base import LimitResult, RateLimit

# Token bucket: atomically refill + consume.
# KEYS[1] = bucket key (HASH { tokens, last_refill })
# ARGV: rate, per, burst, now
_TOKEN_BUCKET_LUA = """
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local last = tonumber(redis.call('HGET', KEYS[1], 'last_refill'))
local rate = tonumber(ARGV[1])
local per = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local refill_rate = rate / per

if tokens == nil then
  tokens = burst
  last = now
end

local elapsed = math.max(0, now - last)
tokens = math.min(burst, tokens + elapsed * refill_rate)

local allowed = 0
local retry_after = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry_after = (1 - tokens) / refill_rate
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill', now)
redis.call('EXPIRE', KEYS[1], math.ceil(per * 2))
return { allowed, tostring(tokens), tostring(retry_after) }
"""

# Sliding window: ZSET of timestamps. Trim then count.
# KEYS[1] = window key (ZSET)
# ARGV: rate, per, now, unique_member
_SLIDING_WINDOW_LUA = """
local rate = tonumber(ARGV[1])
local per = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - per
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local count = redis.call('ZCARD', KEYS[1])
local allowed = 0
local retry_after = 0
local oldest = now
if count < rate then
  redis.call('ZADD', KEYS[1], now, member)
  redis.call('EXPIRE', KEYS[1], math.ceil(per * 2))
  count = count + 1
  allowed = 1
else
  local first = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  if first[2] ~= nil then
    oldest = tonumber(first[2])
    retry_after = math.max(0, oldest + per - now)
  end
end
return { allowed, tostring(rate - count), tostring(retry_after), tostring(oldest) }
"""


@dataclass
class RedisLimiter:
    """Cluster-safe limiter backed by Redis Lua scripts."""

    url: str = "redis://localhost:6379/0"
    name: str = "redis"
    strategy: str = "token_bucket"
    key_prefix: str = "hawkapi:rl:"
    socket_timeout: float = 0.2
    fail_closed: bool = False
    """When True, Redis errors deny the request. Default False — allow on error
    (fail-open) and log a warning. Choose ``fail_closed=True`` for endpoints
    where rate-limit MUST hold (admin / payment)."""

    _client: Any = field(default=None, init=False)
    _bucket_sha: str = field(default="", init=False)
    _window_sha: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if self.strategy not in {"token_bucket", "sliding_window"}:
            raise ValueError(
                f"strategy must be 'token_bucket' or 'sliding_window'; got {self.strategy!r}"
            )

    async def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import redis.asyncio as redis  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise ImportError("redis is required; pip install 'hawkapi-ratelimit[redis]'") from exc
        self._client = redis.from_url(
            self.url,
            socket_timeout=self.socket_timeout,
            socket_connect_timeout=self.socket_timeout,
            decode_responses=False,
        )
        self._bucket_sha = await self._client.script_load(_TOKEN_BUCKET_LUA)
        self._window_sha = await self._client.script_load(_SLIDING_WINDOW_LUA)
        return self._client

    async def hit(self, key: str, limit: RateLimit, *, now: float | None = None) -> LimitResult:
        if len(key) > 256:
            key = key[:256]
        now = now if now is not None else time.time()
        try:
            client = await self._get_client()
            full = self.key_prefix + key
            if self.strategy == "token_bucket":
                result = await client.evalsha(
                    self._bucket_sha,
                    1,
                    full,
                    str(limit.rate),
                    str(limit.per),
                    str(limit.burst),
                    f"{now:.6f}",
                )
                allowed = bool(int(result[0]))
                tokens = float(result[1])
                retry = float(result[2])
                return LimitResult(
                    allowed=allowed,
                    remaining=int(tokens),
                    reset_at=now + retry,
                    retry_after=retry,
                )
            # sliding window
            # Random suffix prevents ZADD score collisions when two concurrent
            # requests hit the same microsecond — id() would reuse addresses
            # after GC and silently undercount.
            member = f"{now:.6f}-{os.urandom(8).hex()}"
            result = await client.evalsha(
                self._window_sha,
                1,
                full,
                str(limit.rate),
                str(limit.per),
                f"{now:.6f}",
                member,
            )
            allowed = bool(int(result[0]))
            remaining = max(0, int(float(result[1])))
            retry = float(result[2])
            oldest = float(result[3])
            return LimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_at=oldest + limit.per,
                retry_after=retry,
            )
        except Exception as exc:
            if self.fail_closed:
                raise
            import logging

            logging.getLogger("hawkapi_ratelimit").warning(
                "redis limiter error — request ALLOWED despite Redis failure "
                "(fail_closed=False; set fail_closed=True on admin/payment routes "
                "to deny instead): %s",
                exc,
            )
            # Fail open — count the request as allowed but report 0 remaining.
            return LimitResult(allowed=True, remaining=0, reset_at=now + limit.per)

    async def reset(self, key: str) -> None:
        if not self._client:
            return
        full = self.key_prefix + key
        try:
            await self._client.delete(full)
        except Exception:
            pass

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None


__all__ = ["RedisLimiter"]

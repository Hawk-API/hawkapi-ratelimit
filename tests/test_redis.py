"""RedisLimiter — Lua scripts mocked via a fake client.

This does NOT spin up a real Redis. We only verify the call shape + fail-open
behaviour. Lua semantics are covered by a real-Redis integration suite that
lives outside CI (gated on a REDIS_URL env var); the unit test below uses a
fake to validate that the limiter wires up the correct script + arguments.
"""

from __future__ import annotations

import pytest

from hawkapi_ratelimit import RateLimit, RedisLimiter


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def script_load(self, _src: str) -> str:
        return "sha-stub"

    async def evalsha(self, sha: str, keys: int, *args: object) -> list[bytes]:
        self.calls.append((sha, args))
        # Token bucket return shape: [allowed, tokens, retry_after]
        return [1, b"4", b"0"]

    async def delete(self, _key: str) -> int:
        return 1

    async def aclose(self) -> None:
        return None


def test_unknown_strategy_rejected() -> None:
    with pytest.raises(ValueError, match="strategy"):
        RedisLimiter(strategy="bogus")


class _BrokenClient:
    async def evalsha(self, *_a: object, **_kw: object) -> object:
        raise RuntimeError("simulated redis failure")

    async def aclose(self) -> None:
        return None

    async def delete(self, *_a: object) -> int:
        return 0


async def test_fail_open_allows_when_redis_errors() -> None:
    """Default ``fail_closed=False`` — Redis errors do NOT block traffic."""
    lim = RedisLimiter(url="redis://stub", fail_closed=False)
    lim._client = _BrokenClient()  # bypass lazy init
    lim._bucket_sha = "sha-stub"
    r = await lim.hit("k", RateLimit(rate=10, per=60), now=100.0)
    assert r.allowed is True
    assert r.remaining == 0  # signal that the limiter could not evaluate


async def test_fail_closed_raises_on_error() -> None:
    """``fail_closed=True`` — Redis errors propagate so the caller can 503."""
    lim = RedisLimiter(url="redis://stub", fail_closed=True)
    lim._client = _BrokenClient()
    lim._bucket_sha = "sha-stub"
    with pytest.raises(RuntimeError, match="simulated"):
        await lim.hit("k", RateLimit(rate=10, per=60), now=100.0)


async def test_token_bucket_call_shape() -> None:
    lim = RedisLimiter(strategy="token_bucket")
    fake = _FakeClient()
    lim._client = fake
    lim._bucket_sha = "sha-stub"
    r = await lim.hit("user:1", RateLimit(rate=10, per=60, burst=20), now=100.0)
    assert r.allowed is True
    assert r.remaining == 4
    assert fake.calls
    sha, args = fake.calls[0]
    assert sha == "sha-stub"
    # Args after the key: rate, per, burst, now
    # KEYS[1] is consumed by evalsha; the first three ARGV are rate, per, burst.
    assert args[1:5] == ("10", "60", "20", "100.000000")

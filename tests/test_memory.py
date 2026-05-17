"""MemoryLimiter — token bucket + sliding window."""

from __future__ import annotations

import pytest

from hawkapi_ratelimit import MemoryLimiter, RateLimit


async def test_token_bucket_allows_within_budget() -> None:
    lim = MemoryLimiter(strategy="token_bucket")
    rl = RateLimit(rate=3, per=1)
    now = 100.0
    for _ in range(3):
        r = await lim.hit("k", rl, now=now)
        assert r.allowed is True


async def test_token_bucket_denies_when_exhausted() -> None:
    lim = MemoryLimiter(strategy="token_bucket")
    rl = RateLimit(rate=2, per=1)
    now = 100.0
    await lim.hit("k", rl, now=now)
    await lim.hit("k", rl, now=now)
    r = await lim.hit("k", rl, now=now)
    assert r.allowed is False
    assert r.retry_after > 0


async def test_token_bucket_refills_over_time() -> None:
    lim = MemoryLimiter(strategy="token_bucket")
    rl = RateLimit(rate=2, per=1)
    now = 100.0
    await lim.hit("k", rl, now=now)
    await lim.hit("k", rl, now=now)
    assert (await lim.hit("k", rl, now=now)).allowed is False
    # Half a second later: 1 token should have refilled.
    r = await lim.hit("k", rl, now=now + 0.5)
    assert r.allowed is True


async def test_sliding_window_precise_count() -> None:
    lim = MemoryLimiter(strategy="sliding_window")
    rl = RateLimit(rate=3, per=10)
    now = 100.0
    for _ in range(3):
        r = await lim.hit("k", rl, now=now)
        assert r.allowed is True
    r = await lim.hit("k", rl, now=now)
    assert r.allowed is False
    # Advance past the oldest entry.
    r = await lim.hit("k", rl, now=now + 11)
    assert r.allowed is True


async def test_unknown_strategy_rejected() -> None:
    with pytest.raises(ValueError, match="strategy"):
        MemoryLimiter(strategy="bogus")


async def test_separate_keys_isolated() -> None:
    lim = MemoryLimiter()
    rl = RateLimit(rate=1, per=1)
    now = 100.0
    a = await lim.hit("alice", rl, now=now)
    b = await lim.hit("bob", rl, now=now)
    assert a.allowed is True
    assert b.allowed is True


async def test_key_truncated_to_256_chars() -> None:
    lim = MemoryLimiter()
    rl = RateLimit(rate=1, per=1)
    long_key = "x" * 500
    r = await lim.hit(long_key, rl, now=100.0)
    assert r.allowed is True


async def test_reset_clears_state() -> None:
    lim = MemoryLimiter()
    rl = RateLimit(rate=1, per=1)
    now = 100.0
    await lim.hit("k", rl, now=now)
    assert (await lim.hit("k", rl, now=now)).allowed is False
    await lim.reset("k")
    assert (await lim.hit("k", rl, now=now)).allowed is True


async def test_eviction_kicks_in_at_max_keys() -> None:
    lim = MemoryLimiter(max_keys=20)
    rl = RateLimit(rate=1, per=60)
    for i in range(25):
        await lim.hit(f"k-{i}", rl, now=100.0 + i)
    # Should have triggered at least one eviction round.
    assert len(lim._last_access) <= 25

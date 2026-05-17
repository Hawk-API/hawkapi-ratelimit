"""RateLimit + LimitResult shape."""

from __future__ import annotations

import pytest

from hawkapi_ratelimit import LimitResult, RateLimit


def test_ratelimit_defaults_burst_to_rate() -> None:
    rl = RateLimit(rate=10, per=60)
    assert rl.burst == 10


def test_ratelimit_explicit_burst() -> None:
    rl = RateLimit(rate=10, per=60, burst=20)
    assert rl.burst == 20


def test_ratelimit_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError, match="rate"):
        RateLimit(rate=0, per=60)
    with pytest.raises(ValueError, match="rate"):
        RateLimit(rate=-1, per=60)


def test_ratelimit_rejects_non_positive_per() -> None:
    with pytest.raises(ValueError, match="per"):
        RateLimit(rate=1, per=0)
    with pytest.raises(ValueError, match="per"):
        RateLimit(rate=1, per=-1)


def test_ratelimit_rejects_negative_burst() -> None:
    with pytest.raises(ValueError, match="burst"):
        RateLimit(rate=1, per=1, burst=-1)


def test_limit_result_shape() -> None:
    r = LimitResult(allowed=True, remaining=5, reset_at=12345.0)
    assert r.allowed is True
    assert r.remaining == 5
    assert r.retry_after == 0.0

"""init_ratelimit + DI."""

from __future__ import annotations

from typing import Any

from hawkapi import Depends, HawkAPI
from hawkapi.testing import TestClient

from hawkapi_ratelimit import (
    MemoryLimiter,
    get_limiter,
    init_ratelimit,
    resolve_limiter,
)


def test_init_attaches_limiter() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    lim = init_ratelimit(app)
    assert app.state.limiter is lim
    assert isinstance(lim, MemoryLimiter)


def test_resolve_falls_back_to_last() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)
    assert resolve_limiter(None) is not None


def test_get_limiter_dep_returns_limiter() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)

    @app.get("/info")
    async def info(lim: MemoryLimiter = Depends(get_limiter)) -> dict[str, Any]:
        return {"name": lim.name}

    client = TestClient(app)
    r = client.get("/info")
    assert r.status_code == 200
    assert r.json()["name"] == "memory"


def test_get_limiter_500_when_missing() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)

    @app.get("/x")
    async def x(lim: MemoryLimiter = Depends(get_limiter)) -> dict[str, Any]:
        return {"ok": True}

    import hawkapi_ratelimit._plugin as _p

    saved = _p._LAST[0]
    _p._LAST[0] = None
    _p._ACTIVE.pop(app, None)
    try:
        r = TestClient(app).get("/x")
        assert r.status_code == 500
    finally:
        _p._LAST[0] = saved

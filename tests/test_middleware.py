"""RateLimitMiddleware — global policy + exclude_paths."""

from __future__ import annotations

from typing import Any

from hawkapi import HawkAPI
from hawkapi.testing import TestClient

from hawkapi_ratelimit import RateLimit, RateLimitMiddleware, init_ratelimit


def _build(limit: RateLimit | None, *, exclude: tuple[str, ...] = ()) -> HawkAPI:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)
    app.add_middleware(RateLimitMiddleware, limit=limit, exclude_paths=exclude)

    @app.get("/a")
    async def a() -> dict[str, Any]:
        return {"path": "a"}

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True}

    return app


def test_middleware_with_no_limit_is_passthrough() -> None:
    app = _build(limit=None)
    client = TestClient(app)
    for _ in range(5):
        assert client.get("/a").status_code == 200


def test_middleware_enforces_global_limit() -> None:
    app = _build(limit=RateLimit(rate=2, per=60))
    client = TestClient(app)
    assert client.get("/a").status_code == 200
    assert client.get("/a").status_code == 200
    r = client.get("/a")
    assert r.status_code == 429
    assert r.headers.get("x-ratelimit-limit") == "2"
    assert int(r.headers.get("retry-after", "0")) >= 1


def test_middleware_excludes_listed_paths() -> None:
    app = _build(limit=RateLimit(rate=1, per=60), exclude=("/health",))
    client = TestClient(app)
    # Health is excluded — many hits, no 429.
    for _ in range(5):
        assert client.get("/health").status_code == 200


def test_exclude_paths_does_not_bypass_sibling_routes() -> None:
    """Regression: ``/sibling-of-health-but-different`` must NOT be treated as
    excluded when only ``/health`` is listed (CWE-284)."""
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)
    app.add_middleware(
        RateLimitMiddleware,
        limit=RateLimit(rate=1, per=60),
        exclude_paths=("/api/health",),
    )

    @app.get("/api/healthcheck")
    async def healthcheck() -> dict[str, Any]:
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/api/healthcheck").status_code == 200
    # The second request MUST be rate-limited — `/api/healthcheck` is not
    # excluded by an `/api/health` entry.
    assert client.get("/api/healthcheck").status_code == 429


def test_exclude_paths_covers_subpaths() -> None:
    """An exclude entry ``/api/health`` also covers ``/api/health/liveness``."""
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)
    app.add_middleware(
        RateLimitMiddleware,
        limit=RateLimit(rate=1, per=60),
        exclude_paths=("/api/health",),
    )

    @app.get("/api/health/liveness")
    async def live() -> dict[str, Any]:
        return {"ok": True}

    client = TestClient(app)
    for _ in range(5):
        assert client.get("/api/health/liveness").status_code == 200

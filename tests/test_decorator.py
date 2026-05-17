"""@rate_limit decorator — headers + 429 + bypass when not configured."""

from __future__ import annotations

from typing import Any

from hawkapi import HawkAPI, Request
from hawkapi.testing import TestClient

from hawkapi_ratelimit import init_ratelimit, rate_limit


def _build_app() -> HawkAPI:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)

    @app.get("/ping")
    @rate_limit(rate=2, per=60)
    async def ping(request: Request) -> dict[str, Any]:
        return {"ok": True}

    return app


def test_allows_within_budget_sets_headers() -> None:
    app = _build_app()
    client = TestClient(app)
    r1 = client.get("/ping")
    r2 = client.get("/ping")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.headers.get("x-ratelimit-limit") == "2"
    assert int(r1.headers.get("x-ratelimit-remaining", "-1")) >= 0


def test_returns_429_when_exhausted() -> None:
    app = _build_app()
    client = TestClient(app)
    client.get("/ping")
    client.get("/ping")
    r = client.get("/ping")
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}
    body = r.json()
    assert body["detail"] == "rate limit exceeded"


def test_handler_without_request_param_emits_warning() -> None:
    """Regression: forgetting the Request parameter must NOT be silent —
    rate limiting is silently skipped for every call, so the developer needs
    to see a warning at import time."""
    import warnings as _w

    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")

        @rate_limit(rate=1, per=60)
        async def _no_req() -> dict[str, Any]:
            return {"ok": True}

    msgs = [str(w.message) for w in caught]
    assert any("silently skipped" in m for m in msgs), msgs


def test_handler_without_request_param_is_skipped() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_ratelimit(app)

    import warnings as _w

    with _w.catch_warnings():
        _w.simplefilter("ignore", UserWarning)

        @app.get("/no-req")
        @rate_limit(rate=1, per=60)
        async def no_req() -> dict[str, Any]:
            return {"ok": True}

    client = TestClient(app)
    # Without the Request parameter, the decorator cannot key on identity —
    # by design it bypasses the check instead of denying every call.
    for _ in range(3):
        assert client.get("/no-req").status_code == 200

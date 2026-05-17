# hawkapi-ratelimit

Production-grade rate limiting for [HawkAPI](https://github.com/Hawk-API/HawkAPI). Token bucket + sliding window. In-memory + Redis-Lua backends. Per-IP / per-user / per-API-key / composite identities. Standard `X-RateLimit-*` + `Retry-After` headers. Decorator or middleware.

## Install

```bash
pip install hawkapi-ratelimit
pip install 'hawkapi-ratelimit[redis]'    # adds redis client for cluster-safe limits
```

## Quickstart

```python
from hawkapi import HawkAPI
from hawkapi_ratelimit import init_ratelimit, rate_limit

app = HawkAPI()
init_ratelimit(app)                   # default: MemoryLimiter (single-process)


@app.get("/search")
@rate_limit(rate=10, per=60)          # 10 requests per minute, per IP
async def search(request, q: str):
    return {"q": q}
```

When the budget is exhausted the route returns `429 Too Many Requests` with `Retry-After` and the `X-RateLimit-*` headers set. Allowed requests get the same headers so clients can self-pace.

## Strategies

```python
from hawkapi_ratelimit import MemoryLimiter, init_ratelimit

# Token bucket — smoothed, allows short bursts (default).
init_ratelimit(app, limiter=MemoryLimiter(strategy="token_bucket"))

# Sliding window — precise, rejects the moment the threshold is crossed.
init_ratelimit(app, limiter=MemoryLimiter(strategy="sliding_window"))
```

## Redis backend

For multi-process / multi-host deployments, swap in `RedisLimiter` — atomic check-and-increment via Lua scripts, cluster-safe:

```python
from hawkapi_ratelimit import RedisLimiter, init_ratelimit

init_ratelimit(
    app,
    limiter=RedisLimiter(
        url="redis://localhost:6379/0",
        strategy="token_bucket",
        key_prefix="myapp:rl:",
        socket_timeout=0.2,    # < 1s — don't let the limiter add tail latency
        fail_closed=False,     # default: allow on Redis error (fail-open)
    ),
)
```

Both strategies are implemented as single atomic Lua scripts — no read-then-write race.

## Identity strategies

```python
from hawkapi_ratelimit import api_key, composite_key, header_key, ip_key, rate_limit, user_key


# Per-IP — default, honors X-Forwarded-For only if you opt in.
@rate_limit(rate=100, per=60, identity=ip_key(trusted_proxy=True))
async def f(request): ...


# Per-authenticated-user (reads ``request.scope["user"]``).
@rate_limit(rate=1000, per=60, identity=user_key(attribute="user_id"))
async def f(request): ...


# Per-API-key (reads Authorization: Bearer <token>).
@rate_limit(rate=10000, per=60, identity=api_key())
async def f(request): ...


# Combine — IP AND user, separately budgeted.
@rate_limit(rate=100, per=60, identity=composite_key(ip_key(), user_key()))
async def f(request): ...
```

`ip_key(trusted_proxy=False)` (the default) reads `request.client.host` — the socket peer. `ip_key(trusted_proxy=True)` reads the **left-most** token of `X-Forwarded-For` (RFC-correct client). **Never** enable `trusted_proxy=True` unless your edge proxy strips inbound `X-Forwarded-For` from clients.

## Middleware mode

For a global policy across the whole app:

```python
from hawkapi_ratelimit import RateLimit, RateLimitMiddleware

app.add_middleware(
    RateLimitMiddleware,
    limit=RateLimit(rate=1000, per=60),
    exclude_paths=("/health", "/metrics"),
)
```

Per-route `@rate_limit` decorators stack on top of the middleware — they share the same backend.

## Response shape

On rejection:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1700000060
Retry-After: 7

{"detail": "rate limit exceeded", "retry_after": 7.0}
```

## Known accepted risks

These are real tradeoffs that operators should layer additional protection around.

- **`user_key()` collapses anonymous traffic to one shared bucket** (`"user:anon"`). A single attacker can exhaust the anonymous budget. Pair with `composite_key(ip_key(), user_key())` or restrict the route to authenticated users.
- **Middleware does not set `X-RateLimit-*` on allowed responses** — only on 429. The decorator sets them on every response. If you need response-headers everywhere, use the decorator (or attach headers in a downstream middleware).
- **`@rate_limit` skipped when handler has no `Request` parameter** — silently no-ops because there's nothing to key on. A `UserWarning` fires at import time if you forget it.
- **`MemoryLimiter` is single-process** — multi-worker deployments must use `RedisLimiter` for cluster-wide budgets.

## Security notes

- **`trusted_proxy=False` by default** — opt in only when your edge strips client-supplied `X-Forwarded-For`. Honoring `XFF` from an untrusted source lets attackers forge their identity by setting the header.
- **Key length capped at 256 chars** — prevents unbounded memory growth in `MemoryLimiter` when an attacker submits very long identifiers.
- **`MemoryLimiter` evicts** the oldest entries when the store exceeds `max_keys` (default 100k). The store cannot grow without bound.
- **Redis `socket_timeout=0.2s`** — short, so a partially-degraded Redis cannot add seconds of tail latency to every request.
- **Fail-open by default** (`RedisLimiter(fail_closed=False)`) — Redis outage = log warning and allow the request, rather than DoS'ing the app. Choose `fail_closed=True` for endpoints where rate-limit MUST hold (admin / payments).
- **Lua atomicity** — token-bucket refill + consume runs in a single `EVAL` round, so concurrent workers cannot race the budget.

## Development

```bash
git clone https://github.com/Hawk-API/hawkapi-ratelimit.git
cd hawkapi-ratelimit
uv sync --extra dev
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run pyright src/
```

## License

MIT.

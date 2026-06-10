# Changelog

## 0.1.1 — 2026-06-10

Security hardening.

- Header- and API-key-derived rate-limit identities (`header_key()`, `api_key()`) are now SHA-256 hashed before use as Redis keys, so bearer tokens and API keys are no longer observable in the keyspace (CWE-312). Note: this changes the key format produced by these identity functions.
- The fail-open path (`RedisLimiter` Redis error with `fail_closed=False`) now logs explicitly that the request was allowed despite the error; security-sensitive routes (admin / payment) should set `fail_closed=True` to deny instead.

## 0.1.0 — 2026-05-17

Initial release.

Security review applied before ship:

- `exclude_paths` now requires exact match OR true sub-path. Plain `startswith()` would have let `/healthz` bypass an `/health` exclusion (CWE-284).
- `user_key()` docstring + README warn about the shared-bucket DoS risk for anonymous traffic.
- `@rate_limit` emits a `UserWarning` at decoration time if the handler has no `Request` parameter — silently no-opped rate limiting is the worst kind of bug.
- `RedisLimiter` sliding-window member token is now `os.urandom(8).hex()` (was `id(now)`, which CPython recycles after GC).
- `MemoryLimiter` eviction uses `heapq.nsmallest` instead of a full sort, dropping the global-lock hold from O(N log N) to O(N + drop·log N) — avoids the latency spike at the `max_keys` ceiling.

Features:

- `MemoryLimiter` — token bucket + sliding window, single-process, with per-key locking via a shared `asyncio.Lock`. Key length capped at 256 chars; oldest 10% evicted when `max_keys` exceeded.
- `RedisLimiter` — atomic check-and-increment via Lua scripts (`EVAL`), cluster-safe. `socket_timeout=0.2s` default; fail-open by default with `fail_closed=True` opt-in.
- Identity strategies — `ip_key(trusted_proxy=...)`, `user_key(attribute=...)`, `header_key(...)`, `api_key()`, `composite_key(...)`.
- `@rate_limit(rate=, per=, identity=)` decorator + `RateLimitMiddleware` global middleware. Both share the same backend via the plugin registry.
- Standard headers — `X-RateLimit-Limit / Remaining / Reset` on every response; `Retry-After` on 429.
- 429 response body — `{"detail": "rate limit exceeded", "retry_after": <seconds>}`.
- `init_ratelimit(app, ...)` + `Depends(get_limiter)` + `WeakKeyDictionary` registry.
- Extras: `[redis]`.

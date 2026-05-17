"""init_ratelimit + get_limiter + WeakKeyDictionary registry."""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from hawkapi import HTTPException, Request

from ._base import Limiter
from ._memory import MemoryLimiter


class _StateNamespace:
    limiter: Any


_ACTIVE: WeakKeyDictionary[Any, Limiter] = WeakKeyDictionary()
_LAST: list[Limiter | None] = [None]


def init_ratelimit(
    app: Any,
    *,
    limiter: Limiter | None = None,
    auto_close: bool = True,
) -> Limiter:
    """Attach a :class:`Limiter` to ``app.state.limiter`` and return it."""
    limiter = limiter or MemoryLimiter()

    if getattr(app, "state", None) is None:
        app.state = _StateNamespace()
    app.state.limiter = limiter
    try:
        _ACTIVE[app] = limiter
    except TypeError:
        pass
    _LAST[0] = limiter

    if auto_close and hasattr(app, "on_shutdown"):

        async def _close() -> None:
            await limiter.close()

        app.on_shutdown(_close)

    return limiter


def resolve_limiter(app: Any) -> Limiter | None:
    if app is None:
        return _LAST[0]
    try:
        found = _ACTIVE.get(app)
    except TypeError:
        found = None
    if found is not None:
        return found
    state = getattr(app, "state", None)
    if state is not None and hasattr(state, "limiter"):
        return state.limiter  # type: ignore[no-any-return]
    return _LAST[0]


def get_limiter(request: Request) -> Limiter:
    found = resolve_limiter(request.scope.get("app"))
    if found is None:
        raise HTTPException(500, detail="Limiter not configured — call init_ratelimit(app, ...)")
    return found


__all__ = ["get_limiter", "init_ratelimit", "resolve_limiter"]

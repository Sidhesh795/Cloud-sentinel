import threading
import time
from collections import deque

from fastapi import HTTPException, Request, status

from backend import config


class RateLimiter:
    """In-process sliding-window limiter. Per-worker; swap for Redis when scaling horizontally."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._ops = 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def _prune(self, key: str, window: float, now: float) -> deque[float]:
        q = self._hits.setdefault(key, deque())
        while q and q[0] <= now - window:
            q.popleft()
        return q

    def _gc(self, now: float) -> None:
        self._ops += 1
        if self._ops % 1000:
            return
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - 3600]:
            del self._hits[k]

    def retry_after(self, key: str, limit: int, window: float) -> int:
        """Seconds until allowed (0 if under the limit). Does not record a hit."""
        if not config.RATE_LIMIT_ENABLED:
            return 0
        now = time.monotonic()
        with self._lock:
            q = self._prune(key, window, now)
            return 0 if len(q) < limit else max(1, int(q[0] + window - now) + 1)

    def hit(self, key: str, window: float) -> None:
        if not config.RATE_LIMIT_ENABLED:
            return
        now = time.monotonic()
        with self._lock:
            self._prune(key, window, now).append(now)
            self._gc(now)

    def check(self, key: str, limit: int, window: float) -> None:
        """Record a hit; raise 429 if over the limit."""
        wait = self.retry_after(key, limit, window)
        if wait:
            raise too_many(wait)
        self.hit(key, window)


def too_many(wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Try again later.",
        headers={"Retry-After": str(wait)},
    )


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    """Client IP. With TRUSTED_PROXY_HOPS=N, takes the Nth-from-last X-Forwarded-For entry (spoof-safe)."""
    hops = config.TRUSTED_PROXY_HOPS
    if hops > 0:
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return request.client.host if request.client else "unknown"


def ip_limit(scope: str, limit_attr: str, window: int = 60):
    """FastAPI dependency: per-IP limit for a scope; limit read from config at request time."""

    def dep(request: Request) -> None:
        limiter.check(f"{scope}:ip:{client_ip(request)}", getattr(config, limit_attr), window)

    return dep


def username_blocked(username: str) -> int:
    """Seconds to wait if too many recent failures for this username, else 0."""
    return limiter.retry_after(f"login:user:{username.strip().lower()}", config.LOGIN_USER_FAILS, config.LOGIN_USER_WINDOW)


def username_failed(username: str) -> None:
    limiter.hit(f"login:user:{username.strip().lower()}", config.LOGIN_USER_WINDOW)

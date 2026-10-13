"""Shared HTTP client with a global request-rate throttle.

The CLI configures one module-level throttle at scan start; every scanner
builds its client via ``net.client()`` so all outbound requests share the
same rate limit. This is what makes ``--rate-limit`` actually do something
and keeps the scanner from hammering (and tripping) a WAF.
"""
import asyncio
import random
import time
from typing import Optional

import httpx


class Throttle:
    """Async rate limiter. rate_per_sec <= 0 means unlimited (no wait)."""

    def __init__(self, rate_per_sec: float = 0.0, jitter: float = 0.0):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self.jitter = max(0.0, jitter)
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        if self.min_interval <= 0 and self.jitter <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._last + self.min_interval - now
            if delay > 0:
                await asyncio.sleep(delay)
            if self.jitter:
                await asyncio.sleep(random.uniform(0, self.jitter))
            self._last = time.monotonic()


# Module-global throttle. Default unlimited so direct scanner calls (and the
# unit tests) run at full speed until the CLI configures a limit.
_throttle = Throttle()
# Bounds how many requests are in flight at once when scanners fire concurrently.
# None = unbounded. Lives at module scope so every client shares it.
_max_concurrency: Optional[int] = None
_sem: "Optional[asyncio.Semaphore]" = None


def configure(rate_per_sec: float = 0.0, jitter: float = 0.0, concurrency: Optional[int] = None) -> None:
    global _throttle, _max_concurrency, _sem
    _throttle = Throttle(rate_per_sec, jitter)
    _max_concurrency = concurrency if concurrency and concurrency > 0 else None
    _sem = None  # lazily created on first use, bound to the running loop


def _semaphore() -> "Optional[asyncio.Semaphore]":
    global _sem
    if _max_concurrency is None:
        return None
    if _sem is None:
        _sem = asyncio.Semaphore(_max_concurrency)
    return _sem


class ThrottledClient(httpx.AsyncClient):
    """httpx client that bounds concurrency and awaits the global throttle
    before every request."""

    async def request(self, *args, **kwargs):
        sem = _semaphore()
        if sem is not None:
            async with sem:
                await _throttle.wait()
                return await super().request(*args, **kwargs)
        await _throttle.wait()
        return await super().request(*args, **kwargs)


def client(timeout: Optional[float] = None, **kwargs) -> ThrottledClient:
    """Construct a throttled client. TLS verification off to match the
    scanner's self-signed-friendly behavior (it targets test endpoints)."""
    kwargs.setdefault("verify", False)
    if timeout is not None:
        kwargs.setdefault("timeout", timeout)
    return ThrottledClient(**kwargs)

"""Token-bucket rate limiter and concurrency helpers."""

from __future__ import annotations

import asyncio
import time
from typing import Optional


class RateLimiter:
    def __init__(self, rate: float = 5.0, capacity: Optional[float] = None) -> None:
        self.rate = max(rate, 0.1)
        self.capacity = capacity if capacity is not None else self.rate
        self.tokens = self.capacity
        self.updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.updated_at
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.updated_at = now
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
                self.updated_at = time.monotonic()
            else:
                self.tokens -= 1.0


class ConcurrencyLimiter:
    def __init__(self, max_workers: int = 5) -> None:
        self._sem = asyncio.Semaphore(max(1, max_workers))

    async def __aenter__(self) -> "ConcurrencyLimiter":
        await self._sem.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        self._sem.release()

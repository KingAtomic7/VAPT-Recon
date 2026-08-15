"""Token bucket rate limiter for async operations."""

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AsyncTokenBucket:
    """Async token bucket rate limiter."""
    rate: int  # tokens per second
    burst: int = 0  # max burst (0 = rate)
    _tokens: float = field(init=False, default=0)
    _last_update: float = field(init=False, default=0)
    _lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst or self.rate)
        self._last_update = time.monotonic()

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, blocking until available."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_update
                self._tokens = min(
                    self.burst or self.rate,
                    self._tokens + elapsed * self.rate
                )
                self._last_update = now

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return

                # Wait for next token
                wait_time = (tokens - self._tokens) / self.rate
                await asyncio.sleep(min(wait_time, 0.1))

    def try_acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens without blocking."""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(
            self.burst or self.rate,
            self._tokens + elapsed * self.rate
        )
        self._last_update = now

        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


class RateLimiter:
    """Global rate limiter with named buckets."""
    def __init__(self, default_rate: int = 100):
        self.default_rate = default_rate
        self._buckets: dict[str, AsyncTokenBucket] = {}
        self._lock = asyncio.Lock()

    def bucket(self, name: str, rate: Optional[int] = None) -> AsyncTokenBucket:
        """Get or create a named bucket."""
        if name not in self._buckets:
            self._buckets[name] = AsyncTokenBucket(rate or self.default_rate)
        return self._buckets[name]

    async def acquire(self, name: str, tokens: int = 1, rate: Optional[int] = None) -> None:
        """Acquire tokens from named bucket."""
        bucket = self.bucket(name, rate)
        await bucket.acquire(tokens)

    def reset(self, name: str) -> None:
        """Reset a bucket."""
        if name in self._buckets:
            del self._buckets[name]


# Global rate limiter instance
_global_limiter: Optional[RateLimiter] = None


def get_limiter(default_rate: int = 100) -> RateLimiter:
    """Get global rate limiter."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter(default_rate)
    return _global_limiter
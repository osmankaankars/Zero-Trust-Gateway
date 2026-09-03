"""Bounded in-memory token-bucket rate limiting."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: float = 0.0


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float
    last_seen: float


class TokenBucketRateLimiter:
    """A memory-bounded limiter intended for a single-process local demo."""

    def __init__(
        self,
        *,
        capacity: int,
        refill_per_second: float,
        max_entries: int,
        idle_ttl_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1 or refill_per_second <= 0 or max_entries < 1:
            raise ValueError("rate limiter values must be positive")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_entries = max_entries
        self.idle_ttl_seconds = idle_ttl_seconds
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str) -> RateLimitDecision:
        now = self._clock()
        self._discard_idle(now)
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self.max_entries:
                oldest_key = min(
                    self._buckets,
                    key=lambda candidate: self._buckets[candidate].last_seen,
                )
                del self._buckets[oldest_key]
            bucket = _Bucket(tokens=float(self.capacity), updated_at=now, last_seen=now)
            self._buckets[key] = bucket

        elapsed = max(0.0, now - bucket.updated_at)
        bucket.tokens = min(
            float(self.capacity), bucket.tokens + elapsed * self.refill_per_second
        )
        bucket.updated_at = now
        bucket.last_seen = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return RateLimitDecision(allowed=True)
        retry_after = (1.0 - bucket.tokens) / self.refill_per_second
        return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)

    @property
    def entry_count(self) -> int:
        """Return the number of currently tracked bounded identities."""

        return len(self._buckets)

    def _discard_idle(self, now: float) -> None:
        expired = [
            key
            for key, bucket in self._buckets.items()
            if now - bucket.last_seen > self.idle_ttl_seconds
        ]
        for key in expired:
            del self._buckets[key]

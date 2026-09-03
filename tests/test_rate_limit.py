from __future__ import annotations

import unittest

from zero_trust_gateway.rate_limit import TokenBucketRateLimiter


class RateLimiterTests(unittest.TestCase):
    def test_denies_after_capacity_and_refills_deterministically(self) -> None:
        now = [100.0]
        limiter = TokenBucketRateLimiter(
            capacity=2,
            refill_per_second=1.0,
            max_entries=10,
            idle_ttl_seconds=60,
            clock=lambda: now[0],
        )
        self.assertTrue(limiter.check("127.0.0.1").allowed)
        self.assertTrue(limiter.check("127.0.0.1").allowed)
        denied = limiter.check("127.0.0.1")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.retry_after_seconds, 1.0)
        now[0] += 1.0
        self.assertTrue(limiter.check("127.0.0.1").allowed)

    def test_bucket_collection_is_bounded(self) -> None:
        now = [100.0]
        limiter = TokenBucketRateLimiter(
            capacity=1,
            refill_per_second=1.0,
            max_entries=2,
            idle_ttl_seconds=60,
            clock=lambda: now[0],
        )
        limiter.check("one")
        now[0] += 1
        limiter.check("two")
        now[0] += 1
        limiter.check("three")
        self.assertEqual(limiter.entry_count, 2)


if __name__ == "__main__":
    unittest.main()

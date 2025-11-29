"""Rate limiting for external API calls in TR4C3R.

This module provides per-service rate limiting to prevent hitting
API rate limits when making requests to external services.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""

    requests_per_second: float
    burst_size: int = 1
    enabled: bool = True

    @property
    def min_interval(self) -> float:
        """Minimum interval between requests in seconds."""
        return 1.0 / self.requests_per_second if self.requests_per_second > 0 else 0


# Default rate limits for various services
DEFAULT_RATE_LIMITS: Dict[str, RateLimitConfig] = {
    # Free APIs with stricter limits
    "github": RateLimitConfig(requests_per_second=10, burst_size=5),  # 60/min for auth
    "reddit": RateLimitConfig(requests_per_second=1, burst_size=2),  # Very strict
    "keybase": RateLimitConfig(requests_per_second=2, burst_size=3),
    # Paid APIs - more generous but still respectful
    "hibp": RateLimitConfig(requests_per_second=1.5, burst_size=2),  # ~10/min
    "hunter": RateLimitConfig(requests_per_second=2, burst_size=3),
    "numverify": RateLimitConfig(requests_per_second=2, burst_size=3),
    "clearbit": RateLimitConfig(requests_per_second=2, burst_size=3),
    # Generic external
    "default": RateLimitConfig(requests_per_second=5, burst_size=5),
}


class TokenBucket:
    """Token bucket rate limiter implementation."""

    def __init__(
        self,
        rate: float,
        burst_size: int = 1,
    ) -> None:
        """Initialize token bucket.

        Args:
            rate: Tokens added per second
            burst_size: Maximum tokens that can accumulate
        """
        self.rate = rate
        self.burst_size = burst_size
        self.tokens = float(burst_size)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            Time waited in seconds
        """
        async with self._lock:
            waited = 0.0

            while True:
                now = time.monotonic()
                # Add tokens based on elapsed time
                elapsed = now - self.last_update
                self.tokens = min(
                    self.burst_size,
                    self.tokens + elapsed * self.rate,
                )
                self.last_update = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return waited

                # Calculate wait time
                needed = tokens - self.tokens
                wait_time = needed / self.rate
                waited += wait_time
                await asyncio.sleep(wait_time)

    def available(self) -> float:
        """Get available tokens without acquiring."""
        now = time.monotonic()
        elapsed = now - self.last_update
        return min(
            self.burst_size,
            self.tokens + elapsed * self.rate,
        )


class RateLimiter:
    """Manages rate limits for multiple services."""

    def __init__(
        self,
        rate_limits: Optional[Dict[str, RateLimitConfig]] = None,
    ) -> None:
        """Initialize rate limiter.

        Args:
            rate_limits: Custom rate limit configurations (merged with defaults)
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._buckets: Dict[str, TokenBucket] = {}
        self._configs: Dict[str, RateLimitConfig] = dict(DEFAULT_RATE_LIMITS)
        if rate_limits:
            self._configs.update(rate_limits)

        # Statistics
        self._stats: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"requests": 0, "total_wait": 0.0}
        )

    def _get_bucket(self, service: str) -> TokenBucket:
        """Get or create token bucket for a service."""
        if service not in self._buckets:
            config = self._configs.get(service, self._configs["default"])
            self._buckets[service] = TokenBucket(
                rate=config.requests_per_second,
                burst_size=config.burst_size,
            )
        return self._buckets[service]

    def _get_config(self, service: str) -> RateLimitConfig:
        """Get rate limit config for a service."""
        return self._configs.get(service, self._configs["default"])

    async def acquire(self, service: str, tokens: int = 1) -> float:
        """Acquire rate limit tokens for a service.

        Args:
            service: Service name (e.g., "github", "reddit")
            tokens: Number of tokens to acquire

        Returns:
            Time waited in seconds
        """
        config = self._get_config(service)
        if not config.enabled:
            return 0.0

        bucket = self._get_bucket(service)
        waited = await bucket.acquire(tokens)

        # Update statistics
        self._stats[service]["requests"] += 1
        self._stats[service]["total_wait"] += waited

        if waited > 0.1:  # Log significant waits
            self.logger.debug(
                "Rate limited %s: waited %.2fs (%d tokens)",
                service,
                waited,
                tokens,
            )

        return waited

    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get rate limiting statistics.

        Returns:
            Dictionary with stats per service
        """
        stats = {}
        for service, data in self._stats.items():
            stats[service] = {
                "requests": data["requests"],
                "total_wait_seconds": round(data["total_wait"], 3),
                "avg_wait_seconds": (
                    round(data["total_wait"] / data["requests"], 3) if data["requests"] > 0 else 0
                ),
            }
        return stats

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats.clear()

    def set_rate_limit(
        self,
        service: str,
        requests_per_second: float,
        burst_size: int = 1,
    ) -> None:
        """Set or update rate limit for a service.

        Args:
            service: Service name
            requests_per_second: Allowed requests per second
            burst_size: Maximum burst size
        """
        self._configs[service] = RateLimitConfig(
            requests_per_second=requests_per_second,
            burst_size=burst_size,
        )
        # Remove existing bucket to force recreation
        if service in self._buckets:
            del self._buckets[service]

        self.logger.info(
            "Set rate limit for %s: %.2f req/s (burst: %d)",
            service,
            requests_per_second,
            burst_size,
        )

    def disable(self, service: str) -> None:
        """Disable rate limiting for a service."""
        if service in self._configs:
            self._configs[service] = RateLimitConfig(
                requests_per_second=self._configs[service].requests_per_second,
                burst_size=self._configs[service].burst_size,
                enabled=False,
            )
        self.logger.info("Disabled rate limiting for %s", service)

    def enable(self, service: str) -> None:
        """Enable rate limiting for a service."""
        if service in self._configs:
            self._configs[service] = RateLimitConfig(
                requests_per_second=self._configs[service].requests_per_second,
                burst_size=self._configs[service].burst_size,
                enabled=True,
            )
        self.logger.info("Enabled rate limiting for %s", service)


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Set the global rate limiter instance."""
    global _rate_limiter
    _rate_limiter = limiter


async def rate_limited(service: str, tokens: int = 1) -> float:
    """Convenience function to acquire rate limit tokens.

    Args:
        service: Service name
        tokens: Number of tokens to acquire

    Returns:
        Time waited in seconds
    """
    limiter = get_rate_limiter()
    return await limiter.acquire(service, tokens)

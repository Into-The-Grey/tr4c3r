"""Tests for the rate limiter module."""

import asyncio
import pytest
import time

from src.core.rate_limiter import (
    RateLimiter,
    RateLimitConfig,
    TokenBucket,
    get_rate_limiter,
    set_rate_limiter,
    rate_limited,
    DEFAULT_RATE_LIMITS,
)


class TestRateLimitConfig:
    """Tests for RateLimitConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = RateLimitConfig(requests_per_second=10.0)
        assert config.requests_per_second == 10.0
        assert config.burst_size == 1
        assert config.enabled is True

    def test_min_interval(self):
        """Test minimum interval calculation."""
        config = RateLimitConfig(requests_per_second=5.0)
        assert config.min_interval == 0.2

    def test_zero_rate(self):
        """Test zero rate per second."""
        config = RateLimitConfig(requests_per_second=0.0)
        assert config.min_interval == 0


class TestTokenBucket:
    """Tests for TokenBucket class."""

    def test_init(self):
        """Test initialization."""
        bucket = TokenBucket(rate=5.0, burst_size=3)
        assert bucket.rate == 5.0
        assert bucket.burst_size == 3
        assert bucket.tokens == 3.0  # Starts full

    def test_available(self):
        """Test available tokens calculation."""
        bucket = TokenBucket(rate=10.0, burst_size=5)
        # Initially full
        assert bucket.available() == 5.0

    @pytest.mark.asyncio
    async def test_acquire_immediate(self):
        """Test acquiring tokens immediately when available."""
        bucket = TokenBucket(rate=10.0, burst_size=5)

        start = time.monotonic()
        waited = await bucket.acquire(1)
        elapsed = time.monotonic() - start

        assert waited == 0.0
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_acquire_waits(self):
        """Test that acquire waits when tokens not available."""
        bucket = TokenBucket(rate=10.0, burst_size=1)

        # First acquire should be immediate
        await bucket.acquire(1)

        # Second acquire should wait
        start = time.monotonic()
        waited = await bucket.acquire(1)
        elapsed = time.monotonic() - start

        assert waited >= 0.08  # ~0.1s at 10/s
        assert elapsed >= 0.08

    @pytest.mark.asyncio
    async def test_burst(self):
        """Test burst capacity."""
        bucket = TokenBucket(rate=10.0, burst_size=5)

        # Should be able to acquire 5 immediately
        total_waited = 0.0
        for _ in range(5):
            waited = await bucket.acquire(1)
            total_waited += waited

        assert total_waited < 0.1  # Should be nearly instant


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_init_default_limits(self):
        """Test initialization with default limits."""
        limiter = RateLimiter()
        assert "default" in limiter._configs
        assert "github" in limiter._configs

    def test_init_custom_limits(self):
        """Test initialization with custom limits."""
        custom = {"custom_service": RateLimitConfig(requests_per_second=1.0)}
        limiter = RateLimiter(rate_limits=custom)

        assert "custom_service" in limiter._configs
        # Should also have defaults
        assert "default" in limiter._configs

    @pytest.mark.asyncio
    async def test_acquire_known_service(self):
        """Test acquiring for a known service."""
        limiter = RateLimiter()
        waited = await limiter.acquire("github")
        # First request should be immediate
        assert waited == 0.0

    @pytest.mark.asyncio
    async def test_acquire_unknown_service(self):
        """Test acquiring for an unknown service uses default."""
        limiter = RateLimiter()
        waited = await limiter.acquire("unknown_service")
        assert waited == 0.0

    def test_get_stats(self):
        """Test getting statistics."""
        limiter = RateLimiter()
        stats = limiter.get_stats()
        assert isinstance(stats, dict)

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Test that statistics are tracked."""
        limiter = RateLimiter()

        await limiter.acquire("test_service")
        await limiter.acquire("test_service")

        stats = limiter.get_stats()
        assert "test_service" in stats
        assert stats["test_service"]["requests"] == 2

    def test_reset_stats(self):
        """Test resetting statistics."""
        limiter = RateLimiter()
        limiter._stats["test"] = {"requests": 10, "total_wait": 5.0}

        limiter.reset_stats()
        assert limiter._stats == {}

    def test_set_rate_limit(self):
        """Test setting a new rate limit."""
        limiter = RateLimiter()
        limiter.set_rate_limit("new_service", 2.0, burst_size=5)

        assert "new_service" in limiter._configs
        assert limiter._configs["new_service"].requests_per_second == 2.0
        assert limiter._configs["new_service"].burst_size == 5

    def test_disable_service(self):
        """Test disabling rate limiting for a service."""
        limiter = RateLimiter()
        limiter.disable("github")

        assert limiter._configs["github"].enabled is False

    def test_enable_service(self):
        """Test enabling rate limiting for a service."""
        limiter = RateLimiter()
        limiter.disable("github")
        limiter.enable("github")

        assert limiter._configs["github"].enabled is True

    @pytest.mark.asyncio
    async def test_disabled_service_no_wait(self):
        """Test that disabled services don't wait."""
        limiter = RateLimiter()
        limiter.set_rate_limit("slow_service", 0.1)  # Very slow
        limiter.disable("slow_service")

        start = time.monotonic()
        # Make many requests
        for _ in range(10):
            await limiter.acquire("slow_service")
        elapsed = time.monotonic() - start

        # Should be very fast since disabled
        assert elapsed < 0.5


class TestGlobalRateLimiter:
    """Tests for global rate limiter functions."""

    def test_get_rate_limiter(self):
        """Test getting global rate limiter."""
        set_rate_limiter(None)  # type: ignore

        limiter = get_rate_limiter()
        assert limiter is not None
        assert isinstance(limiter, RateLimiter)

    def test_set_rate_limiter(self):
        """Test setting global rate limiter."""
        custom = RateLimiter()
        custom.set_rate_limit("custom", 999.0)

        set_rate_limiter(custom)
        limiter = get_rate_limiter()

        assert "custom" in limiter._configs

    @pytest.mark.asyncio
    async def test_rate_limited_function(self):
        """Test rate_limited convenience function."""
        set_rate_limiter(RateLimiter())

        waited = await rate_limited("github")
        assert waited == 0.0


class TestDefaultRateLimits:
    """Tests for default rate limits."""

    def test_github_limit(self):
        """Test GitHub rate limit configuration."""
        config = DEFAULT_RATE_LIMITS["github"]
        assert config.requests_per_second == 10.0
        assert config.enabled is True

    def test_reddit_limit(self):
        """Test Reddit rate limit configuration."""
        config = DEFAULT_RATE_LIMITS["reddit"]
        assert config.requests_per_second == 1.0  # Reddit is strict

    def test_default_limit(self):
        """Test default rate limit configuration."""
        config = DEFAULT_RATE_LIMITS["default"]
        assert config.requests_per_second == 5.0


class TestConcurrentRequests:
    """Tests for concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_acquire(self):
        """Test concurrent token acquisition."""
        limiter = RateLimiter()
        limiter.set_rate_limit("test", 10.0, burst_size=3)

        # Make concurrent requests
        tasks = [limiter.acquire("test") for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # First 3 should be immediate (burst), rest should wait
        immediate = sum(1 for r in results if r < 0.05)
        assert immediate == 3

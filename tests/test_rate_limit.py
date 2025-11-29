"""Tests for rate limiting middleware and utilities."""

import asyncio
import time
from unittest.mock import MagicMock, AsyncMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.rate_limit import (
    FixedWindowLimiter,
    RateLimitConfig,
    RateLimitExceeded,
    RateLimitManager,
    RateLimitMiddleware,
    RateLimitResult,
    RateLimitStrategy,
    SlidingWindowLimiter,
    TokenBucketLimiter,
    get_rate_limit_config,
    rate_limit,
    RATE_LIMIT_PRESETS,
)


class TestRateLimitConfig:
    """Tests for RateLimitConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RateLimitConfig()

        assert config.requests == 100
        assert config.window == 60
        assert config.strategy == RateLimitStrategy.SLIDING_WINDOW
        assert config.burst == 10
        assert config.include_headers is True
        assert config.exclude_paths == []

    def test_custom_config(self):
        """Test custom configuration."""
        config = RateLimitConfig(
            requests=50,
            window=30,
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            burst=5,
        )

        assert config.requests == 50
        assert config.window == 30
        assert config.strategy == RateLimitStrategy.TOKEN_BUCKET
        assert config.burst == 5


class TestTokenBucketLimiter:
    """Tests for TokenBucketLimiter."""

    @pytest.fixture
    def limiter(self):
        """Create limiter for testing."""
        return TokenBucketLimiter(rate=1.0, capacity=5)

    @pytest.mark.asyncio
    async def test_initial_requests_allowed(self, limiter):
        """Test that initial requests are allowed."""
        result = await limiter.check("user1")

        assert result.allowed is True
        assert result.remaining == 4  # capacity - 1
        assert result.limit == 5

    @pytest.mark.asyncio
    async def test_capacity_exhaustion(self, limiter):
        """Test that bucket exhausts after capacity requests."""
        # Use all tokens
        for i in range(5):
            result = await limiter.check("user1")
            assert result.allowed is True

        # Next request should be denied
        result = await limiter.check("user1")
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None

    @pytest.mark.asyncio
    async def test_token_refill(self, limiter):
        """Test that tokens refill over time."""
        # Use all tokens
        for _ in range(5):
            await limiter.check("user1")

        # Wait for refill
        await asyncio.sleep(1.1)

        # Should be allowed now
        result = await limiter.check("user1")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_different_keys_independent(self, limiter):
        """Test that different keys have independent limits."""
        # Exhaust user1
        for _ in range(5):
            await limiter.check("user1")

        result1 = await limiter.check("user1")
        result2 = await limiter.check("user2")

        assert result1.allowed is False
        assert result2.allowed is True

    @pytest.mark.asyncio
    async def test_reset(self, limiter):
        """Test resetting a key."""
        # Exhaust user1
        for _ in range(5):
            await limiter.check("user1")

        assert (await limiter.check("user1")).allowed is False

        # Reset
        await limiter.reset("user1")

        # Should be allowed now
        result = await limiter.check("user1")
        assert result.allowed is True


class TestSlidingWindowLimiter:
    """Tests for SlidingWindowLimiter."""

    @pytest.fixture
    def limiter(self):
        """Create limiter for testing."""
        return SlidingWindowLimiter(limit=5, window=10)

    @pytest.mark.asyncio
    async def test_requests_within_limit(self, limiter):
        """Test requests within limit are allowed."""
        for i in range(5):
            result = await limiter.check("user1")
            assert result.allowed is True
            assert result.remaining == 4 - i

    @pytest.mark.asyncio
    async def test_exceeds_limit(self, limiter):
        """Test requests exceeding limit are denied."""
        for _ in range(5):
            await limiter.check("user1")

        result = await limiter.check("user1")
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None

    @pytest.mark.asyncio
    async def test_sliding_window(self, limiter):
        """Test that old requests slide out of window."""
        # Use all requests
        for _ in range(5):
            await limiter.check("user1")

        # Wait for some requests to expire
        await asyncio.sleep(11)

        # Should be allowed now
        result = await limiter.check("user1")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_reset(self, limiter):
        """Test resetting a key."""
        for _ in range(5):
            await limiter.check("user1")

        await limiter.reset("user1")

        result = await limiter.check("user1")
        assert result.allowed is True
        assert result.remaining == 4


class TestFixedWindowLimiter:
    """Tests for FixedWindowLimiter."""

    @pytest.fixture
    def limiter(self):
        """Create limiter for testing."""
        return FixedWindowLimiter(limit=5, window=10)

    @pytest.mark.asyncio
    async def test_requests_within_limit(self, limiter):
        """Test requests within limit are allowed."""
        for i in range(5):
            result = await limiter.check("user1")
            assert result.allowed is True
            assert result.remaining == 4 - i

    @pytest.mark.asyncio
    async def test_exceeds_limit(self, limiter):
        """Test requests exceeding limit are denied."""
        for _ in range(5):
            await limiter.check("user1")

        result = await limiter.check("user1")
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_window_reset(self, limiter):
        """Test that limit resets with new window."""
        # Use all requests
        for _ in range(5):
            await limiter.check("user1")

        # Wait for new window
        await asyncio.sleep(11)

        # Should be allowed in new window
        result = await limiter.check("user1")
        assert result.allowed is True


class TestRateLimitManager:
    """Tests for RateLimitManager."""

    @pytest.fixture
    def manager(self):
        """Create manager for testing."""
        config = RateLimitConfig(requests=5, window=60)
        return RateLimitManager(config)

    @pytest.fixture
    def mock_request(self):
        """Create mock request."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/search"
        request.headers = {}
        request.client.host = "127.0.0.1"
        return request

    @pytest.mark.asyncio
    async def test_check_allowed(self, manager, mock_request):
        """Test checking allowed request."""
        result = await manager.check(mock_request)

        assert result.allowed is True
        assert result.remaining == 4

    @pytest.mark.asyncio
    async def test_check_exceeded(self, manager, mock_request):
        """Test checking exceeded limit."""
        for _ in range(5):
            await manager.check(mock_request)

        result = await manager.check(mock_request)
        assert result.allowed is False

    def test_get_key_from_ip(self, manager, mock_request):
        """Test getting key from IP address."""
        key = manager.get_key(mock_request)
        assert key == "127.0.0.1"

    def test_get_key_from_forwarded(self, manager, mock_request):
        """Test getting key from X-Forwarded-For header."""
        mock_request.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}
        key = manager.get_key(mock_request)
        assert key == "10.0.0.1"

    def test_get_key_custom_function(self, mock_request):
        """Test custom key function."""

        def api_key_func(req):
            return req.headers.get("X-API-Key", "anonymous")

        config = RateLimitConfig(key_func=api_key_func)
        manager = RateLimitManager(config)

        mock_request.headers = {"X-API-Key": "my-api-key"}
        key = manager.get_key(mock_request)
        assert key == "my-api-key"

    def test_is_excluded(self, manager):
        """Test path exclusion."""
        manager.config.exclude_paths = ["/health", "/metrics"]

        assert manager.is_excluded("/health") is True
        assert manager.is_excluded("/healthcheck") is True
        assert manager.is_excluded("/api/search") is False

    @pytest.mark.asyncio
    async def test_excluded_path_always_allowed(self, manager, mock_request):
        """Test that excluded paths are always allowed."""
        manager.config.exclude_paths = ["/api/search"]

        # Should always be allowed
        for _ in range(10):
            result = await manager.check(mock_request)
            assert result.allowed is True

    def test_endpoint_specific_limits(self):
        """Test endpoint-specific rate limits."""
        config = RateLimitConfig(
            requests=100,
            window=60,
            endpoint_limits={
                "/api/expensive": {"requests": 5, "window": 60},
            },
        )
        manager = RateLimitManager(config)

        default_limiter = manager.get_limiter("/api/normal")
        expensive_limiter = manager.get_limiter("/api/expensive")

        # Different limiter instances
        assert default_limiter is not expensive_limiter

    @pytest.mark.asyncio
    async def test_reset_key(self, manager, mock_request):
        """Test resetting a specific key."""
        # Exhaust limit
        for _ in range(5):
            await manager.check(mock_request)

        assert (await manager.check(mock_request)).allowed is False

        # Reset
        key = manager.get_key(mock_request)
        await manager.reset(key)

        # Should be allowed
        result = await manager.check(mock_request)
        assert result.allowed is True


class TestRateLimitMiddleware:
    """Tests for RateLimitMiddleware."""

    @pytest.fixture
    def app(self):
        """Create test FastAPI app."""
        app = FastAPI()

        # Add rate limit middleware
        config = RateLimitConfig(
            requests=5,
            window=60,
            exclude_paths=["/health"],
        )
        app.add_middleware(RateLimitMiddleware, config=config)

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        return app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)

    def test_requests_within_limit(self, client):
        """Test requests within limit succeed."""
        for i in range(5):
            response = client.get("/test")
            assert response.status_code == 200
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers

    def test_rate_limit_exceeded(self, client):
        """Test exceeding rate limit."""
        for _ in range(5):
            client.get("/test")

        response = client.get("/test")
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    def test_excluded_path(self, client):
        """Test excluded paths are not rate limited."""
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == 200

    def test_rate_limit_headers(self, client):
        """Test rate limit headers are included."""
        response = client.get("/test")

        assert response.headers["X-RateLimit-Limit"] == "5"
        assert response.headers["X-RateLimit-Remaining"] == "4"
        assert "X-RateLimit-Reset" in response.headers


class TestRateLimitDecorator:
    """Tests for rate_limit decorator."""

    def test_decorator_on_endpoint(self):
        """Test rate limit decorator on endpoint."""
        from fastapi.responses import JSONResponse

        app = FastAPI()

        @app.exception_handler(RateLimitExceeded)
        async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers if exc.headers else {},
            )

        @app.get("/limited")
        @rate_limit(requests=3, window=60)
        async def limited_endpoint(request: Request):
            return {"status": "ok"}

        client = TestClient(app)

        # First 3 should succeed
        for _ in range(3):
            response = client.get("/limited")
            assert response.status_code == 200

        # 4th should fail
        response = client.get("/limited")
        assert response.status_code == 429

    def test_decorator_custom_key(self):
        """Test decorator with custom key function."""
        from fastapi.responses import JSONResponse

        app = FastAPI()

        @app.exception_handler(RateLimitExceeded)
        async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers if exc.headers else {},
            )

        def api_key_extractor(request: Request):
            return request.headers.get("X-API-Key", "default")

        @app.get("/custom")
        @rate_limit(requests=2, window=60, key_func=api_key_extractor)
        async def custom_endpoint(request: Request):
            return {"status": "ok"}

        client = TestClient(app)

        # Different API keys should have independent limits
        for _ in range(2):
            response = client.get("/custom", headers={"X-API-Key": "key1"})
            assert response.status_code == 200

        # key1 exhausted
        response = client.get("/custom", headers={"X-API-Key": "key1"})
        assert response.status_code == 429

        # key2 should still work
        response = client.get("/custom", headers={"X-API-Key": "key2"})
        assert response.status_code == 200


class TestRateLimitPresets:
    """Tests for rate limit presets."""

    def test_presets_exist(self):
        """Test all presets exist."""
        assert "strict" in RATE_LIMIT_PRESETS
        assert "standard" in RATE_LIMIT_PRESETS
        assert "relaxed" in RATE_LIMIT_PRESETS
        assert "api" in RATE_LIMIT_PRESETS
        assert "search" in RATE_LIMIT_PRESETS

    def test_get_preset(self):
        """Test getting preset configuration."""
        config = get_rate_limit_config("strict")

        assert config.requests == 10
        assert config.window == 60

    def test_get_invalid_preset(self):
        """Test getting invalid preset raises error."""
        with pytest.raises(ValueError, match="Unknown preset"):
            get_rate_limit_config("nonexistent")

    def test_api_preset_token_bucket(self):
        """Test API preset uses token bucket."""
        config = get_rate_limit_config("api")

        assert config.strategy == RateLimitStrategy.TOKEN_BUCKET
        assert config.burst == 10

    def test_search_preset_endpoint_limits(self):
        """Test search preset has endpoint limits."""
        config = get_rate_limit_config("search")

        assert "/search/email" in config.endpoint_limits
        assert config.endpoint_limits["/search/email"]["requests"] == 10


class TestRateLimitExceeded:
    """Tests for RateLimitExceeded exception."""

    def test_exception_status_code(self):
        """Test exception has correct status code."""
        exc = RateLimitExceeded()
        assert exc.status_code == 429

    def test_exception_with_retry_after(self):
        """Test exception includes Retry-After header."""
        exc = RateLimitExceeded(retry_after=30)

        assert exc.retry_after == 30
        assert exc.headers is not None
        assert exc.headers["Retry-After"] == "30"

    def test_exception_custom_message(self):
        """Test exception with custom message."""
        exc = RateLimitExceeded(detail="Custom rate limit message")
        assert exc.detail == "Custom rate limit message"


class TestRateLimitResult:
    """Tests for RateLimitResult."""

    def test_allowed_result(self):
        """Test allowed result."""
        result = RateLimitResult(
            allowed=True,
            remaining=5,
            limit=10,
            reset=int(time.time()) + 60,
        )

        assert result.allowed is True
        assert result.remaining == 5
        assert result.retry_after is None

    def test_denied_result(self):
        """Test denied result."""
        result = RateLimitResult(
            allowed=False,
            remaining=0,
            limit=10,
            reset=int(time.time()) + 30,
            retry_after=30,
        )

        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after == 30


class TestIntegration:
    """Integration tests for rate limiting."""

    def test_complete_api_flow(self):
        """Test complete API flow with rate limiting."""
        app = FastAPI()

        config = RateLimitConfig(
            requests=3,
            window=60,
            strategy=RateLimitStrategy.SLIDING_WINDOW,
            exclude_paths=["/health"],
        )
        app.add_middleware(RateLimitMiddleware, config=config)

        @app.get("/search")
        async def search():
            return {"results": []}

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        client = TestClient(app)

        # Health endpoint not rate limited
        for _ in range(5):
            assert client.get("/health").status_code == 200

        # Search endpoint rate limited
        for i in range(3):
            response = client.get("/search")
            assert response.status_code == 200
            assert response.headers["X-RateLimit-Remaining"] == str(2 - i)

        # Exceeded
        response = client.get("/search")
        assert response.status_code == 429

    def test_per_user_rate_limiting(self):
        """Test rate limiting per user."""
        app = FastAPI()

        config = RateLimitConfig(requests=2, window=60)
        app.add_middleware(RateLimitMiddleware, config=config)

        @app.get("/api")
        async def api():
            return {"status": "ok"}

        client = TestClient(app)

        # Simulate different IPs using headers
        # Note: In test client, we'd need to use X-Forwarded-For

        # Default client (same IP)
        for _ in range(2):
            assert client.get("/api").status_code == 200

        assert client.get("/api").status_code == 429

"""Rate limiting middleware and utilities for TR4C3R API.

Provides multiple rate limiting strategies:
- In-memory rate limiting (development/single-instance)
- Token bucket algorithm
- Sliding window algorithm
- Per-endpoint rate limits
- Per-user rate limits
"""

import asyncio
import hashlib
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitStrategy(str, Enum):
    """Rate limiting strategies."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


class RateLimitExceeded(HTTPException):
    """Rate limit exceeded exception."""

    def __init__(
        self,
        detail: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
    ):
        """Initialize rate limit exception.

        Args:
            detail: Error message
            retry_after: Seconds until limit resets
        """
        headers = {}
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)

        super().__init__(
            status_code=429,
            detail=detail,
            headers=headers if headers else None,
        )
        self.retry_after = retry_after


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    # Requests per window
    requests: int = 100

    # Window size in seconds
    window: int = 60

    # Strategy to use
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW

    # Burst allowance (for token bucket)
    burst: int = 10

    # Whether to include headers
    include_headers: bool = True

    # Custom key function
    key_func: Optional[Callable[[Request], str]] = None

    # Endpoints to exclude
    exclude_paths: list[str] = field(default_factory=list)

    # Per-endpoint overrides
    endpoint_limits: dict[str, dict] = field(default_factory=dict)


@dataclass
class RateLimitResult:
    """Result of rate limit check."""

    allowed: bool
    remaining: int
    limit: int
    reset: int  # Unix timestamp
    retry_after: Optional[int] = None


class RateLimiter(ABC):
    """Abstract base class for rate limiters."""

    @abstractmethod
    async def check(self, key: str) -> RateLimitResult:
        """Check if request is allowed.

        Args:
            key: Unique identifier for the client

        Returns:
            RateLimitResult with allowed status and metadata
        """
        pass

    @abstractmethod
    async def reset(self, key: str) -> None:
        """Reset rate limit for a key.

        Args:
            key: Key to reset
        """
        pass


class TokenBucketLimiter(RateLimiter):
    """Token bucket rate limiter.

    Allows bursts of traffic while maintaining an average rate.
    """

    def __init__(
        self,
        rate: float,
        capacity: int,
    ):
        """Initialize token bucket limiter.

        Args:
            rate: Tokens per second
            capacity: Maximum bucket capacity
        """
        self.rate = rate
        self.capacity = capacity
        self._buckets: dict[str, dict[str, float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> RateLimitResult:
        """Check if request is allowed using token bucket."""
        async with self._lock:
            now = time.time()

            if key not in self._buckets:
                self._buckets[key] = {
                    "tokens": self.capacity - 1,
                    "last_update": now,
                }
                return RateLimitResult(
                    allowed=True,
                    remaining=self.capacity - 1,
                    limit=self.capacity,
                    reset=int(now + (1 / self.rate)),
                )

            bucket = self._buckets[key]
            elapsed = now - bucket["last_update"]

            # Add tokens based on time elapsed
            bucket["tokens"] = min(self.capacity, bucket["tokens"] + elapsed * self.rate)
            bucket["last_update"] = now

            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return RateLimitResult(
                    allowed=True,
                    remaining=int(bucket["tokens"]),
                    limit=self.capacity,
                    reset=int(now + (1 / self.rate)),
                )

            # Calculate retry after
            tokens_needed = 1 - bucket["tokens"]
            retry_after = int(tokens_needed / self.rate) + 1

            return RateLimitResult(
                allowed=False,
                remaining=0,
                limit=self.capacity,
                reset=int(now + retry_after),
                retry_after=retry_after,
            )

    async def reset(self, key: str) -> None:
        """Reset token bucket for a key."""
        async with self._lock:
            if key in self._buckets:
                del self._buckets[key]


class SlidingWindowLimiter(RateLimiter):
    """Sliding window rate limiter.

    Provides smoother rate limiting than fixed windows.
    """

    def __init__(
        self,
        limit: int,
        window: int,
    ):
        """Initialize sliding window limiter.

        Args:
            limit: Maximum requests per window
            window: Window size in seconds
        """
        self.limit = limit
        self.window = window
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> RateLimitResult:
        """Check if request is allowed using sliding window."""
        async with self._lock:
            now = time.time()
            window_start = now - self.window

            # Remove old requests
            self._requests[key] = [ts for ts in self._requests[key] if ts > window_start]

            current_count = len(self._requests[key])

            if current_count < self.limit:
                self._requests[key].append(now)
                return RateLimitResult(
                    allowed=True,
                    remaining=self.limit - current_count - 1,
                    limit=self.limit,
                    reset=int(now + self.window),
                )

            # Calculate retry after (when oldest request expires)
            oldest = min(self._requests[key]) if self._requests[key] else now
            retry_after = int(oldest + self.window - now) + 1

            return RateLimitResult(
                allowed=False,
                remaining=0,
                limit=self.limit,
                reset=int(oldest + self.window),
                retry_after=retry_after,
            )

    async def reset(self, key: str) -> None:
        """Reset sliding window for a key."""
        async with self._lock:
            if key in self._requests:
                del self._requests[key]


class FixedWindowLimiter(RateLimiter):
    """Fixed window rate limiter.

    Simple but can allow bursts at window boundaries.
    """

    def __init__(
        self,
        limit: int,
        window: int,
    ):
        """Initialize fixed window limiter.

        Args:
            limit: Maximum requests per window
            window: Window size in seconds
        """
        self.limit = limit
        self.window = window
        self._windows: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> RateLimitResult:
        """Check if request is allowed using fixed window."""
        async with self._lock:
            now = time.time()
            window_key = int(now / self.window)

            if key not in self._windows or self._windows[key]["window"] != window_key:
                self._windows[key] = {
                    "window": window_key,
                    "count": 1,
                }
                reset_time = (window_key + 1) * self.window
                return RateLimitResult(
                    allowed=True,
                    remaining=self.limit - 1,
                    limit=self.limit,
                    reset=int(reset_time),
                )

            if self._windows[key]["count"] < self.limit:
                self._windows[key]["count"] += 1
                reset_time = (window_key + 1) * self.window
                return RateLimitResult(
                    allowed=True,
                    remaining=self.limit - self._windows[key]["count"],
                    limit=self.limit,
                    reset=int(reset_time),
                )

            reset_time = (window_key + 1) * self.window
            retry_after = int(reset_time - now) + 1

            return RateLimitResult(
                allowed=False,
                remaining=0,
                limit=self.limit,
                reset=int(reset_time),
                retry_after=retry_after,
            )

    async def reset(self, key: str) -> None:
        """Reset fixed window for a key."""
        async with self._lock:
            if key in self._windows:
                del self._windows[key]


class RateLimitManager:
    """Manager for multiple rate limiters with different configurations."""

    def __init__(self, default_config: Optional[RateLimitConfig] = None):
        """Initialize rate limit manager.

        Args:
            default_config: Default configuration
        """
        self.config = default_config or RateLimitConfig()
        self._limiters: dict[str, RateLimiter] = {}
        self._endpoint_limiters: dict[str, RateLimiter] = {}

        # Create default limiter
        self._default_limiter = self._create_limiter(self.config)

    def _create_limiter(self, config: RateLimitConfig) -> RateLimiter:
        """Create a limiter based on configuration."""
        if config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            rate = config.requests / config.window
            return TokenBucketLimiter(rate=rate, capacity=config.burst)
        elif config.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return SlidingWindowLimiter(limit=config.requests, window=config.window)
        elif config.strategy == RateLimitStrategy.FIXED_WINDOW:
            return FixedWindowLimiter(limit=config.requests, window=config.window)
        else:
            raise ValueError(f"Unknown strategy: {config.strategy}")

    def get_limiter(self, endpoint: Optional[str] = None) -> RateLimiter:
        """Get limiter for an endpoint.

        Args:
            endpoint: Optional endpoint path

        Returns:
            Appropriate rate limiter
        """
        if endpoint and endpoint in self.config.endpoint_limits:
            if endpoint not in self._endpoint_limiters:
                endpoint_config = RateLimitConfig(
                    **{**vars(self.config), **self.config.endpoint_limits[endpoint]}
                )
                self._endpoint_limiters[endpoint] = self._create_limiter(endpoint_config)
            return self._endpoint_limiters[endpoint]

        return self._default_limiter

    def get_key(self, request: Request) -> str:
        """Get rate limit key from request.

        Args:
            request: FastAPI request

        Returns:
            Unique key for rate limiting
        """
        if self.config.key_func:
            return self.config.key_func(request)

        # Default: Use IP address
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"

        return ip

    def is_excluded(self, path: str) -> bool:
        """Check if path is excluded from rate limiting.

        Args:
            path: Request path

        Returns:
            True if excluded
        """
        for excluded in self.config.exclude_paths:
            if path.startswith(excluded):
                return True
        return False

    async def check(self, request: Request) -> RateLimitResult:
        """Check rate limit for a request.

        Args:
            request: FastAPI request

        Returns:
            RateLimitResult
        """
        key = self.get_key(request)
        path = request.url.path

        if self.is_excluded(path):
            return RateLimitResult(
                allowed=True,
                remaining=self.config.requests,
                limit=self.config.requests,
                reset=int(time.time() + self.config.window),
            )

        limiter = self.get_limiter(path)
        return await limiter.check(key)

    async def reset(self, key: str, endpoint: Optional[str] = None) -> None:
        """Reset rate limit for a key.

        Args:
            key: Key to reset
            endpoint: Optional specific endpoint
        """
        limiter = self.get_limiter(endpoint)
        await limiter.reset(key)

    async def reset_all(self) -> None:
        """Reset all rate limits."""
        # Reset default limiter
        if hasattr(self._default_limiter, "_buckets"):
            self._default_limiter._buckets.clear()
        elif hasattr(self._default_limiter, "_requests"):
            self._default_limiter._requests.clear()
        elif hasattr(self._default_limiter, "_windows"):
            self._default_limiter._windows.clear()

        # Reset endpoint limiters
        for limiter in self._endpoint_limiters.values():
            if hasattr(limiter, "_buckets"):
                limiter._buckets.clear()
            elif hasattr(limiter, "_requests"):
                limiter._requests.clear()
            elif hasattr(limiter, "_windows"):
                limiter._windows.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting."""

    def __init__(
        self,
        app,
        config: Optional[RateLimitConfig] = None,
        manager: Optional[RateLimitManager] = None,
    ):
        """Initialize rate limit middleware.

        Args:
            app: FastAPI application
            config: Rate limit configuration
            manager: Optional pre-configured manager
        """
        super().__init__(app)
        self.manager = manager or RateLimitManager(config)

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request with rate limiting."""
        from starlette.responses import JSONResponse

        result = await self.manager.check(request)

        if not result.allowed:
            headers = {
                "Retry-After": str(result.retry_after or 60),
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(result.reset),
            }
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded. Try again in {result.retry_after} seconds."
                },
                headers=headers,
            )

        response = await call_next(request)

        # Add rate limit headers
        if self.manager.config.include_headers:
            response.headers["X-RateLimit-Limit"] = str(result.limit)
            response.headers["X-RateLimit-Remaining"] = str(result.remaining)
            response.headers["X-RateLimit-Reset"] = str(result.reset)

        return response


def rate_limit(
    requests: int = 10,
    window: int = 60,
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW,
    key_func: Optional[Callable[[Request], str]] = None,
):
    """Decorator for rate limiting individual endpoints.

    Args:
        requests: Maximum requests per window
        window: Window size in seconds
        strategy: Rate limiting strategy
        key_func: Custom function to generate rate limit key

    Returns:
        Decorator function

    Example:
        @app.get("/expensive")
        @rate_limit(requests=5, window=60)
        async def expensive_operation():
            ...
    """
    config = RateLimitConfig(
        requests=requests,
        window=window,
        strategy=strategy,
        key_func=key_func,
    )
    manager = RateLimitManager(config)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find request in args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if request is None:
                request = kwargs.get("request")

            if request is None:
                # No request found, skip rate limiting
                return await func(*args, **kwargs)

            result = await manager.check(request)

            if not result.allowed:
                raise RateLimitExceeded(
                    detail=f"Rate limit exceeded. Try again in {result.retry_after} seconds.",
                    retry_after=result.retry_after,
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Predefined rate limit configurations
RATE_LIMIT_PRESETS = {
    "strict": RateLimitConfig(
        requests=10,
        window=60,
        strategy=RateLimitStrategy.SLIDING_WINDOW,
    ),
    "standard": RateLimitConfig(
        requests=100,
        window=60,
        strategy=RateLimitStrategy.SLIDING_WINDOW,
    ),
    "relaxed": RateLimitConfig(
        requests=1000,
        window=60,
        strategy=RateLimitStrategy.SLIDING_WINDOW,
    ),
    "api": RateLimitConfig(
        requests=60,
        window=60,
        strategy=RateLimitStrategy.TOKEN_BUCKET,
        burst=10,
    ),
    "search": RateLimitConfig(
        requests=30,
        window=60,
        strategy=RateLimitStrategy.SLIDING_WINDOW,
        endpoint_limits={
            "/search/email": {"requests": 10, "window": 60},
            "/search/phone": {"requests": 10, "window": 60},
            "/search/username": {"requests": 20, "window": 60},
        },
    ),
}


def get_rate_limit_config(preset: str = "standard") -> RateLimitConfig:
    """Get a predefined rate limit configuration.

    Args:
        preset: Name of the preset

    Returns:
        RateLimitConfig
    """
    if preset not in RATE_LIMIT_PRESETS:
        raise ValueError(f"Unknown preset: {preset}. Available: {list(RATE_LIMIT_PRESETS.keys())}")
    return RATE_LIMIT_PRESETS[preset]

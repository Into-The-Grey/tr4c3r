"""Caching layer for TR4C3R search results.

This module provides a high-level caching interface that integrates with
the database cache table.  It supports TTL-based expiration, cache key
generation, and result serialization.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, List, Optional, TypeVar, Union

from src.core.data_models import Result
from src.storage.database import Database

logger = logging.getLogger(__name__)

# Default TTL values (in seconds)
DEFAULT_TTL = 3600  # 1 hour
SHORT_TTL = 300  # 5 minutes (for volatile data)
LONG_TTL = 86400  # 24 hours (for stable data)

# Type variable for async functions returning List[Result]
F = TypeVar("F", bound=Callable[..., Awaitable[List[Result]]])


class CacheManager:
    """Manages caching of search results with TTL support."""

    def __init__(
        self,
        db: Optional[Database] = None,
        default_ttl: int = DEFAULT_TTL,
        enabled: bool = True,
    ) -> None:
        """Initialize the cache manager.

        Args:
            db: Database instance (creates one if not provided)
            default_ttl: Default time-to-live in seconds
            enabled: Whether caching is enabled
        """
        self._db = db
        self.default_ttl = default_ttl
        self.enabled = enabled
        self.logger = logging.getLogger(self.__class__.__name__)
        self._hits = 0
        self._misses = 0

    @property
    def db(self) -> Database:
        """Lazy-load database connection."""
        if self._db is None:
            self._db = Database()
        return self._db

    def _generate_key(self, prefix: str, *args: Any, **kwargs: Any) -> str:
        """Generate a cache key from prefix and arguments.

        Args:
            prefix: Key prefix (e.g., 'username_search')
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Hashed cache key
        """
        # Create a deterministic string from arguments
        key_parts = [prefix]
        key_parts.extend(str(arg) for arg in args)
        key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
        key_string = ":".join(key_parts)

        # Hash for consistent key length
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()[:32]
        return f"{prefix}:{key_hash}"

    def _serialize_results(self, results: List[Result]) -> str:
        """Serialize Result objects to JSON."""
        return json.dumps(
            [
                {
                    "source": r.source,
                    "identifier": r.identifier,
                    "url": r.url,
                    "confidence": r.confidence,
                    "timestamp": r.timestamp.isoformat(),
                    "metadata": r.metadata,
                }
                for r in results
            ]
        )

    def _deserialize_results(self, data: str) -> List[Result]:
        """Deserialize JSON to Result objects."""
        items = json.loads(data)
        return [
            Result(
                source=item["source"],
                identifier=item["identifier"],
                url=item.get("url"),
                confidence=item.get("confidence", 0.5),
                timestamp=datetime.fromisoformat(item["timestamp"]),
                metadata=item.get("metadata", {}),
            )
            for item in items
        ]

    def get(self, prefix: str, *args: Any, **kwargs: Any) -> Optional[List[Result]]:
        """Get cached results.

        Args:
            prefix: Cache key prefix
            *args: Arguments used to generate key
            **kwargs: Keyword arguments used to generate key

        Returns:
            Cached results or None if not found/expired
        """
        if not self.enabled:
            return None

        key = self._generate_key(prefix, *args, **kwargs)

        try:
            cached = self.db.cache_get(key)
            if cached:
                self._hits += 1
                self.logger.debug("Cache hit for key: %s", key)
                return self._deserialize_results(cached)
            else:
                self._misses += 1
                self.logger.debug("Cache miss for key: %s", key)
                return None
        except Exception as e:
            self.logger.warning("Cache get failed: %s", e)
            return None

    def set(
        self,
        results: List[Result],
        prefix: str,
        *args: Any,
        ttl: Optional[int] = None,
        **kwargs: Any,
    ) -> bool:
        """Store results in cache.

        Args:
            results: Results to cache
            prefix: Cache key prefix
            *args: Arguments used to generate key
            ttl: Time-to-live in seconds (uses default if not specified)
            **kwargs: Keyword arguments used to generate key

        Returns:
            True if cached successfully
        """
        if not self.enabled:
            return False

        key = self._generate_key(prefix, *args, **kwargs)
        ttl = ttl if ttl is not None else self.default_ttl

        try:
            serialized = self._serialize_results(results)
            self.db.cache_set(key, serialized, ttl)
            self.logger.debug("Cached %d results for key: %s (TTL: %ds)", len(results), key, ttl)
            return True
        except Exception as e:
            self.logger.warning("Cache set failed: %s", e)
            return False

    def invalidate(self, prefix: str, *args: Any, **kwargs: Any) -> bool:
        """Invalidate a specific cache entry.

        Args:
            prefix: Cache key prefix
            *args: Arguments used to generate key
            **kwargs: Keyword arguments used to generate key

        Returns:
            True if invalidated successfully
        """
        key = self._generate_key(prefix, *args, **kwargs)

        try:
            self.db.cache_clear(key)
            self.logger.debug("Invalidated cache key: %s", key)
            return True
        except Exception as e:
            self.logger.warning("Cache invalidate failed: %s", e)
            return False

    def invalidate_prefix(self, prefix: str) -> int:
        """Invalidate all cache entries with a given prefix.

        Args:
            prefix: Cache key prefix to match

        Returns:
            Number of entries invalidated
        """
        try:
            deleted = self.db.cache_clear(f"{prefix}:%")
            self.logger.info("Invalidated %d cache entries for prefix: %s", deleted, prefix)
            return deleted
        except Exception as e:
            self.logger.warning("Cache prefix invalidation failed: %s", e)
            return 0

    def clear_all(self) -> int:
        """Clear all cache entries.

        Returns:
            Number of entries cleared
        """
        try:
            deleted = self.db.cache_clear()
            self.logger.info("Cleared all cache entries: %d", deleted)
            return deleted
        except Exception as e:
            self.logger.warning("Cache clear failed: %s", e)
            return 0

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        try:
            deleted = self.db.cleanup_expired_cache()
            self.logger.info("Cleaned up %d expired cache entries", deleted)
            return deleted
        except Exception as e:
            self.logger.warning("Cache cleanup failed: %s", e)
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "total_requests": total,
            "hit_rate_percent": round(hit_rate, 2),
            "enabled": self.enabled,
            "default_ttl": self.default_ttl,
        }


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


def get_cache_manager() -> CacheManager:
    """Get or create the global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager


def set_cache_manager(manager: CacheManager) -> None:
    """Set the global cache manager instance."""
    global _cache_manager
    _cache_manager = manager


def cached_search(
    prefix: str,
    ttl: Optional[int] = None,
    cache_empty: bool = False,
) -> Callable[[F], F]:
    """Decorator to cache search results.

    Args:
        prefix: Cache key prefix
        ttl: Time-to-live in seconds
        cache_empty: Whether to cache empty results

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> List[Result]:
            cache = get_cache_manager()

            # Skip caching for certain kwargs
            skip_cache = kwargs.pop("skip_cache", False)
            if skip_cache:
                return await func(*args, **kwargs)

            # Try to get from cache (exclude 'self' from key generation)
            cache_args = args[1:] if args and hasattr(args[0], "__class__") else args
            cached = cache.get(prefix, *cache_args, **kwargs)
            if cached is not None:
                return cached  # type: ignore

            # Execute function
            result = await func(*args, **kwargs)

            # Cache result
            if result or cache_empty:
                cache.set(result, prefix, *cache_args, ttl=ttl, **kwargs)

            return result

        return wrapper  # type: ignore

    return decorator

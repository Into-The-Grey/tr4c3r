"""Tests for the cache module."""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.core.cache import (
    CacheManager,
    get_cache_manager,
    set_cache_manager,
    cached_search,
    DEFAULT_TTL,
    SHORT_TTL,
    LONG_TTL,
)
from src.core.data_models import Result


class TestCacheManager:
    """Tests for CacheManager class."""

    def test_init_defaults(self):
        """Test default initialization."""
        cache = CacheManager(enabled=True)
        assert cache.enabled is True
        assert cache.default_ttl == DEFAULT_TTL

    def test_init_custom_ttl(self):
        """Test custom TTL initialization."""
        cache = CacheManager(default_ttl=120, enabled=True)
        assert cache.default_ttl == 120

    def test_disabled_cache_returns_none(self):
        """Test that disabled cache returns None."""
        cache = CacheManager(enabled=False)
        result = cache.get("prefix", "query")
        assert result is None

    def test_disabled_cache_does_not_set(self):
        """Test that disabled cache does not store."""
        cache = CacheManager(enabled=False)
        results = [Result(source="test", identifier="test", confidence=0.5)]
        stored = cache.set(results, "prefix", "query")
        assert stored is False

    def test_generate_key(self):
        """Test cache key generation."""
        cache = CacheManager(enabled=True)
        key1 = cache._generate_key("search", "query1")
        key2 = cache._generate_key("search", "query2")
        key3 = cache._generate_key("search", "query1")

        # Same inputs should produce same key
        assert key1 == key3
        # Different inputs should produce different keys
        assert key1 != key2
        # Key should start with prefix
        assert key1.startswith("search:")

    def test_generate_key_with_kwargs(self):
        """Test cache key generation with kwargs."""
        cache = CacheManager(enabled=True)
        key1 = cache._generate_key("search", "query", fuzzy=True)
        key2 = cache._generate_key("search", "query", fuzzy=False)

        # Different kwargs should produce different keys
        assert key1 != key2

    def test_serialize_results(self):
        """Test result serialization."""
        cache = CacheManager(enabled=True)
        results = [
            Result(
                source="test",
                identifier="test_id",
                url="https://example.com",
                confidence=0.9,
                metadata={"key": "value"},
            )
        ]

        serialized = cache._serialize_results(results)
        assert isinstance(serialized, str)

        # Should be valid JSON
        parsed = json.loads(serialized)
        assert len(parsed) == 1
        assert parsed[0]["source"] == "test"
        assert parsed[0]["identifier"] == "test_id"

    def test_deserialize_results(self):
        """Test result deserialization."""
        cache = CacheManager(enabled=True)
        data = json.dumps(
            [
                {
                    "source": "test",
                    "identifier": "test_id",
                    "url": "https://example.com",
                    "confidence": 0.9,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {"key": "value"},
                }
            ]
        )

        results = cache._deserialize_results(data)
        assert len(results) == 1
        assert results[0].source == "test"
        assert results[0].identifier == "test_id"
        assert results[0].confidence == 0.9
        assert results[0].metadata == {"key": "value"}

    def test_get_stats(self):
        """Test cache statistics."""
        cache = CacheManager(enabled=True)
        cache._hits = 10
        cache._misses = 5

        stats = cache.get_stats()
        assert stats["hits"] == 10
        assert stats["misses"] == 5
        assert stats["total_requests"] == 15
        assert stats["hit_rate_percent"] == pytest.approx(66.67, rel=0.01)


class TestCacheManagerWithMockedDB:
    """Tests for CacheManager with mocked database."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock database."""
        db = MagicMock()
        db.cache_get.return_value = None
        db.cache_set.return_value = None
        db.cache_clear.return_value = 0
        db.cleanup_expired_cache.return_value = 0
        return db

    def test_get_miss(self, mock_db):
        """Test cache miss."""
        cache = CacheManager(db=mock_db, enabled=True)
        result = cache.get("prefix", "query")

        assert result is None
        assert cache._misses == 1
        mock_db.cache_get.assert_called_once()

    def test_get_hit(self, mock_db):
        """Test cache hit."""
        cached_data = json.dumps(
            [
                {
                    "source": "test",
                    "identifier": "test_id",
                    "url": None,
                    "confidence": 0.5,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {},
                }
            ]
        )
        mock_db.cache_get.return_value = cached_data

        cache = CacheManager(db=mock_db, enabled=True)
        result = cache.get("prefix", "query")

        assert result is not None
        assert len(result) == 1
        assert cache._hits == 1

    def test_set(self, mock_db):
        """Test cache set."""
        cache = CacheManager(db=mock_db, enabled=True)
        results = [Result(source="test", identifier="id", confidence=0.5)]

        stored = cache.set(results, "prefix", "query")

        assert stored is True
        mock_db.cache_set.assert_called_once()

    def test_invalidate(self, mock_db):
        """Test cache invalidation."""
        cache = CacheManager(db=mock_db, enabled=True)
        cache.invalidate("prefix", "query")

        mock_db.cache_clear.assert_called_once()

    def test_invalidate_prefix(self, mock_db):
        """Test prefix invalidation."""
        mock_db.cache_clear.return_value = 5

        cache = CacheManager(db=mock_db, enabled=True)
        deleted = cache.invalidate_prefix("prefix")

        assert deleted == 5
        mock_db.cache_clear.assert_called_with("prefix:%")

    def test_clear_all(self, mock_db):
        """Test clearing all cache."""
        mock_db.cache_clear.return_value = 10

        cache = CacheManager(db=mock_db, enabled=True)
        deleted = cache.clear_all()

        assert deleted == 10
        mock_db.cache_clear.assert_called_with()

    def test_cleanup_expired(self, mock_db):
        """Test cleanup of expired entries."""
        mock_db.cleanup_expired_cache.return_value = 3

        cache = CacheManager(db=mock_db, enabled=True)
        deleted = cache.cleanup_expired()

        assert deleted == 3
        mock_db.cleanup_expired_cache.assert_called_once()


class TestGlobalCacheManager:
    """Tests for global cache manager functions."""

    def test_get_cache_manager(self):
        """Test getting global cache manager."""
        # Reset global state
        set_cache_manager(None)  # type: ignore

        manager = get_cache_manager()
        assert manager is not None
        assert isinstance(manager, CacheManager)

    def test_set_cache_manager(self):
        """Test setting global cache manager."""
        custom = CacheManager(default_ttl=999, enabled=True)
        set_cache_manager(custom)

        manager = get_cache_manager()
        assert manager.default_ttl == 999


class TestCachedSearchDecorator:
    """Tests for cached_search decorator."""

    @pytest.mark.asyncio
    async def test_decorator_caches_results(self):
        """Test that decorator caches function results."""
        call_count = 0

        class MockSearcher:
            @cached_search("test_prefix", ttl=60)
            async def search(self, query: str) -> list:
                nonlocal call_count
                call_count += 1
                return [Result(source="test", identifier=query, confidence=0.5)]

        # Use mock cache manager
        mock_db = MagicMock()
        mock_db.cache_get.return_value = None
        mock_db.cache_set.return_value = None

        cache = CacheManager(db=mock_db, enabled=True)
        set_cache_manager(cache)

        searcher = MockSearcher()

        # First call should execute function
        results1 = await searcher.search("query1")
        assert call_count == 1
        assert len(results1) == 1

    @pytest.mark.asyncio
    async def test_decorator_skip_cache(self):
        """Test that skip_cache bypasses caching."""
        call_count = 0

        class MockSearcher:
            @cached_search("test_prefix", ttl=60)
            async def search(self, query: str) -> list:
                nonlocal call_count
                call_count += 1
                return [Result(source="test", identifier=query, confidence=0.5)]

        cache = CacheManager(enabled=True)
        set_cache_manager(cache)

        searcher = MockSearcher()

        # Call with skip_cache
        results = await searcher.search("query1", skip_cache=True)
        assert call_count == 1
        assert len(results) == 1


class TestTTLConstants:
    """Tests for TTL constants."""

    def test_ttl_values(self):
        """Test TTL constant values."""
        assert DEFAULT_TTL == 3600  # 1 hour
        assert SHORT_TTL == 300  # 5 minutes
        assert LONG_TTL == 86400  # 24 hours

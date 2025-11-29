"""Tests for the database storage module."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.core.data_models import Result
from src.storage.database import Database


class TestDatabase:
    """Test the Database class."""

    @pytest.fixture
    def temp_db(self) -> Database:
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        db = Database(db_path)
        yield db

        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    def sample_results(self) -> list[Result]:
        """Create sample results for testing."""
        return [
            Result(
                source="test:source1",
                identifier="test123",
                url="https://example.com/1",
                confidence=0.9,
                timestamp=datetime.now(timezone.utc),
                metadata={"key": "value1"},
            ),
            Result(
                source="test:source2",
                identifier="test456",
                url="https://example.com/2",
                confidence=0.7,
                timestamp=datetime.now(timezone.utc),
                metadata={"key": "value2"},
            ),
        ]

    def test_database_initialization(self, temp_db: Database) -> None:
        """Test that database initializes with proper schema."""
        assert Path(temp_db.db_path).exists()

        # Check that tables exist
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT name FROM sqlite_master 
                WHERE type='table'
                ORDER BY name
            """
            )
            tables = [row[0] for row in cursor.fetchall()]

            assert "search_history" in tables
            assert "results" in tables
            assert "cache" in tables

    def test_save_search(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test saving a search with results."""
        search_id = temp_db.save_search(
            search_type="username",
            query="testuser",
            results=sample_results,
            metadata={"platform": "github"},
        )

        assert search_id > 0

        # Verify search was saved
        history = temp_db.get_search_history()
        assert len(history) == 1
        assert history[0]["search_type"] == "username"
        assert history[0]["query"] == "testuser"
        assert history[0]["result_count"] == 2

    def test_get_search_results(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test retrieving results for a search."""
        search_id = temp_db.save_search(
            search_type="email", query="test@example.com", results=sample_results
        )

        retrieved_results = temp_db.get_search_results(search_id)

        assert len(retrieved_results) == 2
        # Results should be ordered by confidence DESC
        assert retrieved_results[0].confidence == 0.9
        assert retrieved_results[0].identifier == "test123"
        assert retrieved_results[1].confidence == 0.7

    def test_get_search_history_filtered(
        self, temp_db: Database, sample_results: list[Result]
    ) -> None:
        """Test filtering search history by type."""
        # Save multiple searches
        temp_db.save_search("username", "user1", sample_results)
        temp_db.save_search("email", "test@example.com", sample_results)
        temp_db.save_search("username", "user2", sample_results)

        # Get all history
        all_history = temp_db.get_search_history()
        assert len(all_history) == 3

        # Get filtered history
        username_history = temp_db.get_search_history(search_type="username")
        assert len(username_history) == 2
        assert all(h["search_type"] == "username" for h in username_history)

    def test_cache_set_and_get(self, temp_db: Database) -> None:
        """Test caching functionality."""
        temp_db.cache_set("test_key", "test_value")

        value = temp_db.cache_get("test_key")
        assert value == "test_value"

    def test_cache_expiration(self, temp_db: Database) -> None:
        """Test that cache entries expire correctly."""
        # Set cache with -1 second TTL (already expired)
        temp_db.cache_set("expire_key", "expire_value", ttl_seconds=-1)

        # Should be expired
        value = temp_db.cache_get("expire_key")
        assert value is None

    def test_cache_get_nonexistent(self, temp_db: Database) -> None:
        """Test getting a cache key that doesn't exist."""
        value = temp_db.cache_get("nonexistent_key")
        assert value is None

    def test_cache_clear_all(self, temp_db: Database) -> None:
        """Test clearing all cache entries."""
        temp_db.cache_set("key1", "value1")
        temp_db.cache_set("key2", "value2")
        temp_db.cache_set("key3", "value3")

        deleted = temp_db.cache_clear()
        assert deleted == 3

        # Verify all are gone
        assert temp_db.cache_get("key1") is None
        assert temp_db.cache_get("key2") is None

    def test_cache_clear_pattern(self, temp_db: Database) -> None:
        """Test clearing cache with pattern matching."""
        temp_db.cache_set("user:1", "data1")
        temp_db.cache_set("user:2", "data2")
        temp_db.cache_set("post:1", "data3")

        deleted = temp_db.cache_clear("user:%")
        assert deleted == 2

        # User keys should be gone
        assert temp_db.cache_get("user:1") is None
        assert temp_db.cache_get("user:2") is None

        # Post key should still exist
        assert temp_db.cache_get("post:1") == "data3"

    def test_export_json(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test exporting search results as JSON."""
        search_id = temp_db.save_search("username", "testuser", sample_results)

        json_export = temp_db.export_search(search_id, format="json")

        data = json.loads(json_export)
        assert "search" in data
        assert "results" in data
        assert data["search"]["search_type"] == "username"
        assert len(data["results"]) == 2

    def test_export_csv(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test exporting search results as CSV."""
        search_id = temp_db.save_search("email", "test@example.com", sample_results)

        csv_export = temp_db.export_search(search_id, format="csv")

        lines = csv_export.split("\n")
        assert lines[0] == "source,identifier,url,confidence,timestamp"
        assert len(lines) == 3  # Header + 2 results

    def test_export_xml(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test exporting search results as XML."""
        search_id = temp_db.save_search("phone", "+1234567890", sample_results)

        xml_export = temp_db.export_search(search_id, format="xml")

        assert '<?xml version="1.0"' in xml_export
        assert "<search>" in xml_export
        assert "<type>phone</type>" in xml_export
        assert "<results>" in xml_export

    def test_export_invalid_format(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test that invalid export format raises error."""
        search_id = temp_db.save_search("username", "test", sample_results)

        with pytest.raises(ValueError, match="Unsupported export format"):
            temp_db.export_search(search_id, format="invalid")

    def test_get_statistics(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test retrieving database statistics."""
        # Add some data
        temp_db.save_search("username", "user1", sample_results)
        temp_db.save_search("email", "test@example.com", sample_results)
        temp_db.cache_set("key1", "value1")

        stats = temp_db.get_statistics()

        assert stats["total_searches"] == 2
        assert stats["total_results"] == 4  # 2 results per search
        assert stats["searches_by_type"]["username"] == 1
        assert stats["searches_by_type"]["email"] == 1
        assert stats["cache_entries"] == 1
        assert "database_size_bytes" in stats

    def test_cleanup_expired_cache(self, temp_db: Database) -> None:
        """Test cleaning up expired cache entries."""
        # Add expired entry
        temp_db.cache_set("expired", "value", ttl_seconds=-1)

        # Add non-expired entry
        temp_db.cache_set("valid", "value", ttl_seconds=3600)

        deleted = temp_db.cleanup_expired_cache()

        # At least the expired one should be deleted
        assert deleted >= 1
        assert temp_db.cache_get("expired") is None
        assert temp_db.cache_get("valid") == "value"

    def test_cache_hit_count(self, temp_db: Database) -> None:
        """Test that cache hit count increments."""
        temp_db.cache_set("counter", "value")

        # Access multiple times
        temp_db.cache_get("counter")
        temp_db.cache_get("counter")
        temp_db.cache_get("counter")

        stats = temp_db.get_statistics()
        assert stats["cache_hits"] >= 3

    def test_metadata_persistence(self, temp_db: Database) -> None:
        """Test that metadata is properly saved and retrieved."""
        results = [
            Result(
                source="test",
                identifier="id1",
                url="http://example.com",
                confidence=0.8,
                timestamp=datetime.now(timezone.utc),
                metadata={"complex": {"nested": "data"}, "list": [1, 2, 3]},
            )
        ]

        search_id = temp_db.save_search("test", "query", results)
        retrieved = temp_db.get_search_results(search_id)

        assert retrieved[0].metadata["complex"]["nested"] == "data"
        assert retrieved[0].metadata["list"] == [1, 2, 3]

    def test_search_history_limit(self, temp_db: Database, sample_results: list[Result]) -> None:
        """Test that history limit works correctly."""
        # Add 10 searches
        for i in range(10):
            temp_db.save_search("username", f"user{i}", sample_results)

        # Get only 5
        history = temp_db.get_search_history(limit=5)
        assert len(history) == 5

        # Verify we got 5 searches (exact order may vary due to same timestamp)
        queries = [h["query"] for h in history]
        assert len(queries) == 5
        assert all(q.startswith("user") for q in queries)

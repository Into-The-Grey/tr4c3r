"""Tests for the deduplication module."""

import pytest
from datetime import datetime, timezone

from src.core.deduplication import (
    ResultDeduplicator,
    deduplicate_results,
    merge_result_lists,
)
from src.core.data_models import Result


class TestResultDeduplicator:
    """Tests for ResultDeduplicator class."""

    def test_init_defaults(self):
        """Test default initialization."""
        dedup = ResultDeduplicator()
        assert dedup.merge_metadata is True

    def test_empty_list(self):
        """Test deduplicating empty list."""
        dedup = ResultDeduplicator()
        result = dedup.deduplicate([])
        assert result == []

    def test_single_result(self):
        """Test deduplicating single result."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="test",
                identifier="user",
                url="https://example.com/user",
                confidence=0.9,
            )
        ]
        deduped = dedup.deduplicate(results)
        assert len(deduped) == 1
        assert deduped[0].source == "test"

    def test_duplicate_urls(self):
        """Test deduplicating results with same URL."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="source1",
                identifier="user",
                url="https://example.com/user",
                confidence=0.8,
            ),
            Result(
                source="source2",
                identifier="user",
                url="https://example.com/user",
                confidence=0.9,
            ),
        ]
        deduped = dedup.deduplicate(results)

        assert len(deduped) == 1
        # Should keep higher confidence
        assert deduped[0].confidence == 0.9
        assert deduped[0].source == "source2"

    def test_different_urls(self):
        """Test that different URLs are not deduplicated."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="source1",
                identifier="user",
                url="https://example.com/user",
                confidence=0.8,
            ),
            Result(
                source="source2",
                identifier="user",
                url="https://other.com/user",
                confidence=0.9,
            ),
        ]
        deduped = dedup.deduplicate(results)

        assert len(deduped) == 2

    def test_url_normalization(self):
        """Test URL normalization for comparison."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="source1",
                identifier="user",
                url="https://example.com/user/",
                confidence=0.8,
            ),
            Result(
                source="source2",
                identifier="user",
                url="https://EXAMPLE.COM/user",
                confidence=0.9,
            ),
        ]
        deduped = dedup.deduplicate(results)

        # Should be considered the same URL after normalization
        assert len(deduped) == 1

    def test_metadata_merging(self):
        """Test that metadata is merged from duplicates."""
        dedup = ResultDeduplicator(merge_metadata=True)
        results = [
            Result(
                source="source1",
                identifier="user",
                url="https://example.com/user",
                confidence=0.8,
                metadata={"key1": "value1"},
            ),
            Result(
                source="source2",
                identifier="user",
                url="https://example.com/user",
                confidence=0.9,
                metadata={"key2": "value2"},
            ),
        ]
        deduped = dedup.deduplicate(results)

        assert len(deduped) == 1
        # Should have merged metadata
        assert deduped[0].metadata.get("key2") == "value2"
        assert "also_found_in" in deduped[0].metadata

    def test_no_metadata_merging(self):
        """Test that metadata is not merged when disabled."""
        dedup = ResultDeduplicator(merge_metadata=False)
        results = [
            Result(
                source="source1",
                identifier="user",
                url="https://example.com/user",
                confidence=0.8,
                metadata={"key1": "value1"},
            ),
            Result(
                source="source2",
                identifier="user",
                url="https://example.com/user",
                confidence=0.9,
                metadata={"key2": "value2"},
            ),
        ]
        deduped = dedup.deduplicate(results)

        assert len(deduped) == 1
        # Should only have the winning result's metadata
        assert "also_found_in" not in deduped[0].metadata

    def test_none_url(self):
        """Test handling of None URLs."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="source1",
                identifier="user",
                url=None,
                confidence=0.8,
            ),
            Result(
                source="source2",
                identifier="user",
                url=None,
                confidence=0.9,
            ),
        ]
        deduped = dedup.deduplicate(results)

        # None URLs should be treated as empty string and grouped together
        assert len(deduped) == 1

    def test_sorted_by_confidence(self):
        """Test that results are sorted by confidence."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="source1",
                identifier="user1",
                url="https://example1.com",
                confidence=0.5,
            ),
            Result(
                source="source2",
                identifier="user2",
                url="https://example2.com",
                confidence=0.9,
            ),
            Result(
                source="source3",
                identifier="user3",
                url="https://example3.com",
                confidence=0.7,
            ),
        ]
        deduped = dedup.deduplicate(results)

        assert len(deduped) == 3
        assert deduped[0].confidence == 0.9
        assert deduped[1].confidence == 0.7
        assert deduped[2].confidence == 0.5


class TestDeduplicateByIdentifier:
    """Tests for identifier-based deduplication."""

    def test_deduplicate_by_identifier(self):
        """Test deduplicating by identifier."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="github:api",
                identifier="user",
                url="https://github.com/user",
                confidence=0.8,
            ),
            Result(
                source="github:web",
                identifier="user",
                url="https://github.com/user/profile",
                confidence=0.9,
            ),
            Result(
                source="twitter:api",
                identifier="user",
                url="https://twitter.com/user",
                confidence=0.7,
            ),
        ]
        deduped = dedup.deduplicate_by_identifier(results)

        # Should have 2: one github, one twitter
        assert len(deduped) == 2

    def test_keeps_higher_confidence(self):
        """Test that higher confidence is kept when deduplicating by identifier."""
        dedup = ResultDeduplicator()
        results = [
            Result(
                source="github:low",
                identifier="USER",
                url="https://github.com/user",
                confidence=0.5,
            ),
            Result(
                source="github:high",
                identifier="user",
                url="https://github.com/user/profile",
                confidence=0.9,
            ),
        ]
        deduped = dedup.deduplicate_by_identifier(results)

        assert len(deduped) == 1
        assert deduped[0].confidence == 0.9


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_deduplicate_results_by_url(self):
        """Test deduplicate_results with by_url=True."""
        results = [
            Result(source="s1", identifier="u", url="https://a.com", confidence=0.8),
            Result(source="s2", identifier="u", url="https://a.com", confidence=0.9),
        ]
        deduped = deduplicate_results(results, by_url=True)
        assert len(deduped) == 1

    def test_deduplicate_results_by_identifier(self):
        """Test deduplicate_results with by_url=False."""
        results = [
            Result(source="s1:a", identifier="user", url="https://a.com", confidence=0.8),
            Result(source="s1:b", identifier="user", url="https://b.com", confidence=0.9),
        ]
        deduped = deduplicate_results(results, by_url=False)
        assert len(deduped) == 1

    def test_merge_result_lists_with_dedup(self):
        """Test merging result lists with deduplication."""
        list1 = [
            Result(source="s1", identifier="u", url="https://a.com", confidence=0.8),
        ]
        list2 = [
            Result(source="s2", identifier="u", url="https://a.com", confidence=0.9),
        ]

        merged = merge_result_lists(list1, list2, deduplicate=True)
        assert len(merged) == 1

    def test_merge_result_lists_without_dedup(self):
        """Test merging result lists without deduplication."""
        list1 = [
            Result(source="s1", identifier="u", url="https://a.com", confidence=0.8),
        ]
        list2 = [
            Result(source="s2", identifier="u", url="https://a.com", confidence=0.9),
        ]

        merged = merge_result_lists(list1, list2, deduplicate=False)
        assert len(merged) == 2

    def test_merge_empty_lists(self):
        """Test merging empty lists."""
        merged = merge_result_lists([], [], deduplicate=True)
        assert merged == []

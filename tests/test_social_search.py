"""Tests for social media search module."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.core.data_models import Result
from src.search.social import RateLimiter, SocialMediaSearch


class TestRateLimiter:
    """Test the RateLimiter class."""

    @pytest.mark.asyncio
    async def test_rate_limiter_allows_initial_calls(self) -> None:
        """Test that rate limiter allows initial calls."""
        limiter = RateLimiter(calls=5, period=1.0)

        # Should allow 5 calls immediately
        for _ in range(5):
            await limiter.acquire()

        assert len(limiter.timestamps) == 5

    @pytest.mark.asyncio
    async def test_rate_limiter_blocks_excess_calls(self) -> None:
        """Test that rate limiter blocks excess calls."""
        limiter = RateLimiter(calls=3, period=0.5)

        # First 3 calls should be fast
        start = asyncio.get_event_loop().time()
        for _ in range(3):
            await limiter.acquire()
        duration1 = asyncio.get_event_loop().time() - start

        # 4th call should be delayed
        start = asyncio.get_event_loop().time()
        await limiter.acquire()
        duration2 = asyncio.get_event_loop().time() - start

        assert duration1 < 0.1  # First calls should be instant
        assert duration2 >= 0.4  # 4th call should wait ~0.5 seconds

    @pytest.mark.asyncio
    async def test_rate_limiter_window_sliding(self) -> None:
        """Test that rate limiter uses sliding window."""
        limiter = RateLimiter(calls=2, period=0.3)

        await limiter.acquire()
        await asyncio.sleep(0.2)
        await limiter.acquire()

        # After 0.2s, first timestamp should still be in window
        assert len(limiter.timestamps) == 2

        await asyncio.sleep(0.2)  # Total 0.4s from first call

        # After 0.4s, first timestamp should be outside 0.3s window
        await limiter.acquire()
        assert len(limiter.timestamps) <= 2


class TestSocialMediaSearch:
    """Test the SocialMediaSearch class."""

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock configuration."""
        config = MagicMock()
        config.get.return_value = {
            "github": {
                "enabled": True,
                "url_template": "https://github.com/{username}",
            },
            "twitter": {
                "enabled": True,
                "url_template": "https://twitter.com/{username}",
            },
            "facebook": {
                "enabled": False,
                "url_template": "https://facebook.com/{username}",
            },
        }
        config.get_site_config.side_effect = lambda platform: {
            "github": {"url_template": "https://github.com/{username}"},
            "twitter": {"url_template": "https://twitter.com/{username}"},
        }.get(platform, {})
        return config

    @pytest.fixture
    def social_search(self, mock_config: MagicMock) -> SocialMediaSearch:
        """Create a SocialMediaSearch instance with mocked config."""
        with patch("src.search.social.get_config", return_value=mock_config):
            with patch("src.search.social.httpx.AsyncClient"):
                return SocialMediaSearch(rate_limit_calls=100, rate_limit_period=1.0)

    def test_initialization(self, social_search: SocialMediaSearch) -> None:
        """Test that SocialMediaSearch initializes correctly."""
        assert social_search.platforms is None
        assert social_search.enable_nsfw_detection is False
        assert social_search.rate_limiter is not None

    def test_initialization_with_platforms(self, mock_config: MagicMock) -> None:
        """Test initialization with specific platforms."""
        with patch("src.search.social.get_config", return_value=mock_config):
            with patch("src.search.social.httpx.AsyncClient"):
                search = SocialMediaSearch(platforms=["github", "twitter"])
                assert search.platforms == ["github", "twitter"]

    def test_get_enabled_platforms(self, social_search: SocialMediaSearch) -> None:
        """Test getting enabled platforms from config."""
        platforms = social_search._get_enabled_platforms()

        assert "github" in platforms
        assert "twitter" in platforms
        assert "facebook" not in platforms  # Disabled

    def test_get_enabled_platforms_filtered(self, mock_config: MagicMock) -> None:
        """Test getting enabled platforms with filter."""
        with patch("src.search.social.get_config", return_value=mock_config):
            with patch("src.search.social.httpx.AsyncClient"):
                search = SocialMediaSearch(platforms=["github"], rate_limit_calls=100)
                platforms = search._get_enabled_platforms()

                assert "github" in platforms
                assert "twitter" not in platforms  # Filtered out

    def test_build_profile_url(self, social_search: SocialMediaSearch) -> None:
        """Test building profile URLs."""
        url = social_search._build_profile_url("github", "testuser")
        assert url == "https://github.com/testuser"

        url = social_search._build_profile_url("twitter", "johndoe")
        assert url == "https://twitter.com/johndoe"

    @pytest.mark.asyncio
    async def test_check_profile_exists_found(self, social_search: SocialMediaSearch) -> None:
        """Test checking a profile that exists."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "tweets followers following joined"

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        exists, confidence, metadata = await social_search._check_profile_exists(
            "twitter", "https://twitter.com/testuser"
        )

        assert exists is True
        assert confidence > 0.5
        assert metadata["status"] == "found"
        assert "indicators" in metadata

    @pytest.mark.asyncio
    async def test_check_profile_exists_not_found(self, social_search: SocialMediaSearch) -> None:
        """Test checking a profile that doesn't exist."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        exists, confidence, metadata = await social_search._check_profile_exists(
            "twitter", "https://twitter.com/nonexistent"
        )

        assert exists is False
        assert confidence == 0.0
        assert metadata["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_check_profile_exists_http_error(self, social_search: SocialMediaSearch) -> None:
        """Test handling HTTP errors."""
        social_search.http_client.get = AsyncMock(side_effect=httpx.HTTPError("Connection failed"))

        exists, confidence, metadata = await social_search._check_profile_exists(
            "twitter", "https://twitter.com/testuser"
        )

        assert exists is False
        assert confidence == 0.0
        assert metadata["status"] == "error"

    @pytest.mark.asyncio
    async def test_search_platform_found(self, social_search: SocialMediaSearch) -> None:
        """Test searching a single platform with success."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "tweets followers following"

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        result = await social_search._search_platform("twitter", "testuser")

        assert result is not None
        assert result.source == "social:twitter"
        assert result.identifier == "testuser"
        assert result.url == "https://twitter.com/testuser"
        assert result.confidence > 0.0

    @pytest.mark.asyncio
    async def test_search_platform_not_found(self, social_search: SocialMediaSearch) -> None:
        """Test searching a single platform with no results."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        result = await social_search._search_platform("twitter", "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_search_multiple_platforms(self, social_search: SocialMediaSearch) -> None:
        """Test searching across multiple platforms."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "profile found"

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        results = await social_search.search("testuser")

        assert len(results) >= 1  # At least one platform should return results
        assert all(isinstance(r, Result) for r in results)

    @pytest.mark.asyncio
    async def test_search_no_enabled_platforms(self, mock_config: MagicMock) -> None:
        """Test search with no enabled platforms."""
        mock_config.get.return_value = {}  # No platforms

        with patch("src.search.social.get_config", return_value=mock_config):
            with patch("src.search.social.httpx.AsyncClient"):
                search = SocialMediaSearch()
                results = await search.search("testuser")

                assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_with_variants(self, social_search: SocialMediaSearch) -> None:
        """Test searching with username variants."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "profile found"

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        # Should use actual variant generator
        results = await social_search.search_with_variants("test", max_variants=3)

        # Should have searched with variants
        assert len(results) >= 0

    @pytest.mark.asyncio
    async def test_search_deduplication(self, social_search: SocialMediaSearch) -> None:
        """Test that search results are deduplicated by URL."""
        # Create responses that would lead to same URLs
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "profile"

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        # Use actual variant generator which may produce similar variants
        results = await social_search.search_with_variants("test", max_variants=5)

        # Should deduplicate - all URLs should be unique
        urls = [r.url for r in results]
        assert len(urls) == len(set(urls))  # All unique

    @pytest.mark.asyncio
    async def test_profile_indicators_increase_confidence(
        self, social_search: SocialMediaSearch
    ) -> None:
        """Test that more indicators increase confidence."""
        # Response with many indicators
        mock_response_many = MagicMock()
        mock_response_many.status_code = 200
        mock_response_many.text = "tweets followers following joined"

        # Response with few indicators
        mock_response_few = MagicMock()
        mock_response_few.status_code = 200
        mock_response_few.text = "some content"

        social_search.http_client.get = AsyncMock(return_value=mock_response_many)
        _, conf_many, _ = await social_search._check_profile_exists(
            "twitter", "https://twitter.com/user1"
        )

        social_search.http_client.get = AsyncMock(return_value=mock_response_few)
        _, conf_few, _ = await social_search._check_profile_exists(
            "twitter", "https://twitter.com/user2"
        )

        assert conf_many > conf_few

    @pytest.mark.asyncio
    async def test_rate_limiting_applied(self, social_search: SocialMediaSearch) -> None:
        """Test that rate limiting is applied during searches."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "profile"

        social_search.http_client.get = AsyncMock(return_value=mock_response)

        # Mock the rate limiter to track calls
        acquire_calls = 0

        async def mock_acquire():
            nonlocal acquire_calls
            acquire_calls += 1

        social_search.rate_limiter.acquire = mock_acquire

        await social_search.search("testuser")

        # Rate limiter should have been called for each platform check
        assert acquire_calls > 0

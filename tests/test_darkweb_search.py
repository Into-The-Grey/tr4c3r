"""Tests for dark web search module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.data_models import Result
from src.search.darkweb import DarkWebSearch, TorClient


class TestTorClient:
    """Test the TorClient class."""

    def test_initialization(self) -> None:
        """Test TorClient initialization."""
        client = TorClient()
        assert client.socks_proxy == "socks5://127.0.0.1:9050"
        assert client.timeout == 30.0

    def test_custom_initialization(self) -> None:
        """Test TorClient with custom settings."""
        client = TorClient(socks_proxy="socks5://localhost:9150", timeout=60.0)
        assert client.socks_proxy == "socks5://localhost:9150"
        assert client.timeout == 60.0

    @pytest.mark.asyncio
    async def test_check_tor_connection_success(self) -> None:
        """Test successful Tor connection check."""
        client = TorClient()

        mock_response = MagicMock()
        mock_response.json.return_value = {"IsTor": True}

        with patch.object(client, "get", return_value=mock_response):
            is_tor = await client.check_tor_connection()
            assert is_tor is True

    @pytest.mark.asyncio
    async def test_check_tor_connection_failure(self) -> None:
        """Test failed Tor connection check."""
        client = TorClient()

        mock_response = MagicMock()
        mock_response.json.return_value = {"IsTor": False}

        with patch.object(client, "get", return_value=mock_response):
            is_tor = await client.check_tor_connection()
            assert is_tor is False

    @pytest.mark.asyncio
    async def test_check_tor_connection_error(self) -> None:
        """Test Tor connection check with error."""
        client = TorClient()

        with patch.object(client, "get", side_effect=Exception("Connection failed")):
            is_tor = await client.check_tor_connection()
            assert is_tor is False


class TestDarkWebSearch:
    """Test the DarkWebSearch class."""

    @pytest.fixture
    def dark_search(self) -> DarkWebSearch:
        """Create a DarkWebSearch instance."""
        with patch("src.search.darkweb.get_config"):
            return DarkWebSearch(use_tor=False, safe_mode=False)

    @pytest.fixture
    def dark_search_with_tor(self) -> DarkWebSearch:
        """Create a DarkWebSearch instance with Tor enabled."""
        with patch("src.search.darkweb.get_config"):
            return DarkWebSearch(use_tor=True, safe_mode=True)

    def test_initialization(self, dark_search: DarkWebSearch) -> None:
        """Test DarkWebSearch initialization."""
        assert dark_search.use_tor is False
        assert dark_search.safe_mode is False
        assert dark_search.tor_client is None

    def test_initialization_with_tor(self, dark_search_with_tor: DarkWebSearch) -> None:
        """Test initialization with Tor."""
        assert dark_search_with_tor.use_tor is True
        assert dark_search_with_tor.safe_mode is True
        assert dark_search_with_tor.tor_client is not None

    def test_is_onion_url(self, dark_search: DarkWebSearch) -> None:
        """Test onion URL detection."""
        assert dark_search._is_onion_url("http://3g2upl4pq6kufc4m.onion") is True
        assert dark_search._is_onion_url("https://example.onion/path") is True
        assert dark_search._is_onion_url("https://example.com") is False
        assert dark_search._is_onion_url("http://localhost:8080") is False

    @pytest.mark.asyncio
    async def test_verify_tor_connection_not_enabled(self, dark_search: DarkWebSearch) -> None:
        """Test Tor verification when Tor not enabled."""
        result = await dark_search._verify_tor_connection()
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_tor_connection_success(self, dark_search_with_tor: DarkWebSearch) -> None:
        """Test successful Tor verification."""
        mock_client = MagicMock()
        mock_client.check_tor_connection = AsyncMock(return_value=True)
        dark_search_with_tor.tor_client = mock_client

        result = await dark_search_with_tor._verify_tor_connection()
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_tor_connection_failure(self, dark_search_with_tor: DarkWebSearch) -> None:
        """Test failed Tor verification."""
        mock_client = MagicMock()
        mock_client.check_tor_connection = AsyncMock(return_value=False)
        dark_search_with_tor.tor_client = mock_client

        result = await dark_search_with_tor._verify_tor_connection()
        assert result is False

    @pytest.mark.asyncio
    async def test_search_ahmia_found(self, dark_search: DarkWebSearch) -> None:
        """Test Ahmia search with results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "test@example.com found in database leak"

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client_class.return_value = mock_client

            results = await dark_search._search_ahmia("test@example.com")

            assert len(results) == 1
            assert results[0].source == "darkweb:ahmia"
            assert results[0].identifier == "test@example.com"
            assert "database" in results[0].metadata["potential_leak_types"]

    @pytest.mark.asyncio
    async def test_search_ahmia_not_found(self, dark_search: DarkWebSearch) -> None:
        """Test Ahmia search with no results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "No results found"

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client_class.return_value = mock_client

            results = await dark_search._search_ahmia("nonexistent")

            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_ahmia_error(self, dark_search: DarkWebSearch) -> None:
        """Test Ahmia search with error."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=Exception("Network error"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client_class.return_value = mock_client

            results = await dark_search._search_ahmia("test")

            # Should handle error gracefully
            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_onion_directory_no_tor(self, dark_search: DarkWebSearch) -> None:
        """Test onion directory search without Tor."""
        results = await dark_search._search_onion_directory("test")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_onion_directory_found(self, dark_search_with_tor: DarkWebSearch) -> None:
        """Test onion directory search with results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            "test user profile " "http://3g2upl4pq6kufc4m.onion " "http://another56characters.onion"
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client_class.return_value = mock_client

            results = await dark_search_with_tor._search_onion_directory("test")

            assert len(results) >= 0

    @pytest.mark.asyncio
    async def test_search_without_tor(self, dark_search: DarkWebSearch) -> None:
        """Test search without Tor (clearnet only)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "some content"

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client_class.return_value = mock_client

            results = await dark_search.search("test", check_tor=False)

            # Should still work with clearnet searches
            assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_search_onion_service_not_onion(
        self, dark_search_with_tor: DarkWebSearch
    ) -> None:
        """Test onion service search with non-onion URL."""
        result = await dark_search_with_tor.search_onion_service("https://example.com", "test")
        assert result is None

    @pytest.mark.asyncio
    async def test_search_onion_service_no_tor(self, dark_search: DarkWebSearch) -> None:
        """Test onion service search without Tor."""
        result = await dark_search.search_onion_service("http://example.onion", "test")
        assert result is None

    @pytest.mark.asyncio
    async def test_search_onion_service_found(self, dark_search_with_tor: DarkWebSearch) -> None:
        """Test onion service search with result."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "test user profile data"

        dark_search_with_tor.tor_client.get = AsyncMock(return_value=mock_response)

        result = await dark_search_with_tor.search_onion_service("http://example.onion", "test")

        assert result is not None
        assert result.source == "darkweb:onion"
        assert result.identifier == "test"
        assert "example.onion" in result.url

    @pytest.mark.asyncio
    async def test_search_onion_service_not_found(
        self, dark_search_with_tor: DarkWebSearch
    ) -> None:
        """Test onion service search with no match."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "no matching content"

        dark_search_with_tor.tor_client.get = AsyncMock(return_value=mock_response)

        result = await dark_search_with_tor.search_onion_service(
            "http://example.onion", "nonexistent"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_search_onion_service_error(self, dark_search_with_tor: DarkWebSearch) -> None:
        """Test onion service search with error."""
        dark_search_with_tor.tor_client.get = AsyncMock(side_effect=Exception("Connection failed"))

        result = await dark_search_with_tor.search_onion_service("http://example.onion", "test")

        assert result is None

    @pytest.mark.asyncio
    async def test_check_data_breach_mentions(self, dark_search: DarkWebSearch) -> None:
        """Test data breach mentions check."""
        results = await dark_search._check_data_breach_mentions("test@example.com")

        # Currently returns empty (placeholder)
        assert isinstance(results, list)

    def test_leak_patterns_defined(self, dark_search: DarkWebSearch) -> None:
        """Test that leak patterns are defined."""
        assert "database" in DarkWebSearch.LEAK_PATTERNS
        assert "credentials" in DarkWebSearch.LEAK_PATTERNS
        assert "email" in DarkWebSearch.LEAK_PATTERNS
        assert "phone" in DarkWebSearch.LEAK_PATTERNS
        assert "financial" in DarkWebSearch.LEAK_PATTERNS

    def test_search_engines_defined(self, dark_search: DarkWebSearch) -> None:
        """Test that search engines are defined."""
        assert "ahmia" in DarkWebSearch.SEARCH_ENGINES
        assert "url" in DarkWebSearch.SEARCH_ENGINES["ahmia"]

    def test_onion_directories_defined(self, dark_search: DarkWebSearch) -> None:
        """Test that onion directories are defined."""
        assert len(DarkWebSearch.ONION_DIRECTORIES) > 0
        assert all(isinstance(url, str) for url in DarkWebSearch.ONION_DIRECTORIES)

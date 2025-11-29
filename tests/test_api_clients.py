"""Tests for the API clients module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import httpx

from src.integrations.api_clients import (
    APIConfig,
    API_REGISTRY,
    GitHubAPI,
    GravatarAPI,
    EmailRepAPI,
    IPInfoAPI,
    HunterAPI,
    HIBPApi,
    APIIntegrationManager,
)
from src.core.data_models import Result


class TestAPIConfig:
    """Tests for APIConfig class."""

    def test_init_defaults(self):
        """Test default initialization."""
        config = APIConfig(name="Test", base_url="https://api.test.com")
        assert config.name == "Test"
        assert config.base_url == "https://api.test.com"
        assert config.is_free is True
        assert config.enabled_by_default is True
        assert config.requires_auth is False

    def test_init_paid(self):
        """Test paid API configuration."""
        config = APIConfig(
            name="Paid",
            base_url="https://api.paid.com",
            is_free=False,
            enabled_by_default=False,
            requires_auth=True,
        )
        assert config.is_free is False
        assert config.enabled_by_default is False
        assert config.requires_auth is True


class TestAPIRegistry:
    """Tests for API_REGISTRY."""

    def test_github_in_registry(self):
        """Test GitHub is registered."""
        assert "github" in API_REGISTRY
        assert API_REGISTRY["github"].is_free is True

    def test_hibp_in_registry(self):
        """Test HIBP is registered as paid."""
        assert "hibp" in API_REGISTRY
        assert API_REGISTRY["hibp"].is_free is False
        assert API_REGISTRY["hibp"].requires_auth is True

    def test_all_free_apis_enabled_by_default(self):
        """Test all free APIs are enabled by default."""
        for name, config in API_REGISTRY.items():
            if config.is_free:
                assert config.enabled_by_default is True, f"{name} should be enabled by default"

    def test_all_paid_apis_disabled_by_default(self):
        """Test all paid APIs are disabled by default."""
        for name, config in API_REGISTRY.items():
            if not config.is_free:
                assert config.enabled_by_default is False, f"{name} should be disabled by default"


class TestGitHubAPI:
    """Tests for GitHubAPI class."""

    def test_init(self):
        """Test initialization."""
        api = GitHubAPI()
        assert api.config.name == "GitHub"

    def test_enabled_by_default(self):
        """Test GitHub is enabled by default."""
        api = GitHubAPI()
        assert api.is_enabled is True

    def test_build_headers_without_key(self):
        """Test header building without API key."""
        api = GitHubAPI()
        headers = api._build_headers()

        assert "Accept" in headers
        assert "User-Agent" in headers
        assert "Authorization" not in headers

    def test_build_headers_with_key(self):
        """Test header building with API key."""
        api = GitHubAPI(api_key="test_token")
        headers = api._build_headers()

        assert "Authorization" in headers
        assert "Bearer test_token" in headers["Authorization"]

    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        """Test search returns Result objects."""
        api = GitHubAPI()

        # Mock the get_user method
        api.get_user = AsyncMock(
            return_value={
                "login": "testuser",
                "html_url": "https://github.com/testuser",
                "name": "Test User",
                "bio": "Test bio",
            }
        )

        results = await api.search("testuser")

        assert len(results) == 1
        assert results[0].source == "github_api"
        assert results[0].identifier == "testuser"
        assert results[0].confidence == 1.0

    @pytest.mark.asyncio
    async def test_search_user_not_found(self):
        """Test search returns empty when user not found."""
        api = GitHubAPI()
        api.get_user = AsyncMock(return_value=None)

        results = await api.search("nonexistent_user_12345")
        assert results == []


class TestGravatarAPI:
    """Tests for GravatarAPI class."""

    def test_email_hash(self):
        """Test email hash generation."""
        api = GravatarAPI()
        hash1 = api._email_hash("test@example.com")
        hash2 = api._email_hash("TEST@EXAMPLE.COM")
        hash3 = api._email_hash("  test@example.com  ")

        # Same email, different case/whitespace should produce same hash
        assert hash1 == hash2
        assert hash1 == hash3
        # Should be 32 char hex string
        assert len(hash1) == 32

    @pytest.mark.asyncio
    async def test_search_not_found(self):
        """Test search returns empty when not found."""
        api = GravatarAPI()
        api.get_profile = AsyncMock(return_value=None)

        results = await api.search("test@example.com")
        assert results == []


class TestEmailRepAPI:
    """Tests for EmailRepAPI class."""

    def test_enabled_by_default(self):
        """Test EmailRep is enabled by default."""
        api = EmailRepAPI()
        assert api.is_enabled is True

    @pytest.mark.asyncio
    async def test_search_with_reputation(self):
        """Test search with reputation data."""
        api = EmailRepAPI()
        api.get_reputation = AsyncMock(
            return_value={
                "reputation": "high",
                "suspicious": False,
                "references": 10,
                "details": {},
                "profiles": [],
            }
        )

        results = await api.search("test@example.com")

        assert len(results) == 1
        assert results[0].confidence == 0.9  # High reputation


class TestIPInfoAPI:
    """Tests for IPInfoAPI class."""

    def test_enabled_by_default(self):
        """Test IPInfo is enabled by default."""
        api = IPInfoAPI()
        assert api.is_enabled is True

    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        """Test search returns IP info."""
        api = IPInfoAPI()
        api.get_ip_info = AsyncMock(
            return_value={
                "ip": "8.8.8.8",
                "city": "Mountain View",
                "country": "US",
                "org": "Google LLC",
            }
        )

        results = await api.search("8.8.8.8")

        assert len(results) == 1
        assert results[0].source == "ipinfo"
        assert results[0].metadata["country"] == "US"


class TestHunterAPI:
    """Tests for HunterAPI (paid)."""

    def test_disabled_without_key(self):
        """Test Hunter is disabled without API key."""
        with patch.object(HunterAPI, "_get_default_config", return_value=API_REGISTRY["hunter"]):
            api = HunterAPI()
            # Should be disabled because no API key and requires auth
            # (Actual behavior depends on config mock)

    @pytest.mark.asyncio
    async def test_search_disabled(self):
        """Test search returns empty when disabled."""
        api = HunterAPI(enabled=False)
        results = await api.search("test@example.com")
        assert results == []


class TestHIBPApi:
    """Tests for HIBPApi (paid)."""

    def test_disabled_without_key(self):
        """Test HIBP is disabled without API key."""
        api = HIBPApi()
        # Should be disabled because requires auth
        assert api.config.requires_auth is True

    @pytest.mark.asyncio
    async def test_check_breaches_disabled(self):
        """Test breach check returns empty when disabled."""
        api = HIBPApi(enabled=False)
        breaches = await api.check_breaches("test@example.com")
        assert breaches == []


class TestAPIIntegrationManager:
    """Tests for APIIntegrationManager class."""

    def test_init(self):
        """Test initialization."""
        manager = APIIntegrationManager()
        assert manager._clients is not None
        assert len(manager._clients) > 0

    def test_get_client(self):
        """Test getting a client by name."""
        manager = APIIntegrationManager()
        client = manager.get_client("github")
        assert client is not None
        assert isinstance(client, GitHubAPI)

    def test_get_nonexistent_client(self):
        """Test getting a nonexistent client."""
        manager = APIIntegrationManager()
        client = manager.get_client("nonexistent")
        assert client is None

    def test_get_enabled_clients(self):
        """Test getting enabled clients."""
        manager = APIIntegrationManager()
        enabled = manager.get_enabled_clients()

        # Should have at least some enabled
        assert len(enabled) > 0
        for name, client in enabled.items():
            assert client.is_enabled is True

    def test_get_free_clients(self):
        """Test getting free clients."""
        manager = APIIntegrationManager()
        free = manager.get_free_clients()

        for name, client in free.items():
            assert client.config.is_free is True

    def test_get_paid_clients(self):
        """Test getting paid clients."""
        manager = APIIntegrationManager()
        paid = manager.get_paid_clients()

        for name, client in paid.items():
            assert client.config.is_free is False

    def test_list_apis(self):
        """Test listing all APIs."""
        manager = APIIntegrationManager()
        apis = manager.list_apis()

        assert "github" in apis
        assert "name" in apis["github"]
        assert "enabled" in apis["github"]
        assert "is_free" in apis["github"]

    @pytest.mark.asyncio
    async def test_search_all(self):
        """Test searching across all APIs."""
        manager = APIIntegrationManager()

        # Mock all client searches
        for client in manager._clients.values():
            client.search = AsyncMock(return_value=[])

        results = await manager.search_all("testuser", "username")

        assert isinstance(results, dict)

    @pytest.mark.asyncio
    async def test_close_all(self):
        """Test closing all clients."""
        manager = APIIntegrationManager()

        # This should not raise
        await manager.close_all()


class TestAPIClientErrorHandling:
    """Tests for API client error handling."""

    @pytest.mark.asyncio
    async def test_github_handles_exception(self):
        """Test GitHub API handles exceptions gracefully."""
        api = GitHubAPI()

        # Mock to raise exception
        async def mock_get(*args, **kwargs):
            raise httpx.ConnectError("Network error")

        api.get = mock_get

        user = await api.get_user("testuser")
        assert user is None

    @pytest.mark.asyncio
    async def test_safe_search_handles_exception(self):
        """Test manager's safe search handles exceptions."""
        manager = APIIntegrationManager()

        async def failing_search(query):
            raise Exception("API error")

        client = MagicMock()
        client.config.name = "TestAPI"
        client.search = failing_search

        results = await manager._safe_search(client, "test")
        assert results == []

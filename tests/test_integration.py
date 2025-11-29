"""Integration tests for TR4C3R.

These tests make real network requests to external services.
They are skipped by default and can be run with:
    pytest tests/test_integration.py -v --run-integration

Or run all tests including integration:
    pytest -v --run-integration
"""

import asyncio
import os
import pytest
from datetime import datetime

# Skip all tests in this module unless --run-integration is passed
pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_INTEGRATION_TESTS"),
    reason="Integration tests are disabled by default. Set RUN_INTEGRATION_TESTS=1 to run.",
)


class TestGitHubIntegration:
    """Integration tests for GitHub API."""

    @pytest.mark.asyncio
    async def test_github_user_lookup(self):
        """Test looking up a real GitHub user."""
        from src.integrations.api_clients import GitHubAPI

        api = GitHubAPI()
        if not api.is_enabled:
            pytest.skip("GitHub API is not enabled")

        user_data = await api.get_user("octocat")
        assert user_data is not None
        assert user_data.get("login") == "octocat"
        assert user_data.get("type") == "User"
        await api.close()

    @pytest.mark.asyncio
    async def test_github_nonexistent_user(self):
        """Test looking up a nonexistent GitHub user."""
        from src.integrations.api_clients import GitHubAPI

        api = GitHubAPI()
        if not api.is_enabled:
            pytest.skip("GitHub API is not enabled")

        user_data = await api.get_user("this-user-definitely-does-not-exist-12345678901234567890")
        assert user_data is None
        await api.close()

    @pytest.mark.asyncio
    async def test_github_search(self):
        """Test GitHub search returning Result objects."""
        from src.integrations.api_clients import GitHubAPI

        api = GitHubAPI()
        if not api.is_enabled:
            pytest.skip("GitHub API is not enabled")

        results = await api.search("octocat")
        assert len(results) == 1
        assert results[0].source == "github_api"
        assert results[0].identifier == "octocat"
        assert "github.com" in results[0].url
        await api.close()


class TestGravatarIntegration:
    """Integration tests for Gravatar API."""

    @pytest.mark.asyncio
    async def test_gravatar_known_email(self):
        """Test looking up a Gravatar profile."""
        from src.integrations.api_clients import GravatarAPI

        api = GravatarAPI()
        if not api.is_enabled:
            pytest.skip("Gravatar API is not enabled")

        # Note: Gravatar profiles may not always be public
        # This test uses a known test email
        results = await api.search("beau@dentedreality.com.au")  # Known Gravatar user
        # May or may not have a profile
        assert isinstance(results, list)
        await api.close()


class TestIPInfoIntegration:
    """Integration tests for IPInfo API."""

    @pytest.mark.asyncio
    async def test_ipinfo_lookup(self):
        """Test looking up IP information."""
        from src.integrations.api_clients import IPInfoAPI

        api = IPInfoAPI()
        if not api.is_enabled:
            pytest.skip("IPInfo API is not enabled")

        # Use Google's DNS for testing
        info = await api.get_ip_info("8.8.8.8")
        assert info is not None
        assert info.get("ip") == "8.8.8.8"
        assert "city" in info
        assert "country" in info
        await api.close()

    @pytest.mark.asyncio
    async def test_ipinfo_search(self):
        """Test IPInfo search returning Result objects."""
        from src.integrations.api_clients import IPInfoAPI

        api = IPInfoAPI()
        if not api.is_enabled:
            pytest.skip("IPInfo API is not enabled")

        results = await api.search("1.1.1.1")
        assert len(results) == 1
        assert results[0].source == "ipinfo"
        assert results[0].identifier == "1.1.1.1"
        assert results[0].metadata.get("country") is not None
        await api.close()


class TestEmailRepIntegration:
    """Integration tests for EmailRep.io API."""

    @pytest.mark.asyncio
    async def test_emailrep_lookup(self):
        """Test looking up email reputation."""
        from src.integrations.api_clients import EmailRepAPI

        api = EmailRepAPI()
        if not api.is_enabled:
            pytest.skip("EmailRep API is not enabled")

        # Use a test email
        rep = await api.get_reputation("bill@microsoft.com")
        if rep:  # Rate limits may apply
            assert "reputation" in rep
        await api.close()


class TestUsernameSearchIntegration:
    """Integration tests for username search."""

    @pytest.mark.asyncio
    async def test_username_search_octocat(self):
        """Test searching for a real username across platforms."""
        from src.core.orchestrator import Orchestrator

        orchestrator = Orchestrator()
        results = await orchestrator.search_username("octocat")

        assert len(results) > 0
        # Should find on GitHub at minimum
        sources = [r.source for r in results]
        assert any("github" in s.lower() for s in sources)

    @pytest.mark.asyncio
    async def test_username_search_nonexistent(self):
        """Test searching for a nonexistent username."""
        from src.core.orchestrator import Orchestrator

        orchestrator = Orchestrator()
        results = await orchestrator.search_username(
            "this_user_definitely_does_not_exist_xyz123456789"
        )

        # Should return empty or very few results
        assert len(results) <= 1


class TestCacheIntegration:
    """Integration tests for caching."""

    @pytest.mark.asyncio
    async def test_cache_stores_and_retrieves(self):
        """Test that cache stores and retrieves results."""
        from src.core.cache import CacheManager
        from src.core.data_models import Result
        from datetime import datetime, timezone

        cache = CacheManager(enabled=True, default_ttl=60)

        # Create test results
        results = [
            Result(
                source="test",
                identifier="test_query",
                url="https://example.com",
                confidence=0.9,
            )
        ]

        # Store in cache
        cache.set(results, "test_search", "test_query")

        # Retrieve from cache
        cached = cache.get("test_search", "test_query")
        assert cached is not None
        assert len(cached) == 1
        assert cached[0].source == "test"
        assert cached[0].identifier == "test_query"


class TestDeduplicationIntegration:
    """Integration tests for result deduplication."""

    def test_deduplicates_same_url(self):
        """Test that results with the same URL are deduplicated."""
        from src.core.deduplication import deduplicate_results
        from src.core.data_models import Result

        results = [
            Result(
                source="source1",
                identifier="user",
                url="https://github.com/user",
                confidence=0.8,
            ),
            Result(
                source="source2",
                identifier="user",
                url="https://github.com/user",
                confidence=0.9,
            ),
            Result(
                source="source3",
                identifier="user",
                url="https://example.com/user",
                confidence=0.7,
            ),
        ]

        deduped = deduplicate_results(results)

        # Should have 2 unique URLs
        assert len(deduped) == 2

        # Higher confidence result should be kept
        github_result = next(r for r in deduped if "github" in r.url)
        assert github_result.confidence == 0.9


class TestRateLimiterIntegration:
    """Integration tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limiter_delays(self):
        """Test that rate limiter properly delays requests."""
        from src.core.rate_limiter import RateLimiter
        import time

        limiter = RateLimiter()
        limiter.set_rate_limit("test_service", requests_per_second=5.0)

        start = time.time()

        # Make 10 requests
        total_wait = 0.0
        for _ in range(10):
            waited = await limiter.acquire("test_service")
            total_wait += waited

        elapsed = time.time() - start

        # Should have waited approximately 1.8 seconds (10 requests at 5/s)
        # Allow for some variance
        assert elapsed >= 1.5
        assert total_wait >= 1.0


class TestConfigValidation:
    """Integration tests for configuration validation."""

    def test_validate_default_config(self):
        """Test validating the default configuration."""
        from src.core.config import Config

        config = Config()
        result = config.validate()

        # Default config should be valid
        assert result.is_valid

    def test_validate_with_missing_keys(self):
        """Test validation reports missing API keys."""
        from src.core.config import Config

        config = Config()
        result = config.validate()

        # Should have missing API key warnings
        assert len(result.missing_api_keys) > 0


class TestErrorRecoveryIntegration:
    """Integration tests for error recovery."""

    @pytest.mark.asyncio
    async def test_partial_results_on_failure(self):
        """Test that partial results are collected when some modules fail."""
        from src.core.error_recovery import ErrorRecoveryManager
        from src.core.data_models import Result

        manager = ErrorRecoveryManager(collect_partial=True, auto_retry=False)

        async def successful_module(query: str):
            return [Result(source="success", identifier=query, confidence=0.9)]

        async def failing_module(query: str):
            raise ConnectionError("Simulated network error")

        modules = {
            "success_module": successful_module,
            "failing_module": failing_module,
        }

        result = await manager.execute_with_recovery(modules, "test_query")

        # Should have collected partial results
        assert len(result.results) == 1
        assert result.results[0].source == "success"

        # Should have recorded the error
        assert len(result.errors) == 1
        assert result.errors[0].module == "failing_module"

        # Should be marked as partial
        assert result.is_partial


class TestAPIIntegrationManager:
    """Integration tests for the API integration manager."""

    @pytest.mark.asyncio
    async def test_manager_lists_apis(self):
        """Test that the manager lists all APIs."""
        from src.integrations.api_clients import APIIntegrationManager

        manager = APIIntegrationManager()
        apis = manager.list_apis()

        # Should have multiple APIs registered
        assert len(apis) >= 4

        # Check structure
        for name, info in apis.items():
            assert "name" in info
            assert "enabled" in info
            assert "is_free" in info
            assert "requires_auth" in info

        await manager.close_all()

    @pytest.mark.asyncio
    async def test_free_vs_paid_clients(self):
        """Test that free and paid clients are correctly categorized."""
        from src.integrations.api_clients import APIIntegrationManager

        manager = APIIntegrationManager()

        free_clients = manager.get_free_clients()
        paid_clients = manager.get_paid_clients()

        # Should have some free clients enabled
        assert len(free_clients) > 0

        # Paid clients should be disabled by default (no API keys)
        # This may vary based on environment
        for name, client in paid_clients.items():
            assert not client.config.is_free

        await manager.close_all()


class TestCLIIntegration:
    """Integration tests for CLI commands."""

    def test_cli_parse_username(self):
        """Test parsing username command."""
        from src.cli import parse_args

        args = parse_args(["username", "testuser", "--fuzzy"])
        assert args.command == "username"
        assert args.username == "testuser"
        assert args.fuzzy is True

    def test_cli_parse_history(self):
        """Test parsing history command."""
        from src.cli import parse_args

        args = parse_args(["history", "--limit", "50", "--type", "email"])
        assert args.command == "history"
        assert args.limit == 50
        assert args.type == "email"

    def test_cli_parse_export(self):
        """Test parsing export command."""
        from src.cli import parse_args

        args = parse_args(["export", "123", "--format", "csv", "--output", "results.csv"])
        assert args.command == "export"
        assert args.search_id == 123
        assert args.format == "csv"
        assert str(args.output) == "results.csv"

    def test_cli_parse_validate(self):
        """Test parsing validate command."""
        from src.cli import parse_args

        args = parse_args(["validate", "--strict"])
        assert args.command == "validate"
        assert args.strict is True


# Pytest hook to add --run-integration option
def pytest_addoption(parser):
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests",
    )


def pytest_configure(config):
    if config.getoption("--run-integration", default=False):
        os.environ["RUN_INTEGRATION_TESTS"] = "1"

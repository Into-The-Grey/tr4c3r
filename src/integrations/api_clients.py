"""Real API integrations for TR4C3R.

This module provides integrations with external OSINT APIs.
APIs marked as 'free' are enabled by default.
APIs marked as 'paid' are disabled by default and require API keys.

Free APIs:
- GitHub API (public user lookup, 60 req/hr unauthenticated)
- Reddit API (public user lookup)
- Keybase API (identity lookups)
- Gravatar (email to profile picture)
- IPInfo (basic IP geolocation)
- EmailRep.io (email reputation, limited free tier)

Paid APIs (disabled by default):
- Hunter.io (email finder/verifier)
- HaveIBeenPwned (breach database)
- Numverify (phone validation)
- Clearbit (company/person enrichment)
- FullContact (contact enrichment)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from src.core.config import get_config
from src.core.data_models import Result
from src.core.rate_limiter import get_rate_limiter


logger = logging.getLogger(__name__)


@dataclass
class APIConfig:
    """Configuration for an API integration."""

    name: str
    base_url: str
    api_key_name: str = ""  # Config key for API key
    is_free: bool = True
    enabled_by_default: bool = True
    rate_limit_per_second: float = 1.0
    requires_auth: bool = False
    timeout: float = 10.0


# Registry of available APIs
API_REGISTRY: Dict[str, APIConfig] = {
    "github": APIConfig(
        name="GitHub",
        base_url="https://api.github.com",
        api_key_name="github_token",
        is_free=True,
        enabled_by_default=True,
        rate_limit_per_second=10.0,  # 60/min unauthenticated, higher with token
        requires_auth=False,
    ),
    "reddit": APIConfig(
        name="Reddit",
        base_url="https://www.reddit.com",
        is_free=True,
        enabled_by_default=True,
        rate_limit_per_second=1.0,  # Reddit is strict
        requires_auth=False,
    ),
    "keybase": APIConfig(
        name="Keybase",
        base_url="https://keybase.io",
        is_free=True,
        enabled_by_default=True,
        rate_limit_per_second=2.0,
        requires_auth=False,
    ),
    "gravatar": APIConfig(
        name="Gravatar",
        base_url="https://www.gravatar.com",
        is_free=True,
        enabled_by_default=True,
        rate_limit_per_second=5.0,
        requires_auth=False,
    ),
    "ipinfo": APIConfig(
        name="IPInfo",
        base_url="https://ipinfo.io",
        api_key_name="ipinfo_token",
        is_free=True,  # Has free tier
        enabled_by_default=True,
        rate_limit_per_second=2.0,
        requires_auth=False,
    ),
    "emailrep": APIConfig(
        name="EmailRep.io",
        base_url="https://emailrep.io",
        api_key_name="emailrep_key",
        is_free=True,  # Has free tier (limited)
        enabled_by_default=True,
        rate_limit_per_second=0.5,  # Conservative for free tier
        requires_auth=False,
    ),
    # Paid APIs
    "hunter": APIConfig(
        name="Hunter.io",
        base_url="https://api.hunter.io/v2",
        api_key_name="hunter_api_key",
        is_free=False,
        enabled_by_default=False,
        rate_limit_per_second=2.0,
        requires_auth=True,
    ),
    "hibp": APIConfig(
        name="Have I Been Pwned",
        base_url="https://haveibeenpwned.com/api/v3",
        api_key_name="hibp_api_key",
        is_free=False,
        enabled_by_default=False,
        rate_limit_per_second=1.5,  # ~10/min with subscription
        requires_auth=True,
    ),
    "numverify": APIConfig(
        name="Numverify",
        base_url="https://apilayer.net/api",
        api_key_name="numverify_api_key",
        is_free=False,
        enabled_by_default=False,
        rate_limit_per_second=2.0,
        requires_auth=True,
    ),
    "clearbit": APIConfig(
        name="Clearbit",
        base_url="https://person.clearbit.com/v2",
        api_key_name="clearbit_api_key",
        is_free=False,
        enabled_by_default=False,
        rate_limit_per_second=2.0,
        requires_auth=True,
    ),
}


class BaseAPIClient(ABC):
    """Base class for API clients."""

    def __init__(
        self,
        config: Optional[APIConfig] = None,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        """Initialize API client.

        Args:
            config: API configuration
            api_key: API key (overrides config)
            enabled: Whether the API is enabled (overrides config)
        """
        self.config = config or self._get_default_config()
        self._api_key = api_key
        self._enabled = enabled if enabled is not None else self.config.enabled_by_default
        self._client: Optional[httpx.AsyncClient] = None
        self.logger = logging.getLogger(self.__class__.__name__)

        # Get API key from config if not provided
        if self._api_key is None and self.config.api_key_name:
            app_config = get_config()
            self._api_key = app_config.get_api_key(
                self.config.api_key_name.replace("_api_key", "")
                .replace("_token", "")
                .replace("_key", "")
            )

        # Disable if requires auth but no API key
        if self.config.requires_auth and not self._api_key:
            self._enabled = False
            self.logger.debug(
                "%s disabled: requires API key '%s'",
                self.config.name,
                self.config.api_key_name,
            )

    @abstractmethod
    def _get_default_config(self) -> APIConfig:
        """Get default configuration for this API."""
        pass

    @property
    def is_enabled(self) -> bool:
        """Check if the API is enabled."""
        return self._enabled

    @property
    def api_key(self) -> Optional[str]:
        """Get the API key."""
        return self._api_key

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.config.timeout)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an API request with rate limiting.

        Args:
            method: HTTP method
            path: API path
            **kwargs: Additional arguments for httpx

        Returns:
            HTTP response
        """
        if not self.is_enabled:
            raise RuntimeError(f"{self.config.name} API is not enabled")

        # Apply rate limiting
        rate_limiter = get_rate_limiter()
        await rate_limiter.acquire(self.config.name.lower())

        url = f"{self.config.base_url}{path}"
        client = await self._get_client()

        self.logger.debug("API request: %s %s", method, url)
        response = await client.request(method, url, **kwargs)

        self.logger.debug(
            "API response: %s %s -> %d",
            method,
            url,
            response.status_code,
        )

        return response

    async def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Make a GET request."""
        return await self._request("GET", path, params=params, headers=headers)

    @abstractmethod
    async def search(self, query: str) -> List[Result]:
        """Search using this API.

        Args:
            query: Search query

        Returns:
            List of Result objects
        """
        pass


class GitHubAPI(BaseAPIClient):
    """GitHub API client for user lookups."""

    def _get_default_config(self) -> APIConfig:
        return API_REGISTRY["github"]

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "TR4C3R/1.0",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get GitHub user information.

        Args:
            username: GitHub username

        Returns:
            User data dictionary or None if not found
        """
        if not self.is_enabled:
            return None

        try:
            response = await self.get(
                f"/users/{username}",
                headers=self._build_headers(),
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                response.raise_for_status()
        except Exception as e:
            self.logger.warning("GitHub API error for %s: %s", username, e)
            return None
        return None

    async def search(self, query: str) -> List[Result]:
        """Search for a GitHub user.

        Args:
            query: Username to search for

        Returns:
            List of Result objects
        """
        user_data = await self.get_user(query)
        if not user_data:
            return []

        return [
            Result(
                source="github_api",
                identifier=query,
                url=user_data.get("html_url"),
                confidence=1.0,
                metadata={
                    "name": user_data.get("name"),
                    "bio": user_data.get("bio"),
                    "location": user_data.get("location"),
                    "company": user_data.get("company"),
                    "blog": user_data.get("blog"),
                    "public_repos": user_data.get("public_repos"),
                    "followers": user_data.get("followers"),
                    "following": user_data.get("following"),
                    "created_at": user_data.get("created_at"),
                    "avatar_url": user_data.get("avatar_url"),
                },
            )
        ]


class GravatarAPI(BaseAPIClient):
    """Gravatar API for email-to-profile lookups."""

    def _get_default_config(self) -> APIConfig:
        return API_REGISTRY["gravatar"]

    def _email_hash(self, email: str) -> str:
        """Generate MD5 hash of email for Gravatar."""
        return hashlib.md5(email.lower().strip().encode()).hexdigest()

    async def get_profile(self, email: str) -> Optional[Dict[str, Any]]:
        """Get Gravatar profile for an email.

        Args:
            email: Email address

        Returns:
            Profile data or None if not found
        """
        if not self.is_enabled:
            return None

        email_hash = self._email_hash(email)

        try:
            response = await self.get(
                f"/{email_hash}.json",
                headers={"User-Agent": "TR4C3R/1.0"},
            )
            if response.status_code == 200:
                data = response.json()
                if "entry" in data and len(data["entry"]) > 0:
                    return data["entry"][0]
            return None
        except Exception as e:
            self.logger.debug("Gravatar lookup failed for %s: %s", email, e)
            return None

    async def search(self, query: str) -> List[Result]:
        """Search for Gravatar profile by email.

        Args:
            query: Email address

        Returns:
            List of Result objects
        """
        profile = await self.get_profile(query)
        if not profile:
            return []

        email_hash = self._email_hash(query)
        return [
            Result(
                source="gravatar",
                identifier=query,
                url=f"https://gravatar.com/{email_hash}",
                confidence=0.9,
                metadata={
                    "display_name": profile.get("displayName"),
                    "preferred_username": profile.get("preferredUsername"),
                    "profile_url": profile.get("profileUrl"),
                    "thumbnail_url": profile.get("thumbnailUrl"),
                    "about_me": profile.get("aboutMe"),
                    "current_location": profile.get("currentLocation"),
                    "accounts": [
                        {"domain": a.get("domain"), "username": a.get("username")}
                        for a in profile.get("accounts", [])
                    ],
                },
            )
        ]


class EmailRepAPI(BaseAPIClient):
    """EmailRep.io API for email reputation lookups."""

    def _get_default_config(self) -> APIConfig:
        return API_REGISTRY["emailrep"]

    async def get_reputation(self, email: str) -> Optional[Dict[str, Any]]:
        """Get email reputation.

        Args:
            email: Email address

        Returns:
            Reputation data or None
        """
        if not self.is_enabled:
            return None

        headers = {"User-Agent": "TR4C3R/1.0"}
        if self._api_key:
            headers["Key"] = self._api_key

        try:
            response = await self.get(f"/{email}", headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.debug("EmailRep lookup failed for %s: %s", email, e)
            return None

    async def search(self, query: str) -> List[Result]:
        """Search for email reputation.

        Args:
            query: Email address

        Returns:
            List of Result objects
        """
        rep = await self.get_reputation(query)
        if not rep:
            return []

        confidence = 0.7
        if rep.get("reputation") == "high":
            confidence = 0.9
        elif rep.get("reputation") == "low":
            confidence = 0.5

        return [
            Result(
                source="emailrep",
                identifier=query,
                url=f"https://emailrep.io/{query}",
                confidence=confidence,
                metadata={
                    "reputation": rep.get("reputation"),
                    "suspicious": rep.get("suspicious"),
                    "references": rep.get("references"),
                    "details": rep.get("details", {}),
                    "profiles": rep.get("profiles", []),
                },
            )
        ]


class IPInfoAPI(BaseAPIClient):
    """IPInfo.io API for IP geolocation."""

    def _get_default_config(self) -> APIConfig:
        return API_REGISTRY["ipinfo"]

    async def get_ip_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get IP information.

        Args:
            ip: IP address

        Returns:
            IP data or None
        """
        if not self.is_enabled:
            return None

        params = {}
        if self._api_key:
            params["token"] = self._api_key

        try:
            response = await self.get(
                f"/{ip}/json",
                params=params if params else None,
                headers={"User-Agent": "TR4C3R/1.0"},
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.debug("IPInfo lookup failed for %s: %s", ip, e)
            return None

    async def search(self, query: str) -> List[Result]:
        """Search for IP information.

        Args:
            query: IP address

        Returns:
            List of Result objects
        """
        info = await self.get_ip_info(query)
        if not info:
            return []

        return [
            Result(
                source="ipinfo",
                identifier=query,
                url=f"https://ipinfo.io/{query}",
                confidence=0.95,
                metadata={
                    "hostname": info.get("hostname"),
                    "city": info.get("city"),
                    "region": info.get("region"),
                    "country": info.get("country"),
                    "loc": info.get("loc"),
                    "org": info.get("org"),
                    "postal": info.get("postal"),
                    "timezone": info.get("timezone"),
                },
            )
        ]


class HunterAPI(BaseAPIClient):
    """Hunter.io API for email verification (PAID)."""

    def _get_default_config(self) -> APIConfig:
        return API_REGISTRY["hunter"]

    async def verify_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Verify an email address.

        Args:
            email: Email to verify

        Returns:
            Verification data or None
        """
        if not self.is_enabled or not self._api_key:
            return None

        try:
            response = await self.get(
                "/email-verifier",
                params={"email": email, "api_key": self._api_key},
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("data")
            return None
        except Exception as e:
            self.logger.debug("Hunter verification failed for %s: %s", email, e)
            return None

    async def search(self, query: str) -> List[Result]:
        """Verify an email.

        Args:
            query: Email address

        Returns:
            List of Result objects
        """
        if not self.is_enabled:
            return []

        data = await self.verify_email(query)
        if not data:
            return []

        return [
            Result(
                source="hunter",
                identifier=query,
                url=None,
                confidence=0.9 if data.get("result") == "deliverable" else 0.5,
                metadata={
                    "result": data.get("result"),
                    "score": data.get("score"),
                    "regexp": data.get("regexp"),
                    "gibberish": data.get("gibberish"),
                    "disposable": data.get("disposable"),
                    "webmail": data.get("webmail"),
                    "mx_records": data.get("mx_records"),
                    "smtp_server": data.get("smtp_server"),
                    "smtp_check": data.get("smtp_check"),
                    "accept_all": data.get("accept_all"),
                },
            )
        ]


class HIBPApi(BaseAPIClient):
    """Have I Been Pwned API for breach lookups (PAID)."""

    def _get_default_config(self) -> APIConfig:
        return API_REGISTRY["hibp"]

    async def check_breaches(self, email: str) -> List[Dict[str, Any]]:
        """Check if an email appears in data breaches.

        Args:
            email: Email to check

        Returns:
            List of breach records
        """
        if not self.is_enabled or not self._api_key:
            return []

        try:
            response = await self.get(
                f"/breachedaccount/{email}",
                headers={
                    "hibp-api-key": self._api_key,
                    "User-Agent": "TR4C3R/1.0",
                },
                params={"truncateResponse": "false"},
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []  # No breaches found
            return []
        except Exception as e:
            self.logger.debug("HIBP check failed for %s: %s", email, e)
            return []

    async def search(self, query: str) -> List[Result]:
        """Search for email in breaches.

        Args:
            query: Email address

        Returns:
            List of Result objects
        """
        if not self.is_enabled:
            return []

        breaches = await self.check_breaches(query)
        if not breaches:
            return []

        return [
            Result(
                source="hibp",
                identifier=query,
                url="https://haveibeenpwned.com/",
                confidence=1.0,
                metadata={
                    "breach_count": len(breaches),
                    "breaches": [
                        {
                            "name": b.get("Name"),
                            "title": b.get("Title"),
                            "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"),
                            "data_classes": b.get("DataClasses", []),
                            "pwn_count": b.get("PwnCount"),
                        }
                        for b in breaches[:10]  # Limit to first 10
                    ],
                },
            )
        ]


class APIIntegrationManager:
    """Manages all API integrations."""

    def __init__(self) -> None:
        """Initialize the integration manager."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self._clients: Dict[str, BaseAPIClient] = {}

        # Initialize clients
        self._clients["github"] = GitHubAPI()
        self._clients["gravatar"] = GravatarAPI()
        self._clients["emailrep"] = EmailRepAPI()
        self._clients["ipinfo"] = IPInfoAPI()
        self._clients["hunter"] = HunterAPI()
        self._clients["hibp"] = HIBPApi()

    def get_client(self, name: str) -> Optional[BaseAPIClient]:
        """Get an API client by name."""
        return self._clients.get(name)

    def get_enabled_clients(self) -> Dict[str, BaseAPIClient]:
        """Get all enabled API clients."""
        return {name: client for name, client in self._clients.items() if client.is_enabled}

    def get_free_clients(self) -> Dict[str, BaseAPIClient]:
        """Get all free API clients."""
        return {
            name: client
            for name, client in self._clients.items()
            if client.config.is_free and client.is_enabled
        }

    def get_paid_clients(self) -> Dict[str, BaseAPIClient]:
        """Get all paid API clients."""
        return {
            name: client
            for name, client in self._clients.items()
            if not client.config.is_free and client.is_enabled
        }

    async def search_all(
        self,
        query: str,
        query_type: str = "username",
    ) -> Dict[str, List[Result]]:
        """Search across all enabled APIs.

        Args:
            query: Search query
            query_type: Type of query (username, email, ip)

        Returns:
            Dictionary of results by API name
        """
        results: Dict[str, List[Result]] = {}

        # Select appropriate clients based on query type
        clients_to_use = []
        if query_type == "email":
            clients_to_use = ["gravatar", "emailrep", "hunter", "hibp"]
        elif query_type == "username":
            clients_to_use = ["github"]
        elif query_type == "ip":
            clients_to_use = ["ipinfo"]
        else:
            clients_to_use = list(self._clients.keys())

        # Execute searches concurrently
        tasks = {}
        for name in clients_to_use:
            client = self._clients.get(name)
            if client and client.is_enabled:
                tasks[name] = asyncio.create_task(self._safe_search(client, query))

        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, result in zip(tasks.keys(), completed):
            if isinstance(result, Exception):
                self.logger.warning("API %s failed: %s", name, result)
                results[name] = []
            else:
                results[name] = result

        return results

    async def _safe_search(
        self,
        client: BaseAPIClient,
        query: str,
    ) -> List[Result]:
        """Safely execute a search."""
        try:
            return await client.search(query)
        except Exception as e:
            self.logger.warning("%s search failed: %s", client.config.name, e)
            return []

    async def close_all(self) -> None:
        """Close all API clients."""
        for client in self._clients.values():
            await client.close()

    def list_apis(self) -> Dict[str, Dict[str, Any]]:
        """List all registered APIs with their status.

        Returns:
            Dictionary of API info
        """
        apis = {}
        for name, client in self._clients.items():
            apis[name] = {
                "name": client.config.name,
                "enabled": client.is_enabled,
                "is_free": client.config.is_free,
                "requires_auth": client.config.requires_auth,
                "has_api_key": bool(client.api_key),
            }
        return apis


# Convenience function
async def search_with_apis(
    query: str,
    query_type: str = "username",
) -> Dict[str, List[Result]]:
    """Search using all enabled API integrations.

    Args:
        query: Search query
        query_type: Type of query (username, email, ip)

    Returns:
        Dictionary of results by API name
    """
    manager = APIIntegrationManager()
    try:
        return await manager.search_all(query, query_type)
    finally:
        await manager.close_all()

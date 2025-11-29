"""Dark‑web search module for TR4C3R.

This module defines the ``DarkWebSearch`` class for searching dark web
data sources through Tor. It includes safety mechanisms, onion service
directory search, and metadata extraction from data dumps and forums.

⚠️ WARNING: This module accesses the dark web. Use responsibly and legally.
Only meta-information about potential leaks is returned, not actual leaked data.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import httpx

from src.core.config import get_config
from src.core.data_models import Result

logger = logging.getLogger(__name__)


class TorClient:
    """Manages HTTP connections through Tor SOCKS proxy."""

    def __init__(self, socks_proxy: str = "socks5://127.0.0.1:9050", timeout: float = 30.0):
        """Initialize Tor client.

        Parameters
        ----------
        socks_proxy : str
            Tor SOCKS proxy URL.
        timeout : float
            Request timeout in seconds.
        """
        self.socks_proxy = socks_proxy
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)
        self._transport = None

    def _get_transport(self):
        """Get the SOCKS transport for httpx.

        Returns
        -------
        httpx.HTTPTransport or None
            Transport configured for SOCKS proxy, or None if not available.
        """
        if self._transport is not None:
            return self._transport

        try:
            # httpx 0.24+ uses mounts with proxy URL
            import httpx

            self._transport = httpx.HTTPTransport(proxy=self.socks_proxy)
            return self._transport
        except Exception:
            pass

        # Fallback: try socksio if available
        try:
            import socksio  # noqa: F401
            import httpx

            self._transport = httpx.HTTPTransport(proxy=self.socks_proxy)
            return self._transport
        except ImportError:
            self.logger.warning("socksio not installed, SOCKS proxy not available")
            return None

    async def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        """Make GET request through Tor.

        Parameters
        ----------
        url : str
            URL to request.
        headers : Optional[Dict[str, str]]
            HTTP headers.

        Returns
        -------
        httpx.Response
            HTTP response.
        """
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
        }
        if headers:
            default_headers.update(headers)

        transport = self._get_transport()

        try:
            if transport:
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=self.timeout,
                    verify=False,  # Onion sites often have self-signed certs
                ) as client:
                    return await client.get(url, headers=default_headers, follow_redirects=True)
            else:
                # No transport available, use direct connection
                # (only works for clearnet sites)
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                ) as client:
                    return await client.get(url, headers=default_headers, follow_redirects=True)
        except Exception as e:
            self.logger.error(f"Tor request failed: {e}")
            raise

    async def check_tor_connection(self) -> bool:
        """Check if Tor connection is working.

        Returns
        -------
        bool
            True if connected through Tor, False otherwise.
        """
        try:
            response = await self.get("https://check.torproject.org/api/ip")
            data = response.json()
            return data.get("IsTor", False)
        except Exception as e:
            self.logger.error(f"Failed to verify Tor connection: {e}")
            return False


class DarkWebSearch:
    """Performs OSINT searches on dark‑web data sources."""

    # Known dark web search engines and services (clearnet mirrors)
    SEARCH_ENGINES = {
        "ahmia": {
            "url": "https://ahmia.fi/search/?q={query}",
            "clearnet": True,
            "description": "Ahmia.fi - Tor search engine",
        },
        "torch": {
            "url": "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={query}",
            "clearnet": False,
            "description": "Torch - Deep web search",
        },
    }

    # Onion service directories
    ONION_DIRECTORIES = [
        "https://thehiddenwiki.org",
        "https://dark.fail",  # Onion service verification
    ]

    # Patterns for identifying leaks and sensitive data mentions
    LEAK_PATTERNS = {
        "database": r"database|dump|leak|breach",
        "credentials": r"password|credential|auth|login",
        "email": r"email|e-mail|mail",
        "phone": r"phone|mobile|cell|number",
        "financial": r"credit\s*card|bank|payment|financial",
    }

    def __init__(
        self,
        use_tor: bool = True,
        socks_proxy: str = "socks5://127.0.0.1:9050",
        safe_mode: bool = True,
    ) -> None:
        """Initialize dark web search.

        Parameters
        ----------
        use_tor : bool
            Whether to use Tor for connections.
        socks_proxy : str
            Tor SOCKS proxy URL.
        safe_mode : bool
            Enable safety checks and warnings.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = get_config()
        self.use_tor = use_tor
        self.safe_mode = safe_mode

        if use_tor:
            self.tor_client = TorClient(socks_proxy=socks_proxy)
        else:
            self.tor_client = None

        if safe_mode:
            self.logger.warning(
                "⚠️  Dark web search enabled. Use responsibly and legally. "
                "Only meta-information will be collected, not actual leaked data."
            )

    async def _verify_tor_connection(self) -> bool:
        """Verify that Tor connection is working.

        Returns
        -------
        bool
            True if Tor is working, False otherwise.
        """
        if not self.use_tor or not self.tor_client:
            self.logger.warning("Tor not enabled - will use clearnet search only")
            return False

        self.logger.info("Verifying Tor connection...")
        is_connected = await self.tor_client.check_tor_connection()

        if is_connected:
            self.logger.info("✓ Tor connection verified")
        else:
            self.logger.error(
                "✗ Tor connection failed. Start Tor service: "
                "brew services start tor (macOS) or systemctl start tor (Linux)"
            )

        return is_connected

    def _is_onion_url(self, url: str) -> bool:
        """Check if URL is an onion service.

        Parameters
        ----------
        url : str
            URL to check.

        Returns
        -------
        bool
            True if onion URL.
        """
        return ".onion" in url

    async def _search_ahmia(self, identifier: str) -> List[Result]:
        """Search Ahmia.fi for identifier.

        Parameters
        ----------
        identifier : str
            Identifier to search for.

        Returns
        -------
        List[Result]
            Search results.
        """
        results = []

        try:
            url = self.SEARCH_ENGINES["ahmia"]["url"].format(query=identifier)
            self.logger.debug(f"Searching Ahmia: {url}")

            # Ahmia is clearnet, use regular HTTP
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)

            if response.status_code == 200:
                # Parse results (simplified - real implementation would parse HTML)
                content = response.text

                # Check for leak patterns
                leak_types = []
                for leak_type, pattern in self.LEAK_PATTERNS.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        leak_types.append(leak_type)

                if leak_types or identifier.lower() in content.lower():
                    result = Result(
                        source="darkweb:ahmia",
                        identifier=identifier,
                        url=url,
                        confidence=0.6,  # Lower confidence for dark web results
                        timestamp=datetime.now(timezone.utc),
                        metadata={
                            "search_engine": "ahmia",
                            "potential_leak_types": leak_types,
                            "content_length": len(content),
                            "warning": "Dark web result - verify independently",
                        },
                    )
                    results.append(result)

        except Exception as e:
            self.logger.error(f"Error searching Ahmia: {e}")

        return results

    async def _search_onion_directory(self, identifier: str) -> List[Result]:
        """Search onion service directories.

        Parameters
        ----------
        identifier : str
            Identifier to search for.

        Returns
        -------
        List[Result]
            Onion services mentioning the identifier.
        """
        results = []

        if not self.use_tor:
            self.logger.warning("Tor not enabled - skipping onion directory search")
            return results

        for directory_url in self.ONION_DIRECTORIES:
            try:
                self.logger.debug(f"Searching directory: {directory_url}")

                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(directory_url)

                if response.status_code == 200:
                    content = response.text

                    # Look for .onion URLs in the directory
                    onion_pattern = r"([a-z0-9]{16,56}\.onion)"
                    onions = re.findall(onion_pattern, content, re.IGNORECASE)

                    if onions and identifier.lower() in content.lower():
                        result = Result(
                            source="darkweb:directory",
                            identifier=identifier,
                            url=directory_url,
                            confidence=0.5,
                            timestamp=datetime.now(timezone.utc),
                            metadata={
                                "directory": directory_url,
                                "onion_services_found": len(set(onions)),
                                "warning": "Directory listing - verify services independently",
                            },
                        )
                        results.append(result)

            except Exception as e:
                self.logger.error(f"Error searching directory {directory_url}: {e}")

        return results

    async def _check_data_breach_mentions(self, identifier: str) -> List[Result]:
        """Check for mentions in known data breach indexes.

        Parameters
        ----------
        identifier : str
            Identifier to check.

        Returns
        -------
        List[Result]
            Breach mentions.
        """
        results = []

        # This would integrate with services like:
        # - DeHashed (clearnet API for leaked data)
        # - LeakCheck
        # - Snusbase
        # For now, return placeholder

        self.logger.info(
            f"Checking data breach indexes for '{identifier}' "
            "(placeholder - integrate with breach APIs)"
        )

        return results

    async def search(self, identifier: str, check_tor: bool = True) -> List[Result]:
        """Search dark‑web indexes for the given identifier.

        Parameters
        ----------
        identifier : str
            The identifier to search for (username, email, phone, etc.).
        check_tor : bool
            Whether to verify Tor connection first.

        Returns
        -------
        List[Result]
            Search results with metadata about potential leaks.
        """
        self.logger.info(f"Starting dark‑web search for '{identifier}'")

        if self.safe_mode:
            self.logger.warning(
                f"⚠️  Searching dark web for: {identifier}. "
                "Only meta-information will be collected."
            )

        results: List[Result] = []

        # Verify Tor if requested
        if check_tor and self.use_tor:
            tor_connected = await self._verify_tor_connection()
            if not tor_connected:
                self.logger.warning("Continuing with clearnet searches only (Tor not available)")

        # Search clearnet dark web search engines
        ahmia_results = await self._search_ahmia(identifier)
        results.extend(ahmia_results)

        # Search onion directories (requires Tor)
        directory_results = await self._search_onion_directory(identifier)
        results.extend(directory_results)

        # Check data breach indexes
        breach_results = await self._check_data_breach_mentions(identifier)
        results.extend(breach_results)

        self.logger.info(
            f"Completed dark‑web search for '{identifier}': " f"found {len(results)} results"
        )

        return results

    async def search_onion_service(self, onion_url: str, identifier: str) -> Optional[Result]:
        """Search a specific onion service for an identifier.

        Parameters
        ----------
        onion_url : str
            Onion service URL.
        identifier : str
            Identifier to search for.

        Returns
        -------
        Optional[Result]
            Result if found, None otherwise.
        """
        if not self._is_onion_url(onion_url):
            self.logger.error(f"Not an onion URL: {onion_url}")
            return None

        if not self.use_tor or not self.tor_client:
            self.logger.error("Tor required for onion service search")
            return None

        try:
            self.logger.info(f"Searching onion service: {onion_url}")

            response = await self.tor_client.get(onion_url)

            if response.status_code == 200:
                content = response.text

                if identifier.lower() in content.lower():
                    return Result(
                        source="darkweb:onion",
                        identifier=identifier,
                        url=onion_url,
                        confidence=0.7,
                        timestamp=datetime.now(timezone.utc),
                        metadata={
                            "onion_service": onion_url,
                            "content_length": len(content),
                            "warning": "Onion service result - verify independently",
                        },
                    )

        except Exception as e:
            self.logger.error(f"Error searching onion service: {e}")

        return None

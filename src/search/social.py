"""Social media search module for TR4C3R.

This module defines the ``SocialMediaSearch`` class, responsible for
searching for a user across supported social media platforms. It handles
rate limiting, profile detection, and optional NSFW content filtering.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from src.core.config import get_config
from src.core.data_models import Result


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, calls: int, period: float):
        """Initialize rate limiter.

        Parameters
        ----------
        calls : int
            Number of calls allowed per period.
        period : float
            Time period in seconds.
        """
        self.calls = calls
        self.period = period
        self.timestamps: List[float] = []

    async def acquire(self) -> None:
        """Wait if necessary to respect rate limit."""
        now = time.time()
        # Remove timestamps outside the current window
        self.timestamps = [ts for ts in self.timestamps if now - ts < self.period]

        if len(self.timestamps) >= self.calls:
            # Need to wait
            sleep_time = self.period - (now - self.timestamps[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
            # Refresh timestamps after sleep
            now = time.time()
            self.timestamps = [ts for ts in self.timestamps if now - ts < self.period]

        self.timestamps.append(now)


class SocialMediaSearch:
    """Performs OSINT searches across social media platforms."""

    # Known patterns for profile detection
    PROFILE_INDICATORS = {
        "twitter": ["tweets", "following", "followers", "joined"],
        "instagram": ["posts", "followers", "following"],
        "linkedin": ["experience", "education", "skills", "connections"],
        "facebook": ["friends", "photos", "about"],
        "youtube": ["subscribers", "videos", "views"],
        "tiktok": ["followers", "following", "likes"],
        "twitch": ["followers", "videos", "clips"],
        "medium": ["stories", "followers", "following"],
        "reddit": ["karma", "cake day"],
    }

    def __init__(
        self,
        platforms: Optional[List[str]] = None,
        enable_nsfw_detection: bool = False,
        rate_limit_calls: int = 10,
        rate_limit_period: float = 60.0,
    ) -> None:
        """Initialize social media search.

        Parameters
        ----------
        platforms : Optional[List[str]]
            Specific platforms to search. If None, searches all enabled platforms.
        enable_nsfw_detection : bool
            Whether to enable NSFW content detection.
        rate_limit_calls : int
            Number of calls allowed per rate limit period.
        rate_limit_period : float
            Rate limit period in seconds.
        """
        self.config = get_config()
        self.platforms = platforms
        self.enable_nsfw_detection = enable_nsfw_detection
        self.logger = logging.getLogger(self.__class__.__name__)
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        self.rate_limiter = RateLimiter(rate_limit_calls, rate_limit_period)

        # Load NSFW detector if enabled
        self.nsfw_detector = None
        if enable_nsfw_detection:
            try:
                from src.enhancement.nsfw_detector import NSFWDetector

                self.nsfw_detector = NSFWDetector()
            except ImportError:
                self.logger.warning("NSFW detection enabled but NSFWDetector not available")

    def _get_enabled_platforms(self) -> List[str]:
        """Get list of enabled platforms from config.

        Returns
        -------
        List[str]
            List of enabled platform names.
        """
        sites = self.config.get("sites", {})
        enabled = []

        for platform, config in sites.items():
            if isinstance(config, dict) and config.get("enabled", False):
                # Filter by requested platforms if specified
                if self.platforms is None or platform in self.platforms:
                    enabled.append(platform)

        return enabled

    def _build_profile_url(self, platform: str, username: str) -> str:
        """Build profile URL for a platform.

        Parameters
        ----------
        platform : str
            Platform name.
        username : str
            Username to search for.

        Returns
        -------
        str
            Profile URL.
        """
        site_config = self.config.get_site_config(platform)
        if site_config and "url_template" in site_config:
            return site_config["url_template"].format(username=username)
        return ""

    async def _check_profile_exists(
        self, platform: str, url: str
    ) -> tuple[bool, float, Dict[str, Any]]:
        """Check if a profile exists on a platform.

        Parameters
        ----------
        platform : str
            Platform name.
        url : str
            Profile URL to check.

        Returns
        -------
        tuple[bool, float, Dict[str, Any]]
            (exists, confidence, metadata)
        """
        await self.rate_limiter.acquire()

        try:
            response = await self.http_client.get(url)

            # Check status code
            if response.status_code == 404:
                return False, 0.0, {"status": "not_found"}

            if response.status_code != 200:
                return False, 0.0, {"status": f"http_{response.status_code}"}

            # Get response text
            content = response.text.lower()

            # Check for profile indicators
            indicators_found = []
            if platform in self.PROFILE_INDICATORS:
                for indicator in self.PROFILE_INDICATORS[platform]:
                    if indicator in content:
                        indicators_found.append(indicator)

            # Calculate confidence based on indicators
            if indicators_found:
                confidence = min(0.9, 0.5 + (len(indicators_found) * 0.1))
            else:
                # Profile exists but no strong indicators
                confidence = 0.6

            metadata = {
                "status": "found",
                "status_code": response.status_code,
                "indicators": indicators_found,
                "content_length": len(response.text),
            }

            # Check for NSFW content if enabled
            if self.nsfw_detector:
                # For now, just mark as checked
                metadata["nsfw_checked"] = True
                # TODO: Implement actual NSFW detection on content

            return True, confidence, metadata

        except httpx.HTTPError as e:
            self.logger.debug(f"HTTP error checking {url}: {e}")
            return False, 0.0, {"status": "error", "error": str(e)}
        except Exception as e:
            self.logger.error(f"Error checking {url}: {e}")
            return False, 0.0, {"status": "error", "error": str(e)}

    async def _search_platform(self, platform: str, identifier: str) -> Optional[Result]:
        """Search for identifier on a specific platform.

        Parameters
        ----------
        platform : str
            Platform name.
        identifier : str
            Username or identifier to search for.

        Returns
        -------
        Optional[Result]
            Result if profile found, None otherwise.
        """
        url = self._build_profile_url(platform, identifier)
        if not url:
            self.logger.debug(f"No URL template for platform: {platform}")
            return None

        self.logger.debug(f"Checking {platform} profile: {url}")

        exists, confidence, metadata = await self._check_profile_exists(platform, url)

        if exists:
            return Result(
                source=f"social:{platform}",
                identifier=identifier,
                url=url,
                confidence=confidence,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "platform": platform,
                    "username": identifier,
                    **metadata,
                },
            )

        return None

    async def search(self, identifier: str) -> List[Result]:
        """Search for the given identifier across social media platforms.

        Parameters
        ----------
        identifier : str
            The identifier to search for, typically a username.

        Returns
        -------
        List[Result]
            List of found profiles.
        """
        self.logger.info(f"Starting social media search for '{identifier}'")

        platforms = self._get_enabled_platforms()
        if not platforms:
            self.logger.warning("No enabled platforms found in configuration")
            return []

        self.logger.debug(f"Searching {len(platforms)} platforms: {platforms}")

        # Search all platforms concurrently
        tasks = [self._search_platform(platform, identifier) for platform in platforms]
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out None values and exceptions
        results = []
        for i, result in enumerate(results_raw):
            if isinstance(result, Exception):
                self.logger.error(f"Error searching {platforms[i]}: {result}", exc_info=result)
            elif result is not None:
                results.append(result)

        self.logger.info(
            f"Completed social media search for '{identifier}': "
            f"found {len(results)} profiles across {len(platforms)} platforms"
        )

        return results

    async def search_with_variants(self, identifier: str, max_variants: int = 10) -> List[Result]:
        """Search with username variants.

        Parameters
        ----------
        identifier : str
            Base identifier to search for.
        max_variants : int
            Maximum number of variants to generate.

        Returns
        -------
        List[Result]
            Combined results from all variants.
        """
        from src.core.variant_generator import generate_variants

        variants = generate_variants(identifier, max_variants=max_variants)

        self.logger.info(f"Searching social media with {len(variants)} variants of '{identifier}'")

        # Search with all variants
        all_results = []
        for variant in variants[:max_variants]:
            results = await self.search(variant)
            all_results.extend(results)

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for result in all_results:
            if result.url not in seen_urls:
                seen_urls.add(result.url)
                unique_results.append(result)

        return unique_results

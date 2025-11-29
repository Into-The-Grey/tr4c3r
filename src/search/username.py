"""Username search module for TR4C3R.

Provides the :class:`UsernameSearch` class which performs asynchronous lookups
for a given username across a configurable list of public endpoints.  The
implementation favours resilience: it performs concurrent HTTP requests with
bounded parallelism, gracefully handles timeouts and integrates with the
variant generator to support fuzzy lookups.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from src.core.data_models import Result
from src.core.http_client import AsyncHTTPClient
from src.core.variant_generator import generate_variants


@dataclass(frozen=True)
class SiteConfig:
    """Configuration for a username lookup endpoint."""

    name: str
    url_template: str
    positive_markers: Sequence[str] = ()
    negative_markers: Sequence[str] = ()
    headers: Optional[Dict[str, str]] = None

    def build_url(self, username: str) -> str:
        return self.url_template.format(username=username)


def _default_sites() -> List[SiteConfig]:
    """Return the built-in set of community-friendly endpoints."""

    return [
        SiteConfig(
            name="github",
            url_template="https://api.github.com/users/{username}",
            positive_markers=('"login":',),
            negative_markers=("Not Found",),
            headers={"Accept": "application/vnd.github+json"},
        ),
        SiteConfig(
            name="reddit",
            url_template="https://www.reddit.com/user/{username}/about.json",
            positive_markers=('"name":',),
            negative_markers=('"error":',),
            headers={"Accept": "application/json"},
        ),
        SiteConfig(
            name="keybase",
            url_template="https://keybase.io/{username}.json",
            positive_markers=("body",),
        ),
    ]


class UsernameSearch:
    """Performs OSINT searches for usernames across multiple services."""

    DEFAULT_USER_AGENT = "TR4C3R/0.1 (+https://github.com/tr4c3r)"

    def __init__(
        self,
        sites: Optional[Iterable[SiteConfig]] = None,
        *,
        concurrency: int = 5,
        http_timeout: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        self.sites = list(sites) if sites is not None else _default_sites()
        self.concurrency = max(1, concurrency)
        self.http_timeout = http_timeout
        self.max_retries = max_retries
        self.logger = logging.getLogger(self.__class__.__name__)

    async def search(
        self, username: str, *, fuzzy: bool = False, max_variants: int = 25
    ) -> List[Result]:
        """Search for the given username across configured sites."""

        self.logger.debug(
            "Starting username search for '%s' (fuzzy=%s, max_variants=%s)",
            username,
            fuzzy,
            max_variants,
        )
        candidates = self._build_candidates(username, fuzzy=fuzzy, max_variants=max_variants)
        if not candidates:
            return []

        sem = asyncio.Semaphore(self.concurrency)
        tasks = []
        async with AsyncHTTPClient(
            timeout=self.http_timeout, max_retries=self.max_retries
        ) as client:
            for candidate in candidates:
                for site in self.sites:
                    tasks.append(
                        asyncio.create_task(
                            self._query_site(
                                client=client,
                                semaphore=sem,
                                site=site,
                                candidate=candidate,
                                canonical=username,
                            )
                        )
                    )
            responses = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[Result] = []
        for response in responses:
            if isinstance(response, Result):
                results.append(response)
            elif isinstance(response, Exception):
                self.logger.debug("Username search task failed: %s", response)

        self.logger.debug(
            "Completed username search for '%s' with %d results", username, len(results)
        )
        return results

    def _build_candidates(self, username: str, *, fuzzy: bool, max_variants: int) -> List[str]:
        username = username.strip()
        if not username:
            return []
        if not fuzzy:
            return [username]
        variants = generate_variants(username, max_variants=max_variants)
        ordered = sorted(set([username] + variants), key=lambda item: (item != username, item))
        return ordered[: max_variants or len(ordered)]

    async def _query_site(
        self,
        *,
        client: AsyncHTTPClient,
        semaphore: asyncio.Semaphore,
        site: SiteConfig,
        candidate: str,
        canonical: str,
    ) -> Optional[Result]:
        async with semaphore:
            try:
                response = await client.request(
                    "GET",
                    site.build_url(candidate),
                    headers=self._build_headers(site),
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.debug(
                    "Site '%s' request failed for '%s': %s", site.name, candidate, exc
                )
                return None

        if not self._response_indicates_presence(site, response):
            return None

        confidence = 1.0 if candidate == canonical else 0.7
        metadata = {
            "site": site.name,
            "queried_candidate": candidate,
            "status_code": response.status_code,
        }
        return Result(
            source=f"username:{site.name}",
            identifier=canonical,
            url=site.build_url(candidate),
            confidence=confidence,
            metadata=metadata,
        )

    def _build_headers(self, site: SiteConfig) -> Dict[str, str]:
        headers = {"User-Agent": self.DEFAULT_USER_AGENT}
        if site.headers:
            headers.update(site.headers)
        return headers

    def _response_indicates_presence(self, site: SiteConfig, response) -> bool:
        """Decide whether a response indicates the username exists."""

        if response.status_code == 404:
            return False

        body = response.text or ""
        if site.negative_markers and any(marker in body for marker in site.negative_markers):
            return False
        if site.positive_markers:
            return any(marker in body for marker in site.positive_markers)
        return response.status_code < 400

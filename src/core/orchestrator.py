"""Central orchestrator for TR4C3R.

This module defines the ``Orchestrator`` class responsible for coordinating
different search modules, merging their results and storing them in the
database.  It exposes a high‑level API that can be called by the CLI,
scripts or the web dashboard to perform searches for various identifiers.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Type

from src.search import (
    UsernameSearch,
    EmailSearch,
    NameSearch,
    PhoneSearch,
    SocialMediaSearch,
    DarkWebSearch,
)
from src.core.data_models import Result
from src.core.logging_setup import configure_logging


class Orchestrator:
    """Coordinates OSINT searches across multiple modules."""

    def __init__(self) -> None:
        # Configure logging once when orchestrator is instantiated
        configure_logging()
        self.logger = logging.getLogger(self.__class__.__name__)
        # Instantiate modules
        self.username_search = UsernameSearch()
        self.email_search = EmailSearch()
        self.name_search = NameSearch()
        self.phone_search = PhoneSearch()
        self.social_search = SocialMediaSearch()
        self.dark_search = DarkWebSearch()

    async def search_username(self, username: str, *, fuzzy: bool = False) -> List[Result]:
        """Run a username search and return results.

        Parameters
        ----------
        username: str
            The username to search for.
        fuzzy: bool
            Whether to generate variants of the username.
        """
        self.logger.info("Orchestrator: searching for username '%s' (fuzzy=%s)", username, fuzzy)
        results = await self.username_search.search(username, fuzzy=fuzzy)
        return results

    async def search_email(self, email: str) -> List[Result]:
        """Run an email search and return results."""
        self.logger.info("Orchestrator: searching for email '%s'", email)
        return await self.email_search.search(email)

    async def search_name(self, name: str) -> List[Result]:
        """Run a full name search and return results."""
        self.logger.info("Orchestrator: searching for name '%s'", name)
        return await self.name_search.search(name)

    async def search_phone(self, number: str) -> List[Result]:
        """Run a phone number search and return results."""
        self.logger.info("Orchestrator: searching for phone '%s'", number)
        return await self.phone_search.search(number)

    async def search_social(self, identifier: str) -> List[Result]:
        """Run a social media search for a username or email."""
        self.logger.info("Orchestrator: searching social platforms for '%s'", identifier)
        return await self.social_search.search(identifier)

    async def search_dark(self, identifier: str) -> List[Result]:
        """Run a dark‑web search for a given identifier."""
        self.logger.info("Orchestrator: searching dark‑web for '%s'", identifier)
        return await self.dark_search.search(identifier)

    async def search_all(self, identifier: str) -> Dict[str, List[Result]]:
        """Search across all modules for a given identifier.

        Parameters
        ----------
        identifier: str
            The identifier to search for (username, email, phone or full name).
        """
        self.logger.info("Orchestrator: running full search for '%s'", identifier)
        tasks = {
            "username": self.username_search.search(identifier),
            "email": self.email_search.search(identifier),
            "name": self.name_search.search(identifier),
            "phone": self.phone_search.search(identifier),
            "social": self.social_search.search(identifier),
            "dark": self.dark_search.search(identifier),
        }
        results = await asyncio.gather(*tasks.values())
        return {key: value for key, value in zip(tasks.keys(), results)}

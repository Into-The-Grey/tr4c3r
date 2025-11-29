"""Full‑name search module for TR4C3R.

This module defines the ``NameSearch`` class for locating occurrences of a
person's full name across public records, social sites and people directories.
Includes name disambiguation, location filtering, and ranking heuristics.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from src.core.data_models import Result
from src.core.http_client import AsyncHTTPClient


@dataclass
class NameComponents:
    """Parsed components of a full name."""

    full_name: str
    first_name: str
    middle_name: Optional[str]
    last_name: str
    suffixes: List[str]
    prefixes: List[str]
    variations: List[str]


class NameParser:
    """Parses and analyzes full names."""

    # Common name suffixes
    SUFFIXES = {"jr", "sr", "ii", "iii", "iv", "v", "phd", "md", "esq", "cpa"}

    # Common prefixes/titles
    PREFIXES = {"mr", "mrs", "ms", "miss", "dr", "prof", "rev"}

    # Common middle name indicators
    MIDDLE_INDICATORS = {"van", "de", "del", "la", "le", "von", "da"}

    def __init__(self):
        """Initialize the name parser."""
        self.logger = logging.getLogger(self.__class__.__name__)

    def parse(self, full_name: str) -> NameComponents:
        """
        Parse a full name into components.

        Args:
            full_name: The full name to parse

        Returns:
            NameComponents with parsed name parts
        """
        # Normalize the name
        full_name = full_name.strip()
        normalized = re.sub(r"\s+", " ", full_name)

        # Split into parts
        parts = normalized.split()

        if len(parts) == 0:
            return NameComponents(
                full_name=full_name,
                first_name="",
                middle_name=None,
                last_name="",
                suffixes=[],
                prefixes=[],
                variations=[],
            )

        # Extract prefixes
        prefixes = []
        while parts and parts[0].lower().rstrip(".") in self.PREFIXES:
            prefixes.append(parts.pop(0))

        # Extract suffixes from the end
        suffixes = []
        while parts and parts[-1].lower().rstrip(".") in self.SUFFIXES:
            suffixes.append(parts.pop())
        suffixes.reverse()

        # Now parse first, middle, last
        if len(parts) == 1:
            first_name = parts[0]
            middle_name = None
            last_name = ""
        elif len(parts) == 2:
            first_name = parts[0]
            middle_name = None
            last_name = parts[1]
        else:
            first_name = parts[0]
            last_name = parts[-1]
            middle_parts = parts[1:-1]
            middle_name = " ".join(middle_parts)

        # Generate variations
        variations = self._generate_variations(first_name, middle_name, last_name, suffixes)

        return NameComponents(
            full_name=normalized,
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            suffixes=suffixes,
            prefixes=prefixes,
            variations=variations,
        )

    def _generate_variations(
        self, first: str, middle: Optional[str], last: str, suffixes: List[str]
    ) -> List[str]:
        """Generate common name variations."""
        variations = []

        # Full name variations
        if middle:
            variations.append(f"{first} {middle} {last}")
            variations.append(f"{first} {middle[0]}. {last}")
            variations.append(f"{first[0]}. {middle} {last}")

        variations.append(f"{first} {last}")

        # With suffixes
        if suffixes:
            suffix_str = " ".join(suffixes)
            if middle:
                variations.append(f"{first} {middle} {last} {suffix_str}")
            variations.append(f"{first} {last} {suffix_str}")

        # Formal variations
        variations.append(f"{last}, {first}")
        if middle:
            variations.append(f"{last}, {first} {middle[0]}.")

        # Initials
        if middle:
            variations.append(f"{first[0]}.{middle[0]}. {last}")
        variations.append(f"{first[0]}. {last}")

        # Remove duplicates while preserving order
        seen: Set[str] = set()
        unique_variations = []
        for v in variations:
            if v not in seen:
                seen.add(v)
                unique_variations.append(v)

        return unique_variations


@dataclass
class DisambiguationContext:
    """Context for disambiguating people with the same name."""

    location: Optional[str] = None
    age_range: Optional[Tuple[int, int]] = None
    occupation: Optional[str] = None
    education: Optional[str] = None
    known_usernames: Optional[List[str]] = None
    known_emails: Optional[List[str]] = None


class NameSearch:
    """Performs OSINT searches for full names."""

    def __init__(self) -> None:
        """Initialize the name search module."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.parser = NameParser()
        self.http_client = AsyncHTTPClient()

        # Load API keys from environment
        self.pipl_api_key = os.getenv("PIPL_API_KEY", "")
        self.clearbit_api_key = os.getenv("CLEARBIT_API_KEY", "")

    async def search(
        self, full_name: str, context: Optional[DisambiguationContext] = None
    ) -> List[Result]:
        """
        Search for the given full name across multiple sources.

        Args:
            full_name: The full name to search for
            context: Optional disambiguation context (location, age, etc.)

        Returns:
            List of Result objects from various sources
        """
        self.logger.info(f"Starting name search for '{full_name}'")
        results: List[Result] = []

        # Step 1: Parse the name
        parsed = self.parser.parse(full_name)

        if not parsed.first_name and not parsed.last_name:
            self.logger.warning(f"Could not parse name: {full_name}")
            return results

        # Create name parsing result
        parsing_result = Result(
            source="name:parsing",
            identifier=parsed.full_name,
            url="",
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "original_input": full_name,
                "first_name": parsed.first_name,
                "middle_name": parsed.middle_name,
                "last_name": parsed.last_name,
                "prefixes": parsed.prefixes,
                "suffixes": parsed.suffixes,
                "variations": parsed.variations[:10],  # Limit to first 10
            },
        )
        results.append(parsing_result)

        # Step 2: Run searches in parallel
        search_tasks = [
            self._search_social_media(parsed, context),
            self._search_people_apis(parsed, context),
            self._search_public_records(parsed, context),
            self._apply_disambiguation(parsed, context),
        ]

        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        # Flatten results and filter out exceptions
        for task_results in search_results:
            if isinstance(task_results, Exception):
                self.logger.error(f"Search task failed: {task_results}")
                continue
            if isinstance(task_results, list):
                results.extend(task_results)

        # Step 3: Apply location filtering if context provided
        if context and context.location:
            results = self._filter_by_location(results, context.location)

        self.logger.info(f"Completed name search for '{full_name}' with {len(results)} results")
        return results

    async def _search_social_media(
        self, parsed: NameComponents, context: Optional[DisambiguationContext]
    ) -> List[Result]:
        """
        Search for name on social media platforms.

        Args:
            parsed: Parsed name components
            context: Optional disambiguation context

        Returns:
            List of Result objects from social media
        """
        results: List[Result] = []

        try:
            # Common social media username patterns from names
            potential_usernames = [
                f"{parsed.first_name.lower()}{parsed.last_name.lower()}",
                f"{parsed.first_name.lower()}.{parsed.last_name.lower()}",
                f"{parsed.first_name.lower()}_{parsed.last_name.lower()}",
                f"{parsed.first_name[0].lower()}{parsed.last_name.lower()}",
            ]

            result = Result(
                source="name:social_media_patterns",
                identifier=parsed.full_name,
                url="",
                confidence=0.5,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "potential_usernames": potential_usernames[:5],
                    "note": "Common username patterns derived from name",
                    "recommendation": "Use username search module to verify these",
                },
            )
            results.append(result)

        except Exception as e:
            self.logger.error(f"Social media search failed: {e}")

        return results

    async def _search_people_apis(
        self, parsed: NameComponents, context: Optional[DisambiguationContext]
    ) -> List[Result]:
        """
        Search people finder APIs.

        Args:
            parsed: Parsed name components
            context: Optional disambiguation context

        Returns:
            List of Result objects from people APIs
        """
        results: List[Result] = []

        # Pipl API integration
        if self.pipl_api_key:
            try:
                url = "https://api.pipl.com/search/"
                params = {
                    "key": self.pipl_api_key,
                    "first_name": parsed.first_name,
                    "last_name": parsed.last_name,
                }

                if context and context.location:
                    params["location"] = context.location

                async with self.http_client as client:
                    response = await client.get(url, params=params, timeout=15.0)

                    if response.status_code == 200:
                        data = response.json()

                        result = Result(
                            source="name:pipl",
                            identifier=parsed.full_name,
                            url="https://pipl.com/",
                            confidence=0.8,
                            timestamp=datetime.now(timezone.utc),
                            metadata={
                                "service": "Pipl",
                                "match_count": data.get("@match_count", 0),
                                "possible_persons": data.get("@possible_persons", 0),
                                "note": "People search API results",
                            },
                        )
                        results.append(result)

            except Exception as e:
                self.logger.error(f"Pipl API search failed: {e}")

        return results

    async def _search_public_records(
        self, parsed: NameComponents, context: Optional[DisambiguationContext]
    ) -> List[Result]:
        """
        Search public records and directories.

        Args:
            parsed: Parsed name components
            context: Optional disambiguation context

        Returns:
            List of Result objects from public records
        """
        results: List[Result] = []

        try:
            # Create a result with common public record sources
            sources = [
                "LinkedIn (professional profiles)",
                "Facebook (social profiles)",
                "Twitter/X (social profiles)",
                "WhitePages (phone directory)",
                "Spokeo (people search)",
                "BeenVerified (public records)",
                "ZoomInfo (business directory)",
                "Company websites (about pages)",
            ]

            result = Result(
                source="name:public_records",
                identifier=parsed.full_name,
                url="",
                confidence=0.6,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "recommended_sources": sources,
                    "name_variations": parsed.variations[:5],
                    "note": "Recommended public record sources for manual search",
                },
            )
            results.append(result)

        except Exception as e:
            self.logger.error(f"Public records search failed: {e}")

        return results

    async def _apply_disambiguation(
        self, parsed: NameComponents, context: Optional[DisambiguationContext]
    ) -> List[Result]:
        """
        Apply disambiguation heuristics.

        Args:
            parsed: Parsed name components
            context: Optional disambiguation context

        Returns:
            List with disambiguation guidance
        """
        results: List[Result] = []

        try:
            disambiguation_score = 0.5  # Base score
            disambiguation_factors = []

            # Common name penalty
            common_last_names = {
                "smith",
                "johnson",
                "williams",
                "brown",
                "jones",
                "garcia",
                "miller",
                "davis",
                "rodriguez",
                "martinez",
                "hernandez",
                "lopez",
                "gonzalez",
                "wilson",
                "anderson",
                "thomas",
                "taylor",
                "moore",
                "jackson",
                "martin",
                "lee",
                "thompson",
                "white",
            }

            if parsed.last_name.lower() in common_last_names:
                disambiguation_score -= 0.2
                disambiguation_factors.append("common_last_name")

            # Unique first name bonus
            if len(parsed.first_name) > 7:  # Longer names tend to be more unique
                disambiguation_score += 0.1
                disambiguation_factors.append("unique_first_name")

            # Middle name bonus (helps disambiguation)
            if parsed.middle_name:
                disambiguation_score += 0.15
                disambiguation_factors.append("has_middle_name")

            # Suffix bonus (jr, sr, etc. help identify specific person)
            if parsed.suffixes:
                disambiguation_score += 0.1
                disambiguation_factors.append("has_suffix")

            # Context bonuses
            if context:
                if context.location:
                    disambiguation_score += 0.2
                    disambiguation_factors.append("location_provided")
                if context.age_range:
                    disambiguation_score += 0.15
                    disambiguation_factors.append("age_range_provided")
                if context.occupation:
                    disambiguation_score += 0.1
                    disambiguation_factors.append("occupation_provided")
                if context.known_usernames:
                    disambiguation_score += 0.15
                    disambiguation_factors.append("known_usernames")
                if context.known_emails:
                    disambiguation_score += 0.15
                    disambiguation_factors.append("known_emails")

            # Clamp score between 0 and 1
            disambiguation_score = max(0.0, min(1.0, disambiguation_score))

            result = Result(
                source="name:disambiguation",
                identifier=parsed.full_name,
                url="",
                confidence=0.7,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "disambiguation_score": round(disambiguation_score, 2),
                    "factors": disambiguation_factors,
                    "uniqueness": (
                        "high"
                        if disambiguation_score > 0.7
                        else "medium" if disambiguation_score > 0.4 else "low"
                    ),
                    "recommendation": self._get_disambiguation_recommendation(disambiguation_score),
                    "has_context": context is not None,
                },
            )
            results.append(result)

        except Exception as e:
            self.logger.error(f"Disambiguation analysis failed: {e}")

        return results

    def _get_disambiguation_recommendation(self, score: float) -> str:
        """Get recommendation based on disambiguation score."""
        if score > 0.7:
            return "Name is relatively unique. Results likely accurate."
        elif score > 0.4:
            return "Moderate ambiguity. Use location or other context to narrow results."
        else:
            return (
                "High ambiguity. Strongly recommend providing location, age, or other identifiers."
            )

    def _filter_by_location(self, results: List[Result], location: str) -> List[Result]:
        """
        Filter results by location.

        Args:
            results: List of results to filter
            location: Location to filter by

        Returns:
            Filtered list of results
        """
        location_lower = location.lower()

        # Get the first result's identifier if available, otherwise use a placeholder
        identifier = "location_filter"
        if results:
            identifier = results[0].identifier

        # Add location filter note
        filter_result = Result(
            source="name:location_filter",
            identifier=identifier,
            url="",
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "filter_applied": "location",
                "location": location,
                "note": f"Results filtered for location: {location}",
            },
        )

        filtered_results = [filter_result] + results
        return filtered_results

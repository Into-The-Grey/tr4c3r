"""Result deduplication utilities for TR4C3R.

This module provides intelligent deduplication of search results,
handling similar results from different sources while preserving
the most relevant information.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from src.core.data_models import Result

logger = logging.getLogger(__name__)


class ResultDeduplicator:
    """Deduplicates search results intelligently."""

    def __init__(
        self,
        url_similarity_threshold: float = 0.9,
        merge_metadata: bool = True,
    ) -> None:
        """Initialize the deduplicator.

        Args:
            url_similarity_threshold: Threshold for considering URLs similar (0-1)
            merge_metadata: Whether to merge metadata from duplicate results
        """
        self.url_similarity_threshold = url_similarity_threshold
        self.merge_metadata = merge_metadata
        self.logger = logging.getLogger(self.__class__.__name__)

    def deduplicate(self, results: List[Result]) -> List[Result]:
        """Remove duplicate results while preserving the best version.

        The deduplication strategy:
        1. Group by normalized URL
        2. Within each group, keep the result with highest confidence
        3. Optionally merge metadata from all duplicates

        Args:
            results: List of results to deduplicate

        Returns:
            Deduplicated list of results
        """
        if not results:
            return []

        # Group results by normalized URL
        url_groups: Dict[str, List[Result]] = defaultdict(list)
        for result in results:
            normalized = self._normalize_url(result.url)
            url_groups[normalized].append(result)

        # Select best result from each group
        deduplicated: List[Result] = []
        for url, group in url_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                best = self._select_best_result(group)
                if self.merge_metadata:
                    best = self._merge_duplicate_metadata(best, group)
                deduplicated.append(best)
                self.logger.debug(
                    "Merged %d duplicates for URL: %s",
                    len(group),
                    url[:50] + "..." if len(url) > 50 else url,
                )

        # Sort by confidence (highest first)
        deduplicated.sort(key=lambda r: r.confidence, reverse=True)

        self.logger.info(
            "Deduplicated %d results to %d unique results",
            len(results),
            len(deduplicated),
        )

        return deduplicated

    def _normalize_url(self, url: Optional[str]) -> str:
        """Normalize URL for comparison.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL string
        """
        if not url:
            return ""

        try:
            parsed = urlparse(url.lower().strip())

            # Remove common tracking parameters
            path = parsed.path.rstrip("/")

            # Remove fragments
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}"

            return normalized
        except Exception:
            return url.lower().strip()

    def _select_best_result(self, group: List[Result]) -> Result:
        """Select the best result from a group of duplicates.

        Selection criteria (in order):
        1. Highest confidence score
        2. Most metadata
        3. First occurrence

        Args:
            group: Group of duplicate results

        Returns:
            Best result from the group
        """
        return max(
            group,
            key=lambda r: (
                r.confidence,
                len(r.metadata) if r.metadata else 0,
            ),
        )

    def _merge_duplicate_metadata(self, best: Result, group: List[Result]) -> Result:
        """Merge metadata from all duplicates into the best result.

        Args:
            best: The best result selected from the group
            group: All results in the duplicate group

        Returns:
            Result with merged metadata
        """
        merged_metadata = dict(best.metadata) if best.metadata else {}

        # Collect sources for reference
        sources = [r.source for r in group if r.source != best.source]
        if sources:
            merged_metadata["also_found_in"] = sources

        # Merge unique metadata keys from other results
        for result in group:
            if result is best:
                continue
            if result.metadata:
                for key, value in result.metadata.items():
                    if key not in merged_metadata:
                        merged_metadata[key] = value

        return Result(
            source=best.source,
            identifier=best.identifier,
            url=best.url,
            confidence=best.confidence,
            timestamp=best.timestamp,
            metadata=merged_metadata,
        )

    def deduplicate_by_identifier(self, results: List[Result]) -> List[Result]:
        """Deduplicate by identifier rather than URL.

        Useful when the same identifier (username, email, etc.) appears
        in multiple results but you want to keep only unique identifiers.

        Args:
            results: List of results to deduplicate

        Returns:
            Deduplicated list with unique identifiers
        """
        if not results:
            return []

        # Group by (source_type, identifier)
        seen: Dict[Tuple[str, str], Result] = {}
        for result in results:
            source_type = result.source.split(":")[0] if ":" in result.source else result.source
            key = (source_type, result.identifier.lower())

            if key not in seen:
                seen[key] = result
            elif result.confidence > seen[key].confidence:
                # Keep higher confidence result
                seen[key] = result

        return sorted(seen.values(), key=lambda r: r.confidence, reverse=True)


def deduplicate_results(
    results: List[Result],
    by_url: bool = True,
    merge_metadata: bool = True,
) -> List[Result]:
    """Convenience function to deduplicate results.

    Args:
        results: List of results to deduplicate
        by_url: If True, deduplicate by URL; if False, by identifier
        merge_metadata: Whether to merge metadata from duplicates

    Returns:
        Deduplicated list of results
    """
    dedup = ResultDeduplicator(merge_metadata=merge_metadata)

    if by_url:
        return dedup.deduplicate(results)
    else:
        return dedup.deduplicate_by_identifier(results)


def merge_result_lists(
    *result_lists: List[Result],
    deduplicate: bool = True,
) -> List[Result]:
    """Merge multiple result lists into one, optionally deduplicating.

    Args:
        *result_lists: Variable number of result lists
        deduplicate: Whether to deduplicate the merged results

    Returns:
        Merged (and optionally deduplicated) list of results
    """
    merged: List[Result] = []
    for results in result_lists:
        merged.extend(results)

    if deduplicate:
        return deduplicate_results(merged)

    return merged

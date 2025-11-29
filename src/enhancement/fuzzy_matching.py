"""Fuzzy matching utilities for TR4C3R.

Provides fuzzy string matching for usernames, names, and other identifiers
using rapidfuzz for high-performance similarity calculations.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from rapidfuzz import fuzz, process, distance

logger = logging.getLogger(__name__)


class FuzzyMatcher:
    """Fuzzy string matching for OSINT operations."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize fuzzy matcher.

        Args:
            config: Optional configuration dictionary with:
                - similarity_threshold: Minimum similarity score (0-100, default: 80)
                - algorithm: Matching algorithm (default: "token_sort_ratio")
                - case_sensitive: Whether matching is case-sensitive (default: False)
        """
        self.config = config or {}
        self.similarity_threshold = self.config.get("similarity_threshold", 80)
        self.algorithm = self.config.get("algorithm", "token_sort_ratio")
        self.case_sensitive = self.config.get("case_sensitive", False)

        # Map algorithm names to functions
        self.algorithms = {
            "ratio": fuzz.ratio,
            "partial_ratio": fuzz.partial_ratio,
            "token_sort_ratio": fuzz.token_sort_ratio,
            "token_set_ratio": fuzz.token_set_ratio,
            "quick_ratio": fuzz.QRatio,
            "weighted_ratio": fuzz.WRatio,
        }

        logger.info(
            f"FuzzyMatcher initialized (threshold: {self.similarity_threshold}, algorithm: {self.algorithm})"
        )

    def match_single(
        self, query: str, target: str, algorithm: Optional[str] = None
    ) -> Dict[str, Any]:
        """Match a single query against a single target.

        Args:
            query: Query string to match
            target: Target string to match against
            algorithm: Optional algorithm override

        Returns:
            Dictionary with match results:
                - score: Similarity score (0-100)
                - is_match: Whether score meets threshold
                - algorithm: Algorithm used
        """
        # Normalize case if not case-sensitive
        if not self.case_sensitive:
            query = query.lower()
            target = target.lower()

        # Get algorithm function
        algo_name = algorithm or self.algorithm
        algo_func = self.algorithms.get(algo_name, fuzz.token_sort_ratio)

        # Calculate similarity
        score = algo_func(query, target)
        is_match = score >= self.similarity_threshold

        return {
            "query": query,
            "target": target,
            "score": score,
            "is_match": is_match,
            "algorithm": algo_name,
        }

    def match_multiple(
        self,
        query: str,
        targets: List[str],
        limit: Optional[int] = None,
        score_cutoff: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Match a query against multiple targets.

        Args:
            query: Query string to match
            targets: List of target strings
            limit: Maximum number of results to return
            score_cutoff: Minimum score to include (default: threshold)

        Returns:
            List of match results, sorted by score (highest first)
        """
        if not self.case_sensitive:
            query = query.lower()
            targets = [t.lower() for t in targets]

        # Get algorithm function
        algo_func = self.algorithms.get(self.algorithm, fuzz.token_sort_ratio)

        # Use process.extract for efficient matching
        cutoff = score_cutoff or self.similarity_threshold
        limit = limit or len(targets)

        matches = process.extract(
            query, targets, scorer=algo_func, limit=limit, score_cutoff=cutoff
        )

        results = [
            {
                "query": query,
                "target": match[0],
                "score": match[1],
                "is_match": match[1] >= self.similarity_threshold,
                "index": match[2] if len(match) > 2 else None,
            }
            for match in matches
        ]

        return results

    def find_best_match(self, query: str, targets: List[str]) -> Optional[Dict[str, Any]]:
        """Find the best match for a query.

        Args:
            query: Query string to match
            targets: List of target strings

        Returns:
            Best match result or None if no match meets threshold
        """
        matches = self.match_multiple(query, targets, limit=1)
        return matches[0] if matches else None

    def match_usernames(
        self, username: str, candidates: List[str], limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Match username against candidate usernames.

        Uses token_sort_ratio which is good for usernames with variations.

        Args:
            username: Username to match
            candidates: List of candidate usernames
            limit: Maximum number of results

        Returns:
            List of matches sorted by score
        """
        # Use token_sort_ratio for usernames (handles different orderings)
        return self.match_multiple(username, candidates, limit=limit)

    def match_names(
        self, name: str, candidates: List[str], limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Match person name against candidate names.

        Uses token_set_ratio which handles name variations well.

        Args:
            name: Name to match
            candidates: List of candidate names
            limit: Maximum number of results

        Returns:
            List of matches sorted by score
        """
        # Temporarily switch to token_set_ratio for names
        original_algo = self.algorithm
        self.algorithm = "token_set_ratio"

        results = self.match_multiple(name, candidates, limit=limit)

        # Restore original algorithm
        self.algorithm = original_algo

        return results

    def calculate_similarity(self, str1: str, str2: str, algorithm: Optional[str] = None) -> float:
        """Calculate similarity score between two strings.

        Args:
            str1: First string
            str2: Second string
            algorithm: Optional algorithm override

        Returns:
            Similarity score (0-100)
        """
        if not self.case_sensitive:
            str1 = str1.lower()
            str2 = str2.lower()

        algo_name = algorithm or self.algorithm
        algo_func = self.algorithms.get(algo_name, fuzz.token_sort_ratio)

        return algo_func(str1, str2)

    def calculate_distance(self, str1: str, str2: str, metric: str = "levenshtein") -> int:
        """Calculate edit distance between two strings.

        Args:
            str1: First string
            str2: Second string
            metric: Distance metric ("levenshtein", "hamming", "jaro", "jaro_winkler")

        Returns:
            Edit distance (lower is more similar)
        """
        if not self.case_sensitive:
            str1 = str1.lower()
            str2 = str2.lower()

        metrics = {
            "levenshtein": distance.Levenshtein.distance,
            "hamming": distance.Hamming.distance,
            "jaro": distance.Jaro.distance,
            "jaro_winkler": distance.JaroWinkler.distance,
        }

        metric_func = metrics.get(metric, distance.Levenshtein.distance)

        try:
            return metric_func(str1, str2)
        except Exception as e:
            logger.error(f"Error calculating {metric} distance: {e}")
            return float("inf")

    def deduplicate_strings(
        self, strings: List[str], threshold: Optional[float] = None
    ) -> List[str]:
        """Remove duplicate and near-duplicate strings.

        Args:
            strings: List of strings to deduplicate
            threshold: Similarity threshold for duplicates (default: 90)

        Returns:
            Deduplicated list of strings
        """
        if not strings:
            return []

        threshold = threshold or 90
        unique_strings = []

        for string in strings:
            # Check if similar to any existing unique string
            is_duplicate = False

            for unique in unique_strings:
                score = self.calculate_similarity(string, unique)
                if score >= threshold:
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique_strings.append(string)

        logger.info(f"Deduplicated {len(strings)} strings to {len(unique_strings)} unique")
        return unique_strings

    def group_similar_strings(
        self, strings: List[str], threshold: Optional[float] = None
    ) -> List[List[str]]:
        """Group similar strings together.

        Args:
            strings: List of strings to group
            threshold: Similarity threshold for grouping (default: 85)

        Returns:
            List of groups (each group is a list of similar strings)
        """
        if not strings:
            return []

        threshold = threshold or 85
        groups = []
        assigned = set()

        for i, string1 in enumerate(strings):
            if i in assigned:
                continue

            # Start new group
            group = [string1]
            assigned.add(i)

            # Find similar strings
            for j, string2 in enumerate(strings[i + 1 :], start=i + 1):
                if j in assigned:
                    continue

                score = self.calculate_similarity(string1, string2)
                if score >= threshold:
                    group.append(string2)
                    assigned.add(j)

            groups.append(group)

        logger.info(f"Grouped {len(strings)} strings into {len(groups)} groups")
        return groups

    def extract_best_matches(
        self,
        query: str,
        choices: Dict[str, Any],
        limit: int = 5,
        score_cutoff: Optional[float] = None,
    ) -> List[Tuple[str, Any, float]]:
        """Extract best matches from a dictionary of choices.

        Args:
            query: Query string to match
            choices: Dictionary mapping strings to values
            limit: Maximum number of results
            score_cutoff: Minimum score threshold

        Returns:
            List of tuples (matched_key, value, score)
        """
        if not self.case_sensitive:
            query = query.lower()

        algo_func = self.algorithms.get(self.algorithm, fuzz.token_sort_ratio)
        cutoff = score_cutoff or self.similarity_threshold

        # Extract keys and match
        keys = list(choices.keys())
        matches = process.extract(query, keys, scorer=algo_func, limit=limit, score_cutoff=cutoff)

        # Return with values
        results = [(match[0], choices[match[0]], match[1]) for match in matches]

        return results

    def get_similarity_matrix(self, strings: List[str]) -> List[List[float]]:
        """Generate similarity matrix for a list of strings.

        Args:
            strings: List of strings

        Returns:
            2D matrix of similarity scores
        """
        n = len(strings)
        matrix = [[0.0] * n for _ in range(n)]

        for i in range(n):
            for j in range(n):
                if i == j:
                    matrix[i][j] = 100.0
                elif i < j:
                    score = self.calculate_similarity(strings[i], strings[j])
                    matrix[i][j] = score
                    matrix[j][i] = score  # Symmetric

        return matrix

    def compare_algorithms(self, str1: str, str2: str) -> Dict[str, float]:
        """Compare all available algorithms for two strings.

        Args:
            str1: First string
            str2: Second string

        Returns:
            Dictionary mapping algorithm names to scores
        """
        if not self.case_sensitive:
            str1 = str1.lower()
            str2 = str2.lower()

        results = {}
        for algo_name, algo_func in self.algorithms.items():
            try:
                score = algo_func(str1, str2)
                results[algo_name] = score
            except Exception as e:
                logger.debug(f"Error with algorithm {algo_name}: {e}")
                results[algo_name] = 0.0

        return results

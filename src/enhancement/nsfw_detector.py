"""NSFW content detection for TR4C3R.

Detects and filters adult/inappropriate content from search results.
Uses keyword-based detection, domain blacklisting, and URL pattern analysis.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

from src.core.data_models import Result

logger = logging.getLogger(__name__)


class NSFWDetector:
    """Detects NSFW content in search results using multiple detection methods."""

    # Known adult content domains
    NSFW_DOMAINS = {
        "pornhub.com",
        "xvideos.com",
        "xnxx.com",
        "redtube.com",
        "youporn.com",
        "tube8.com",
        "spankbang.com",
        "xhamster.com",
        "porn.com",
        "sex.com",
        "xxx.com",
        "adult.com",
        "onlyfans.com",
        "fansly.com",
        "manyvids.com",
        # Add subdomains
        "www.pornhub.com",
        "www.xvideos.com",
        "www.xnxx.com",
    }

    # NSFW keywords (categories)
    NSFW_KEYWORDS = {
        # Explicit terms
        "porn",
        "xxx",
        "sex",
        "nude",
        "naked",
        "nsfw",
        "adult",
        "erotic",
        "hentai",
        "camgirl",
        "webcam",
        "strip",
        "escort",
        "hookup",
        "fetish",
        "bdsm",
        # Platform-specific
        "onlyfans",
        "fansly",
        "patreon",
        "manyvids",
        # Slang terms
        "thot",
        "lewd",
        "r34",
        "rule34",
        "ahegao",
    }

    # High-confidence NSFW URL patterns
    NSFW_URL_PATTERNS = [
        r"/porn/",
        r"/xxx/",
        r"/sex/",
        r"/nude/",
        r"/adult/",
        r"/nsfw/",
        r"/erotic/",
        r"/18\+/",
        r"/mature/",
        r"porn\.",
        r"xxx\.",
        r"sex\.",
        r"adult\.",
    ]

    # Content indicators in titles/descriptions
    NSFW_INDICATORS = {
        "18+",
        "18plus",
        "adults only",
        "mature content",
        "explicit content",
        "nsfw content",
        "age restricted",
        "parental advisory",
        "not safe for work",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the NSFW detector.

        Args:
            config: Optional configuration dictionary with:
                - sensitivity: "low", "medium", "high" (default: "medium")
                - custom_domains: Additional domains to block
                - custom_keywords: Additional keywords to detect
                - whitelist_domains: Domains to never flag
        """
        self.config = config or {}
        self.sensitivity = self.config.get("sensitivity", "medium")

        # Build custom domain list
        self.blocked_domains = self.NSFW_DOMAINS.copy()
        if "custom_domains" in self.config:
            self.blocked_domains.update(self.config["custom_domains"])

        # Build custom keyword list
        self.nsfw_keywords = self.NSFW_KEYWORDS.copy()
        if "custom_keywords" in self.config:
            self.nsfw_keywords.update(k.lower() for k in self.config["custom_keywords"])

        # Whitelist (trusted domains that should never be flagged)
        self.whitelist_domains = set(self.config.get("whitelist_domains", []))

        logger.info(f"NSFWDetector initialized (sensitivity: {self.sensitivity})")

    async def scan_results(self, results: List[Result]) -> List[Result]:
        """Scan results for NSFW content and flag them.

        Args:
            results: List of search results to scan

        Returns:
            Results with NSFW flags added to metadata
        """
        logger.info(f"Scanning {len(results)} results for NSFW content")

        scanned_results = []
        nsfw_count = 0

        for result in results:
            nsfw_check = await self.analyze_result(result)

            # Add NSFW metadata
            if result.metadata is None:
                result.metadata = {}

            result.metadata["nsfw_check"] = nsfw_check
            result.metadata["is_nsfw"] = nsfw_check["is_nsfw"]
            result.metadata["nsfw_confidence"] = nsfw_check["confidence"]
            result.metadata["nsfw_reasons"] = nsfw_check["reasons"]

            if nsfw_check["is_nsfw"]:
                nsfw_count += 1
                logger.debug(
                    f"NSFW detected: {result.url} (confidence: {nsfw_check['confidence']:.2f})"
                )

            scanned_results.append(result)

        logger.info(f"NSFW scan complete: {nsfw_count}/{len(results)} flagged as NSFW")
        return scanned_results

    async def analyze_result(self, result: Result) -> Dict[str, Any]:
        """Analyze a single result for NSFW content.

        Args:
            result: Result to analyze

        Returns:
            Dictionary with:
                - is_nsfw: bool
                - confidence: float (0.0-1.0)
                - reasons: List[str]
                - details: Dict with detection breakdown
        """
        reasons = []
        confidence_scores = []
        details = {
            "domain_match": False,
            "url_pattern_match": False,
            "keyword_match": False,
            "indicator_match": False,
        }

        # Check domain
        if result.url:
            domain_check = self._check_domain(result.url)
            if domain_check["is_nsfw"]:
                reasons.append(f"NSFW domain: {domain_check['domain']}")
                confidence_scores.append(1.0)  # High confidence
                details["domain_match"] = True

        # Check URL patterns
        if result.url:
            url_pattern_check = self._check_url_patterns(result.url)
            if url_pattern_check["matches"]:
                reasons.append(f"NSFW URL pattern: {', '.join(url_pattern_check['matches'])}")
                confidence_scores.append(0.8)
                details["url_pattern_match"] = True

        # Check title and description for keywords
        text_to_check = []
        if result.metadata and "title" in result.metadata:
            text_to_check.append(result.metadata["title"])
        if result.metadata and "description" in result.metadata:
            text_to_check.append(result.metadata["description"])

        if text_to_check:
            keyword_check = self._check_keywords(" ".join(text_to_check))
            if keyword_check["matches"]:
                reasons.append(f"NSFW keywords: {', '.join(keyword_check['matches'][:3])}")
                confidence_scores.append(0.6)
                details["keyword_match"] = True

        # Check for explicit content indicators
        if text_to_check:
            indicator_check = self._check_indicators(" ".join(text_to_check))
            if indicator_check["matches"]:
                reasons.append(f"Content indicators: {', '.join(indicator_check['matches'])}")
                confidence_scores.append(0.7)
                details["indicator_match"] = True

        # Calculate overall confidence
        if confidence_scores:
            confidence = max(confidence_scores)  # Use highest confidence
        else:
            confidence = 0.0

        # Apply sensitivity threshold
        threshold = self._get_confidence_threshold()
        is_nsfw = confidence >= threshold

        return {
            "is_nsfw": is_nsfw,
            "confidence": confidence,
            "reasons": reasons,
            "details": details,
        }

    async def is_nsfw(self, url: str, title: str = "", description: str = "") -> bool:
        """Check if a URL/content contains NSFW material.

        Args:
            url: The URL to check
            title: Optional title text
            description: Optional description text

        Returns:
            True if NSFW, False otherwise
        """
        # Create temporary result for analysis
        metadata = {}
        if title:
            metadata["title"] = title
        if description:
            metadata["description"] = description

        result = Result(source="check", identifier="temp_check", url=url, metadata=metadata)

        analysis = await self.analyze_result(result)
        return analysis["is_nsfw"]

    def filter_nsfw_results(self, results: List[Result], remove: bool = False) -> List[Result]:
        """Filter NSFW results from a list.

        Args:
            results: List of results to filter
            remove: If True, remove NSFW results; if False, just mark them

        Returns:
            Filtered list of results
        """
        if remove:
            filtered = [r for r in results if not r.metadata.get("is_nsfw", False)]
            logger.info(f"Filtered {len(results) - len(filtered)} NSFW results")
            return filtered
        else:
            return results

    def _check_domain(self, url: str) -> Dict[str, Any]:
        """Check if URL domain is in NSFW domain list.

        Args:
            url: URL to check

        Returns:
            Dictionary with is_nsfw and domain
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove www. prefix for comparison
            domain_clean = domain.replace("www.", "")

            # Check whitelist first
            if domain in self.whitelist_domains or domain_clean in self.whitelist_domains:
                return {"is_nsfw": False, "domain": domain}

            # Check against blocked domains
            is_blocked = (
                domain in self.blocked_domains
                or domain_clean in self.blocked_domains
                or any(domain.endswith(f".{blocked}") for blocked in self.blocked_domains)
            )

            return {"is_nsfw": is_blocked, "domain": domain}
        except Exception as e:
            logger.debug(f"Error parsing URL {url}: {e}")
            return {"is_nsfw": False, "domain": ""}

    def _check_url_patterns(self, url: str) -> Dict[str, Any]:
        """Check URL for NSFW patterns.

        Args:
            url: URL to check

        Returns:
            Dictionary with matches
        """
        matches = []
        url_lower = url.lower()

        for pattern in self.NSFW_URL_PATTERNS:
            if re.search(pattern, url_lower):
                matches.append(pattern)

        return {"matches": matches}

    def _check_keywords(self, text: str) -> Dict[str, Any]:
        """Check text for NSFW keywords.

        Args:
            text: Text to check

        Returns:
            Dictionary with matches
        """
        text_lower = text.lower()
        matches = []

        for keyword in self.nsfw_keywords:
            # Use word boundaries to avoid false positives
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, text_lower):
                matches.append(keyword)

        return {"matches": matches}

    def _check_indicators(self, text: str) -> Dict[str, Any]:
        """Check text for NSFW content indicators.

        Args:
            text: Text to check

        Returns:
            Dictionary with matches
        """
        text_lower = text.lower()
        matches = []

        for indicator in self.NSFW_INDICATORS:
            if indicator in text_lower:
                matches.append(indicator)

        return {"matches": matches}

    def _get_confidence_threshold(self) -> float:
        """Get confidence threshold based on sensitivity setting.

        Returns:
            Confidence threshold (0.0-1.0)
        """
        thresholds = {
            "low": 0.8,  # Only flag high-confidence NSFW
            "medium": 0.6,  # Flag moderate and high confidence
            "high": 0.4,  # Flag anything suspicious
        }

        return thresholds.get(self.sensitivity, 0.6)

    def get_statistics(self, results: List[Result]) -> Dict[str, Any]:
        """Get NSFW detection statistics for results.

        Args:
            results: List of results to analyze

        Returns:
            Dictionary with statistics
        """
        total = len(results)
        nsfw_count = sum(1 for r in results if r.metadata and r.metadata.get("is_nsfw", False))

        # Confidence distribution
        confidences = [
            r.metadata.get("nsfw_confidence", 0.0)
            for r in results
            if r.metadata and r.metadata.get("is_nsfw", False)
        ]

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        # Reason breakdown
        all_reasons = []
        for r in results:
            if r.metadata and r.metadata.get("is_nsfw", False):
                all_reasons.extend(r.metadata.get("nsfw_reasons", []))

        return {
            "total_results": total,
            "nsfw_count": nsfw_count,
            "nsfw_percentage": (nsfw_count / total * 100) if total > 0 else 0,
            "clean_count": total - nsfw_count,
            "average_confidence": avg_confidence,
            "total_reasons": len(all_reasons),
            "sensitivity": self.sensitivity,
        }

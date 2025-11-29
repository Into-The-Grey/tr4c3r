"""Tests for enhancement modules (NSFW detection, ethics, fuzzy matching).

Tests cover:
- NSFW content detection with multiple methods
- Ethical guidelines and usage acknowledgment
- Fuzzy string matching algorithms
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
from pathlib import Path
import json

from src.enhancement.nsfw_detector import NSFWDetector
from src.enhancement.ethics import (
    EthicsChecker,
    ETHICAL_GUIDELINES,
    DETAILED_ETHICAL_PRINCIPLES,
    SafetyLevel,
    OVERRIDE_CODE,
)
from src.enhancement.fuzzy_matching import FuzzyMatcher
from src.core.data_models import Result


class TestNSFWDetector:
    """Test NSFW content detection."""

    @pytest.fixture
    def nsfw_detector(self):
        """Create NSFW detector instance."""
        return NSFWDetector()

    @pytest.fixture
    def nsfw_detector_high_sensitivity(self):
        """Create NSFW detector with high sensitivity."""
        return NSFWDetector(config={"sensitivity": "high"})

    def test_initialization(self, nsfw_detector):
        """Test NSFW detector initialization."""
        assert nsfw_detector is not None
        assert nsfw_detector.sensitivity == "medium"
        assert len(nsfw_detector.blocked_domains) > 0
        assert len(nsfw_detector.nsfw_keywords) > 0

    def test_initialization_with_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            "sensitivity": "high",
            "custom_domains": ["custom-adult.com"],
            "custom_keywords": ["explicit"],
            "whitelist_domains": ["trusted.com"],
        }
        detector = NSFWDetector(config=config)

        assert detector.sensitivity == "high"
        assert "custom-adult.com" in detector.blocked_domains
        assert "explicit" in detector.nsfw_keywords
        assert "trusted.com" in detector.whitelist_domains

    @pytest.mark.asyncio
    async def test_check_domain_nsfw(self, nsfw_detector):
        """Test NSFW domain detection."""
        result = nsfw_detector._check_domain("https://pornhub.com/video")
        assert result["is_nsfw"] is True

        result = nsfw_detector._check_domain("https://www.xvideos.com/test")
        assert result["is_nsfw"] is True

    @pytest.mark.asyncio
    async def test_check_domain_safe(self, nsfw_detector):
        """Test safe domain detection."""
        result = nsfw_detector._check_domain("https://google.com")
        assert result["is_nsfw"] is False

        result = nsfw_detector._check_domain("https://github.com")
        assert result["is_nsfw"] is False

    @pytest.mark.asyncio
    async def test_check_domain_whitelist(self):
        """Test whitelisted domains are never flagged."""
        detector = NSFWDetector(config={"whitelist_domains": ["example.com"]})
        result = detector._check_domain("https://example.com")
        assert result["is_nsfw"] is False

    def test_check_url_patterns(self, nsfw_detector):
        """Test URL pattern detection."""
        result = nsfw_detector._check_url_patterns("https://example.com/porn/video.html")
        assert len(result["matches"]) > 0

        result = nsfw_detector._check_url_patterns("https://example.com/xxx/gallery")
        assert len(result["matches"]) > 0

        result = nsfw_detector._check_url_patterns("https://example.com/normal/page")
        assert len(result["matches"]) == 0

    def test_check_keywords(self, nsfw_detector):
        """Test NSFW keyword detection."""
        result = nsfw_detector._check_keywords("This is a porn video title")
        assert len(result["matches"]) > 0
        assert "porn" in result["matches"]

        result = nsfw_detector._check_keywords("Normal content here")
        assert len(result["matches"]) == 0

    def test_check_indicators(self, nsfw_detector):
        """Test NSFW indicator detection."""
        result = nsfw_detector._check_indicators("18+ adult content warning")
        assert len(result["matches"]) > 0

        result = nsfw_detector._check_indicators("This is NSFW content")
        assert len(result["matches"]) > 0

        result = nsfw_detector._check_indicators("Safe content")
        assert len(result["matches"]) == 0

    @pytest.mark.asyncio
    async def test_analyze_result_nsfw_domain(self, nsfw_detector):
        """Test result analysis with NSFW domain."""
        result = Result(
            source="test",
            identifier="test_video_123",
            url="https://pornhub.com/video/123",
            metadata={"title": "Test Video"},
        )

        analysis = await nsfw_detector.analyze_result(result)

        assert analysis["is_nsfw"] is True
        assert analysis["confidence"] >= 0.6
        assert len(analysis["reasons"]) > 0
        assert analysis["details"]["domain_match"] is True

    @pytest.mark.asyncio
    async def test_analyze_result_nsfw_keywords(self, nsfw_detector):
        """Test result analysis with NSFW keywords."""
        result = Result(
            source="test",
            identifier="test_page",
            url="https://example.com/page",
            metadata={"title": "Porn videos and xxx content"},
        )

        analysis = await nsfw_detector.analyze_result(result)

        assert analysis["is_nsfw"] is True
        assert analysis["details"]["keyword_match"] is True

    @pytest.mark.asyncio
    async def test_analyze_result_safe_content(self, nsfw_detector):
        """Test result analysis with safe content."""
        result = Result(
            source="test",
            identifier="wiki_article",
            url="https://wikipedia.org/wiki/Article",
            metadata={"title": "Educational Article"},
        )

        analysis = await nsfw_detector.analyze_result(result)

        assert analysis["is_nsfw"] is False
        assert analysis["confidence"] == 0.0

    @pytest.mark.asyncio
    async def test_scan_results(self, nsfw_detector):
        """Test scanning multiple results."""
        results = [
            Result(
                source="test",
                identifier="video_1",
                url="https://pornhub.com/video",
                metadata={"title": "NSFW"},
            ),
            Result(
                source="test",
                identifier="google_1",
                url="https://google.com",
                metadata={"title": "Safe"},
            ),
            Result(
                source="test",
                identifier="example_1",
                url="https://example.com/porn",
                metadata={"title": "Test"},
            ),
        ]

        scanned = await nsfw_detector.scan_results(results)

        assert len(scanned) == 3
        assert all(r.metadata.get("nsfw_check") is not None for r in scanned)

        # Count NSFW results
        nsfw_count = sum(1 for r in scanned if r.metadata.get("is_nsfw"))
        assert nsfw_count >= 1

    @pytest.mark.asyncio
    async def test_is_nsfw_method(self, nsfw_detector):
        """Test is_nsfw convenience method."""
        is_nsfw = await nsfw_detector.is_nsfw("https://pornhub.com/video")
        assert is_nsfw is True

        is_nsfw = await nsfw_detector.is_nsfw("https://wikipedia.org")
        assert is_nsfw is False

    @pytest.mark.asyncio
    async def test_is_nsfw_with_title_description(self, nsfw_detector):
        """Test is_nsfw with title and description."""
        is_nsfw = await nsfw_detector.is_nsfw(
            "https://example.com", title="XXX Videos", description="Adult content"
        )
        assert is_nsfw is True

    def test_filter_nsfw_results_mark_only(self, nsfw_detector):
        """Test filtering NSFW results (mark only)."""
        results = [
            Result(
                source="test",
                identifier="test1",
                url="https://test1.com",
                metadata={"title": "Safe", "is_nsfw": False},
            ),
            Result(
                source="test",
                identifier="test2",
                url="https://test2.com",
                metadata={"title": "NSFW", "is_nsfw": True},
            ),
        ]

        filtered = nsfw_detector.filter_nsfw_results(results, remove=False)
        assert len(filtered) == 2

    def test_filter_nsfw_results_remove(self, nsfw_detector):
        """Test filtering NSFW results (remove)."""
        results = [
            Result(
                source="test",
                identifier="test1",
                url="https://test1.com",
                metadata={"title": "Safe", "is_nsfw": False},
            ),
            Result(
                source="test",
                identifier="test2",
                url="https://test2.com",
                metadata={"title": "NSFW", "is_nsfw": True},
            ),
        ]

        filtered = nsfw_detector.filter_nsfw_results(results, remove=True)
        assert len(filtered) == 1
        assert filtered[0].url == "https://test1.com"

    def test_get_confidence_threshold(self, nsfw_detector):
        """Test confidence threshold calculation."""
        nsfw_detector.sensitivity = "low"
        assert nsfw_detector._get_confidence_threshold() == 0.8

        nsfw_detector.sensitivity = "medium"
        assert nsfw_detector._get_confidence_threshold() == 0.6

        nsfw_detector.sensitivity = "high"
        assert nsfw_detector._get_confidence_threshold() == 0.4

    def test_get_statistics(self, nsfw_detector):
        """Test NSFW statistics generation."""
        results = [
            Result(
                source="test",
                identifier="test1",
                url="https://test1.com",
                metadata={"title": "Safe", "is_nsfw": False, "nsfw_confidence": 0.0},
            ),
            Result(
                source="test",
                identifier="test2",
                url="https://test2.com",
                metadata={
                    "title": "NSFW",
                    "is_nsfw": True,
                    "nsfw_confidence": 0.9,
                    "nsfw_reasons": ["domain"],
                },
            ),
            Result(
                source="test",
                identifier="test3",
                url="https://test3.com",
                metadata={
                    "title": "NSFW2",
                    "is_nsfw": True,
                    "nsfw_confidence": 0.8,
                    "nsfw_reasons": ["keyword"],
                },
            ),
        ]

        stats = nsfw_detector.get_statistics(results)

        assert stats["total_results"] == 3
        assert stats["nsfw_count"] == 2
        assert stats["clean_count"] == 1
        assert stats["nsfw_percentage"] > 0


class TestEthicsChecker:
    """Test ethical guidelines and usage acknowledgment."""

    @pytest.fixture
    def ethics_checker(self):
        """Create ethics checker instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(config={"consent_file": str(consent_file)})
            yield checker

    def test_initialization(self, ethics_checker):
        """Test ethics checker initialization."""
        assert ethics_checker is not None
        assert ethics_checker.require_acknowledgment is True

    def test_get_guidelines(self, ethics_checker):
        """Test getting ethical guidelines."""
        guidelines = ethics_checker.get_guidelines()
        assert guidelines == ETHICAL_GUIDELINES
        assert "Consent & Privacy" in guidelines
        assert "Prohibited Uses" in guidelines

    def test_get_detailed_principles(self, ethics_checker):
        """Test getting detailed ethical principles."""
        principles = ethics_checker.get_detailed_principles()
        assert principles == DETAILED_ETHICAL_PRINCIPLES
        assert len(principles) == 5
        assert all("principle" in p for p in principles)

    def test_check_acknowledgment_not_acknowledged(self, ethics_checker):
        """Test checking acknowledgment when not acknowledged."""
        result = ethics_checker.check_acknowledgment()
        assert result is False

    def test_record_acknowledgment(self, ethics_checker):
        """Test recording user acknowledgment."""
        result = ethics_checker.record_acknowledgment(
            user_id="test_user", purpose="security research"
        )

        assert result["success"] is True
        assert "timestamp" in result

    def test_check_acknowledgment_after_recording(self, ethics_checker):
        """Test checking acknowledgment after recording."""
        ethics_checker.record_acknowledgment(user_id="test_user")
        result = ethics_checker.check_acknowledgment()
        assert result is True

    def test_validate_purpose_legitimate(self, ethics_checker):
        """Test validating legitimate purpose."""
        result = ethics_checker.validate_purpose("security research and threat intelligence")
        assert result["is_valid"] is True
        assert len(result["matches"]) > 0

    def test_validate_purpose_prohibited(self, ethics_checker):
        """Test validating prohibited purpose."""
        result = ethics_checker.validate_purpose("stalking and harassment")
        assert result["is_valid"] is False
        assert len(result["matches"]) > 0

    def test_validate_purpose_unclear(self, ethics_checker):
        """Test validating unclear purpose."""
        result = ethics_checker.validate_purpose("just curious")
        assert result["is_valid"] is None
        assert result["reason"] == "unclear_purpose"

    def test_check_compliance_legitimate(self, ethics_checker):
        """Test compliance check for legitimate use."""
        result = ethics_checker.check_compliance(
            data_type="public", target="username123", purpose="security research"
        )

        assert result["is_compliant"] is True
        assert len(result["recommendations"]) > 0

    def test_check_compliance_prohibited(self, ethics_checker):
        """Test compliance check for prohibited use."""
        result = ethics_checker.check_compliance(
            data_type="personal", target="user@example.com", purpose="stalking investigation"
        )

        assert result["is_compliant"] is False
        assert len(result["issues"]) > 0

    def test_check_compliance_sensitive_data(self, ethics_checker):
        """Test compliance check with sensitive data."""
        result = ethics_checker.check_compliance(
            data_type="sensitive", target="test_target", purpose="investigation"
        )

        assert len(result["warnings"]) > 0

    def test_get_usage_statistics_no_consent(self, ethics_checker):
        """Test getting usage statistics without consent."""
        stats = ethics_checker.get_usage_statistics()
        assert stats["acknowledged"] is False

    def test_get_usage_statistics_with_consent(self, ethics_checker):
        """Test getting usage statistics with consent."""
        ethics_checker.record_acknowledgment(user_id="test_user", purpose="research")
        stats = ethics_checker.get_usage_statistics()

        assert stats["acknowledged"] is True
        assert stats["user_id"] == "test_user"
        assert stats["purpose"] == "research"

    def test_prompt_user_acknowledgment(self, ethics_checker):
        """Test generating user acknowledgment prompt."""
        prompt = ethics_checker.prompt_user_acknowledgment()
        assert ETHICAL_GUIDELINES in prompt
        assert "yes/no" in prompt

    def test_generate_ethical_report(self, ethics_checker):
        """Test generating ethical compliance report."""
        operations = [
            {"data_type": "public", "target": "user1", "purpose": "security research"},
            {"data_type": "personal", "target": "user2", "purpose": "stalking"},
            {"data_type": "public", "target": "user3", "purpose": "investigation"},
        ]

        report = ethics_checker.generate_ethical_report(operations)

        assert report["total_operations"] == 3
        assert report["compliant_operations"] >= 1
        assert "compliance_rate" in report
        assert "timestamp" in report

    def test_safety_level_none(self):
        """Test NONE safety level bypasses all checks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "none"}
            )

            # Should bypass all checks
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="stalking"
            )

            assert result["is_compliant"] is True
            assert len(result["issues"]) == 0
            assert checker.check_acknowledgment() is True

    def test_safety_level_low(self):
        """Test LOW safety level only checks prohibited purposes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "low"}
            )

            # Prohibited purpose should fail
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="stalking someone"
            )
            assert result["is_compliant"] is False
            assert len(result["issues"]) > 0

            # Unclear purpose should pass
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="testing"
            )
            assert result["is_compliant"] is True

    def test_safety_level_medium(self):
        """Test MEDIUM safety level (default)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "medium"}
            )

            # Should have warnings for unclear purpose
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="testing"
            )
            assert result["is_compliant"] is True
            assert len(result["warnings"]) > 0

    def test_safety_level_high(self):
        """Test HIGH safety level requires clear purpose."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "high"}
            )

            # Unclear purpose should fail
            result = checker.check_compliance(
                data_type="email", target="user@example.com", purpose="testing"
            )
            assert result["is_compliant"] is False
            assert len(result["issues"]) > 0

            # Clear legitimate purpose should pass
            checker.record_acknowledgment(user_id="test")
            result = checker.check_compliance(
                data_type="public", target="username", purpose="security research"
            )
            assert result["is_compliant"] is True

    def test_safety_level_total(self):
        """Test TOTAL safety level with maximum enforcement."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "total"}
            )

            # Should fail even with decent purpose (too short)
            result = checker.check_compliance(
                data_type="email", target="user@example.com", purpose="testing"
            )
            assert result["is_compliant"] is False
            assert len(result["issues"]) >= 3  # Multiple issues in TOTAL mode

            # Long, legitimate purpose should pass
            checker.record_acknowledgment(user_id="test")
            result = checker.check_compliance(
                data_type="public",
                target="johndoe",  # No digits to avoid phone number check
                purpose="comprehensive security research and threat intelligence investigation",
            )
            assert result["is_compliant"] is True

    def test_override_code_activation(self):
        """Test override code activation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "total"}
            )

            # Initially not active
            assert checker.is_override_active() is False

            # Wrong code should fail
            result = checker.activate_override("1234")
            assert result is False
            assert checker.is_override_active() is False

            # Correct code should activate
            result = checker.activate_override("3825")
            assert result is True
            assert checker.is_override_active() is True

    def test_override_code_bypasses_checks(self):
        """Test override code bypasses all ethics checks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "total"}
            )

            # Should fail without override
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="bad"
            )
            assert result["is_compliant"] is False

            # Activate override
            checker.activate_override("3825")

            # Should pass with override
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="bad"
            )
            assert result["is_compliant"] is True
            assert len(result["issues"]) == 0
            assert checker.check_acknowledgment() is True

    def test_override_code_deactivation(self):
        """Test override code deactivation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(
                config={"consent_file": str(consent_file), "safety_level": "total"}
            )

            # Activate override
            checker.activate_override("3825")
            assert checker.is_override_active() is True

            # Deactivate
            checker.deactivate_override()
            assert checker.is_override_active() is False

            # Checks should be enforced again
            result = checker.check_compliance(
                data_type="personal", target="user@example.com", purpose="test"
            )
            assert result["is_compliant"] is False

    def test_legacy_strict_mode_maps_to_high(self):
        """Test legacy strict_mode config maps to HIGH safety level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            consent_file = Path(tmpdir) / ".tr4c3r_consent.json"
            checker = EthicsChecker(config={"consent_file": str(consent_file), "strict_mode": True})

            from src.enhancement.ethics import SafetyLevel

            assert checker.safety_level == SafetyLevel.HIGH
            assert checker.strict_mode is True


class TestFuzzyMatcher:
    """Test fuzzy string matching."""

    @pytest.fixture
    def fuzzy_matcher(self):
        """Create fuzzy matcher instance."""
        return FuzzyMatcher()

    def test_initialization(self, fuzzy_matcher):
        """Test fuzzy matcher initialization."""
        assert fuzzy_matcher is not None
        assert fuzzy_matcher.similarity_threshold == 80
        assert fuzzy_matcher.algorithm == "token_sort_ratio"

    def test_initialization_with_config(self):
        """Test initialization with custom config."""
        matcher = FuzzyMatcher(
            config={"similarity_threshold": 90, "algorithm": "ratio", "case_sensitive": True}
        )

        assert matcher.similarity_threshold == 90
        assert matcher.algorithm == "ratio"
        assert matcher.case_sensitive is True

    def test_match_single_exact(self, fuzzy_matcher):
        """Test single match with exact string."""
        result = fuzzy_matcher.match_single("hello", "hello")
        assert result["score"] == 100
        assert result["is_match"] is True

    def test_match_single_similar(self, fuzzy_matcher):
        """Test single match with similar string."""
        result = fuzzy_matcher.match_single("hello", "helo")
        assert result["score"] > 50
        assert "score" in result

    def test_match_single_different(self, fuzzy_matcher):
        """Test single match with different string."""
        result = fuzzy_matcher.match_single("hello", "goodbye")
        assert result["score"] < 50

    def test_match_multiple(self, fuzzy_matcher):
        """Test matching against multiple targets."""
        targets = ["john_smith", "john_smyth", "jane_smith", "bob_jones"]
        results = fuzzy_matcher.match_multiple("john_smith", targets, limit=3)

        assert len(results) <= 3
        assert results[0]["target"] == "john_smith"  # Exact match first
        assert results[0]["score"] == 100

    def test_find_best_match(self, fuzzy_matcher):
        """Test finding best match."""
        targets = ["john_smith", "john_smyth", "jane_smith"]
        result = fuzzy_matcher.find_best_match("jon_smith", targets)

        assert result is not None
        assert "john" in result["target"]

    def test_find_best_match_no_match(self, fuzzy_matcher):
        """Test finding best match with no good matches."""
        matcher = FuzzyMatcher(config={"similarity_threshold": 95})
        targets = ["completely", "different", "words"]
        result = matcher.find_best_match("xyz", targets)

        assert result is None

    def test_match_usernames(self, fuzzy_matcher):
        """Test username matching."""
        candidates = ["user123", "user_123", "user.123", "user456"]
        results = fuzzy_matcher.match_usernames("user123", candidates, limit=3)

        assert len(results) > 0
        assert results[0]["score"] == 100  # Exact match

    def test_match_names(self, fuzzy_matcher):
        """Test name matching."""
        candidates = ["John Smith", "Smith John", "John R Smith", "Jane Smith"]
        results = fuzzy_matcher.match_names("John Smith", candidates, limit=3)

        assert len(results) > 0
        assert results[0]["score"] >= 90  # High similarity

    def test_calculate_similarity(self, fuzzy_matcher):
        """Test calculating similarity score."""
        score = fuzzy_matcher.calculate_similarity("hello", "hello")
        assert score == 100

        score = fuzzy_matcher.calculate_similarity("hello", "helo")
        assert 70 <= score <= 95

    def test_calculate_distance_levenshtein(self, fuzzy_matcher):
        """Test Levenshtein distance calculation."""
        distance = fuzzy_matcher.calculate_distance("hello", "hello", metric="levenshtein")
        assert distance == 0

        distance = fuzzy_matcher.calculate_distance("hello", "helo", metric="levenshtein")
        assert distance == 1  # One deletion

    def test_deduplicate_strings(self, fuzzy_matcher):
        """Test string deduplication."""
        strings = ["hello", "helo", "hello", "world", "wrld"]
        unique = fuzzy_matcher.deduplicate_strings(strings, threshold=90)

        assert len(unique) < len(strings)
        assert "hello" in unique

    def test_group_similar_strings(self, fuzzy_matcher):
        """Test grouping similar strings."""
        strings = ["john_smith", "john_smyth", "jane_doe", "jane_doe2"]
        groups = fuzzy_matcher.group_similar_strings(strings, threshold=85)

        assert len(groups) >= 2
        assert all(isinstance(g, list) for g in groups)

    def test_extract_best_matches_dict(self, fuzzy_matcher):
        """Test extracting best matches from dictionary."""
        choices = {
            "john_smith": {"id": 1, "name": "John Smith"},
            "jane_doe": {"id": 2, "name": "Jane Doe"},
            "john_smyth": {"id": 3, "name": "John Smyth"},
        }

        results = fuzzy_matcher.extract_best_matches("john smith", choices, limit=2)

        assert len(results) <= 2
        assert all(len(r) == 3 for r in results)  # (key, value, score)

    def test_get_similarity_matrix(self, fuzzy_matcher):
        """Test generating similarity matrix."""
        strings = ["hello", "helo", "world"]
        matrix = fuzzy_matcher.get_similarity_matrix(strings)

        assert len(matrix) == 3
        assert all(len(row) == 3 for row in matrix)
        assert matrix[0][0] == 100.0  # Diagonal is 100
        assert matrix[0][1] == matrix[1][0]  # Symmetric

    def test_compare_algorithms(self, fuzzy_matcher):
        """Test comparing all algorithms."""
        results = fuzzy_matcher.compare_algorithms("hello world", "helo world")

        assert len(results) > 0
        assert all(isinstance(score, (int, float)) for score in results.values())
        assert "ratio" in results
        assert "token_sort_ratio" in results

    def test_case_sensitivity(self):
        """Test case-sensitive vs case-insensitive matching."""
        # Case-insensitive (default)
        matcher = FuzzyMatcher()
        result = matcher.match_single("HELLO", "hello")
        assert result["score"] == 100

        # Case-sensitive
        matcher = FuzzyMatcher(config={"case_sensitive": True})
        result = matcher.match_single("HELLO", "hello")
        assert result["score"] < 100

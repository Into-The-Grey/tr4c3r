"""Tests for the name search module."""

from __future__ import annotations

import pytest

from src.search.name import (
    DisambiguationContext,
    NameComponents,
    NameParser,
    NameSearch,
)


class TestNameParser:
    """Test the NameParser class."""

    @pytest.fixture
    def parser(self) -> NameParser:
        """Create a NameParser instance."""
        return NameParser()

    def test_simple_two_part_name(self, parser: NameParser) -> None:
        """Test parsing a simple two-part name."""
        parsed = parser.parse("John Smith")
        assert parsed.first_name == "John"
        assert parsed.last_name == "Smith"
        assert parsed.middle_name is None
        assert parsed.full_name == "John Smith"

    def test_three_part_name_with_middle(self, parser: NameParser) -> None:
        """Test parsing a name with middle name."""
        parsed = parser.parse("John Robert Smith")
        assert parsed.first_name == "John"
        assert parsed.middle_name == "Robert"
        assert parsed.last_name == "Smith"
        assert "John Robert Smith" in parsed.variations

    def test_name_with_prefix(self, parser: NameParser) -> None:
        """Test parsing a name with title prefix."""
        parsed = parser.parse("Dr. Jane Doe")
        assert parsed.first_name == "Jane"
        assert parsed.last_name == "Doe"
        assert "Dr." in parsed.prefixes or "Dr" in parsed.prefixes

    def test_name_with_suffix(self, parser: NameParser) -> None:
        """Test parsing a name with suffix."""
        parsed = parser.parse("Robert Johnson Jr.")
        assert parsed.first_name == "Robert"
        assert parsed.last_name == "Johnson"
        assert any("jr" in s.lower() for s in parsed.suffixes)

    def test_name_with_multiple_suffixes(self, parser: NameParser) -> None:
        """Test parsing a name with multiple suffixes."""
        parsed = parser.parse("John Smith Jr. PhD")
        assert parsed.first_name == "John"
        assert parsed.last_name == "Smith"
        assert len(parsed.suffixes) >= 1

    def test_compound_middle_name(self, parser: NameParser) -> None:
        """Test parsing a name with compound middle name."""
        parsed = parser.parse("Maria Elena Garcia Lopez")
        assert parsed.first_name == "Maria"
        assert parsed.last_name == "Lopez"
        assert parsed.middle_name is not None
        assert "Elena Garcia" in parsed.middle_name

    def test_name_variations_generated(self, parser: NameParser) -> None:
        """Test that name variations are generated."""
        parsed = parser.parse("John Michael Smith")
        assert len(parsed.variations) > 0
        assert "John Smith" in parsed.variations
        assert "John M. Smith" in parsed.variations or "J. Michael Smith" in parsed.variations

    def test_empty_name(self, parser: NameParser) -> None:
        """Test parsing an empty name."""
        parsed = parser.parse("")
        assert parsed.first_name == ""
        assert parsed.last_name == ""

    def test_single_name(self, parser: NameParser) -> None:
        """Test parsing a single name (mononym)."""
        parsed = parser.parse("Madonna")
        assert parsed.first_name == "Madonna"
        assert parsed.last_name == ""

    def test_name_with_extra_whitespace(self, parser: NameParser) -> None:
        """Test parsing a name with extra whitespace."""
        parsed = parser.parse("  John   Smith  ")
        assert parsed.first_name == "John"
        assert parsed.last_name == "Smith"
        assert parsed.full_name == "John Smith"

    def test_hyphenated_last_name(self, parser: NameParser) -> None:
        """Test parsing a hyphenated last name."""
        parsed = parser.parse("Jane Smith-Jones")
        assert parsed.first_name == "Jane"
        assert "Smith-Jones" in parsed.last_name


class TestNameSearch:
    """Test the NameSearch class."""

    @pytest.fixture
    def name_search(self) -> NameSearch:
        """Create a NameSearch instance."""
        return NameSearch()

    @pytest.mark.asyncio
    async def test_search_returns_results(self, name_search: NameSearch) -> None:
        """Test that search returns results."""
        results = await name_search.search("John Smith")
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_search_includes_parsing_result(self, name_search: NameSearch) -> None:
        """Test that search includes name parsing result."""
        results = await name_search.search("Jane Doe")
        parsing_results = [r for r in results if r.source == "name:parsing"]
        assert len(parsing_results) == 1
        assert parsing_results[0].metadata["first_name"] == "Jane"
        assert parsing_results[0].metadata["last_name"] == "Doe"

    @pytest.mark.asyncio
    async def test_search_includes_disambiguation(self, name_search: NameSearch) -> None:
        """Test that search includes disambiguation analysis."""
        results = await name_search.search("John Smith")
        disambiguation_results = [r for r in results if r.source == "name:disambiguation"]
        assert len(disambiguation_results) == 1
        assert "disambiguation_score" in disambiguation_results[0].metadata

    @pytest.mark.asyncio
    async def test_common_name_has_low_disambiguation_score(self, name_search: NameSearch) -> None:
        """Test that common names have lower disambiguation scores."""
        results = await name_search.search("John Smith")
        disambiguation_results = [r for r in results if r.source == "name:disambiguation"]
        assert len(disambiguation_results) == 1
        score = disambiguation_results[0].metadata["disambiguation_score"]
        # Common name should have lower score
        assert score < 0.7

    @pytest.mark.asyncio
    async def test_unique_name_has_higher_disambiguation_score(
        self, name_search: NameSearch
    ) -> None:
        """Test that unique names have higher disambiguation scores."""
        results = await name_search.search("Xenophilius Lovegood Jr.")
        disambiguation_results = [r for r in results if r.source == "name:disambiguation"]
        assert len(disambiguation_results) == 1
        score = disambiguation_results[0].metadata["disambiguation_score"]
        # Unique name with suffix should have higher score
        assert score > 0.5

    @pytest.mark.asyncio
    async def test_search_includes_social_media_patterns(self, name_search: NameSearch) -> None:
        """Test that search includes social media username patterns."""
        results = await name_search.search("Jane Doe")
        social_results = [r for r in results if r.source == "name:social_media_patterns"]
        assert len(social_results) == 1
        assert "potential_usernames" in social_results[0].metadata
        usernames = social_results[0].metadata["potential_usernames"]
        assert "janedoe" in usernames or "jane.doe" in usernames

    @pytest.mark.asyncio
    async def test_search_includes_public_records(self, name_search: NameSearch) -> None:
        """Test that search includes public records guidance."""
        results = await name_search.search("John Smith")
        public_records = [r for r in results if r.source == "name:public_records"]
        assert len(public_records) == 1
        assert "recommended_sources" in public_records[0].metadata

    @pytest.mark.asyncio
    async def test_disambiguation_with_location_context(self, name_search: NameSearch) -> None:
        """Test that providing location context improves disambiguation."""
        context = DisambiguationContext(location="San Francisco, CA")
        results = await name_search.search("John Smith", context=context)

        disambiguation_results = [r for r in results if r.source == "name:disambiguation"]
        assert len(disambiguation_results) == 1

        # Should have location_provided factor
        factors = disambiguation_results[0].metadata["factors"]
        assert "location_provided" in factors

    @pytest.mark.asyncio
    async def test_location_filter_applied(self, name_search: NameSearch) -> None:
        """Test that location filtering adds filter result."""
        context = DisambiguationContext(location="New York, NY")
        results = await name_search.search("Jane Doe", context=context)

        filter_results = [r for r in results if r.source == "name:location_filter"]
        assert len(filter_results) == 1
        assert filter_results[0].metadata["location"] == "New York, NY"

    @pytest.mark.asyncio
    async def test_disambiguation_with_multiple_context_factors(
        self, name_search: NameSearch
    ) -> None:
        """Test disambiguation with multiple context factors."""
        context = DisambiguationContext(
            location="Boston, MA",
            age_range=(30, 40),
            occupation="Software Engineer",
            known_usernames=["jsmith123"],
            known_emails=["john@example.com"],
        )
        results = await name_search.search("John Smith", context=context)

        disambiguation_results = [r for r in results if r.source == "name:disambiguation"]
        assert len(disambiguation_results) == 1

        factors = disambiguation_results[0].metadata["factors"]
        # Should have multiple context factors
        assert "location_provided" in factors
        assert "age_range_provided" in factors
        assert "occupation_provided" in factors
        assert "known_usernames" in factors
        assert "known_emails" in factors

    @pytest.mark.asyncio
    async def test_empty_name_returns_no_results(self, name_search: NameSearch) -> None:
        """Test that empty name returns no results."""
        results = await name_search.search("")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_name_with_middle_name_improves_disambiguation(
        self, name_search: NameSearch
    ) -> None:
        """Test that middle names improve disambiguation scores."""
        results_no_middle = await name_search.search("John Smith")
        results_with_middle = await name_search.search("John Robert Smith")

        # Get disambiguation scores
        score_no_middle = [r for r in results_no_middle if r.source == "name:disambiguation"][
            0
        ].metadata["disambiguation_score"]
        score_with_middle = [r for r in results_with_middle if r.source == "name:disambiguation"][
            0
        ].metadata["disambiguation_score"]

        # Score with middle name should be higher
        assert score_with_middle > score_no_middle

    @pytest.mark.asyncio
    async def test_name_variations_in_parsing_result(self, name_search: NameSearch) -> None:
        """Test that name variations are included in parsing result."""
        results = await name_search.search("John Michael Smith")
        parsing_results = [r for r in results if r.source == "name:parsing"]
        assert len(parsing_results) == 1

        variations = parsing_results[0].metadata["variations"]
        assert isinstance(variations, list)
        assert len(variations) > 0

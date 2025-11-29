"""Tests for phone search module."""

import pytest

from src.search.phone import PhoneSearch, PhoneValidator


class TestPhoneValidator:
    """Test phone validation functionality."""

    def test_valid_us_number(self):
        """Test validation of a valid US phone number."""
        validator = PhoneValidator()
        result = validator.validate("+1 650-253-0000", "US")

        assert result.is_valid is True
        assert result.country_code == 1
        assert result.country == "US"
        assert result.e164_format == "+16502530000"
        assert result.error is None

    def test_valid_us_number_without_country_code(self):
        """Test US number without country code uses default region."""
        validator = PhoneValidator()
        result = validator.validate("(650) 253-0000", "US")

        assert result.is_valid is True
        assert result.country_code == 1
        assert result.country == "US"

    def test_valid_uk_number(self):
        """Test validation of a valid UK phone number."""
        validator = PhoneValidator()
        result = validator.validate("+44 20 7946 0958", "GB")

        assert result.is_valid is True
        assert result.country_code == 44
        assert result.country == "GB"
        assert result.e164_format == "+442079460958"

    def test_valid_mobile_number(self):
        """Test validation of a valid mobile number."""
        validator = PhoneValidator()
        result = validator.validate("+1 415-555-2671", "US")

        assert result.is_valid is True
        assert result.number_type in ["mobile", "fixed_or_mobile"]

    def test_invalid_number_format(self):
        """Test validation of invalid phone number formats."""
        validator = PhoneValidator()

        invalid_numbers = ["123", "abc-def-ghij", "+1 999-999-9999", ""]  # Invalid area code

        for number in invalid_numbers:
            result = validator.validate(number, "US")
            assert result.is_valid is False
            assert result.error is not None

    def test_international_format(self):
        """Test that numbers are formatted internationally."""
        validator = PhoneValidator()
        result = validator.validate("6502530000", "US")

        assert result.is_valid is True
        assert result.international_format == "+1 650-253-0000"
        assert result.e164_format == "+16502530000"

    def test_carrier_extraction(self):
        """Test carrier information extraction."""
        validator = PhoneValidator()
        result = validator.validate("+1 650-253-0000", "US")

        assert result.is_valid is True
        assert result.carrier_name is not None  # May be "Unknown" or actual carrier

    def test_geographic_location(self):
        """Test geographic location extraction."""
        validator = PhoneValidator()
        result = validator.validate("+1 650-253-0000", "US")

        assert result.is_valid is True
        assert result.region is not None
        assert result.country == "US"

    def test_timezone_extraction(self):
        """Test timezone information extraction."""
        validator = PhoneValidator()
        result = validator.validate("+1 650-253-0000", "US")

        assert result.is_valid is True
        assert result.timezones is not None
        assert isinstance(result.timezones, list)

    def test_number_type_detection(self):
        """Test different number type detection."""
        validator = PhoneValidator()

        # Mobile number
        mobile = validator.validate("+1 415-555-0100", "US")
        assert mobile.is_valid is True
        assert mobile.number_type in ["mobile", "fixed_or_mobile", "fixed_line"]

        # Toll-free
        toll_free = validator.validate("+1 800-555-0100", "US")
        assert toll_free.is_valid is True
        assert toll_free.number_type == "toll_free"


@pytest.mark.asyncio
class TestPhoneSearch:
    """Test phone search functionality."""

    async def test_phone_search_with_validation(self):
        """Test phone search returns validation results."""
        search = PhoneSearch()
        results = await search.search("+1 650-253-0000")

        # Should have at least validation result
        assert len(results) >= 1

        # Check validation result
        validation_result = results[0]
        assert validation_result.source == "phone:validation"
        assert validation_result.metadata["is_valid"] is True
        assert validation_result.metadata["country"] == "US"

    async def test_invalid_phone_returns_empty(self):
        """Test that invalid phones return no results."""
        search = PhoneSearch()
        results = await search.search("not-a-phone")

        assert len(results) == 0

    async def test_phone_search_includes_carrier(self):
        """Test phone search includes carrier information."""
        search = PhoneSearch()
        results = await search.search("+1 650-253-0000")

        # Find carrier result
        carrier_results = [r for r in results if r.source == "phone:carrier_lookup"]
        assert len(carrier_results) > 0

        carrier_result = carrier_results[0]
        assert "carrier" in carrier_result.metadata
        assert "region" in carrier_result.metadata
        assert "number_type" in carrier_result.metadata

    async def test_phone_search_includes_reputation(self):
        """Test phone search includes spam/reputation check."""
        search = PhoneSearch()
        results = await search.search("+1 650-253-0000")

        # Find reputation result
        reputation_results = [r for r in results if r.source == "phone:reputation"]
        assert len(reputation_results) > 0

        rep_result = reputation_results[0]
        assert "spam_score" in rep_result.metadata
        assert "flags" in rep_result.metadata

    async def test_toll_free_number_detection(self):
        """Test that toll-free numbers are properly flagged."""
        search = PhoneSearch()
        results = await search.search("+1 800-555-0100")

        # Find validation result
        validation_results = [r for r in results if r.source == "phone:validation"]
        assert len(validation_results) > 0

        val_result = validation_results[0]
        assert val_result.metadata["number_type"] == "toll_free"

        # Check reputation flags toll-free
        reputation_results = [r for r in results if r.source == "phone:reputation"]
        if reputation_results:
            rep_result = reputation_results[0]
            assert "toll_free_number" in rep_result.metadata.get("flags", [])

    async def test_international_number_formats(self):
        """Test various international number formats."""
        search = PhoneSearch()

        # UK number
        uk_results = await search.search("+44 20 7946 0958", "GB")
        assert len(uk_results) > 0
        assert uk_results[0].metadata["country"] == "GB"

        # US number
        us_results = await search.search("+1 650-253-0000", "US")
        assert len(us_results) > 0
        assert us_results[0].metadata["country"] == "US"

    async def test_default_region_parameter(self):
        """Test that default region parameter works correctly."""
        search = PhoneSearch()

        # Number without country code, using default region
        results = await search.search("(650) 253-0000", "US")

        assert len(results) > 0
        validation_result = results[0]
        assert validation_result.metadata["country"] == "US"
        assert validation_result.metadata["country_code"] == 1

    async def test_e164_format_normalization(self):
        """Test that numbers are normalized to E164 format."""
        search = PhoneSearch()

        # Various input formats
        formats = ["+1 650-253-0000", "1-650-253-0000", "(650) 253-0000", "6502530000"]

        for fmt in formats:
            results = await search.search(fmt, "US")
            if results:
                validation_result = results[0]
                assert validation_result.metadata["formats"]["e164"] == "+16502530000"

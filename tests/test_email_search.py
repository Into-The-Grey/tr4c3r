"""Tests for email search module."""

import pytest 
from datetime import datetime

from src.search.email import EmailSearch, EmailValidator


class TestEmailValidator:
    """Test email validation functionality."""

    def test_valid_email(self):
        """Test validation of a valid email."""
        validator = EmailValidator()
        result = validator.validate("test@example.com")

        assert result.is_valid is True
        assert result.email == "test@example.com"
        assert result.domain == "example.com"
        assert result.username == "test"
        assert result.error is None

    def test_invalid_email_format(self):
        """Test validation of invalid email formats."""
        validator = EmailValidator()

        invalid_emails = [
            "notanemail",
            "@example.com",
            "test@",
            "test @example.com",
            "test@.com",
            "",
        ]

        for email in invalid_emails:
            result = validator.validate(email)
            assert result.is_valid is False
            assert result.error is not None

    def test_disposable_email_detection(self):
        """Test detection of disposable email addresses."""
        validator = EmailValidator()
        result = validator.validate("test@mailinator.com")

        assert result.is_valid is True
        assert result.is_disposable is True

    def test_role_based_email_detection(self):
        """Test detection of role-based email addresses."""
        validator = EmailValidator()

        role_emails = ["admin@example.com", "support@example.com", "noreply@example.com"]

        for email in role_emails:
            result = validator.validate(email)
            assert result.is_valid is True
            assert result.is_role_based is True

    def test_normal_email_not_role_based(self):
        """Test that normal emails are not flagged as role-based."""
        validator = EmailValidator()
        result = validator.validate("john.doe@example.com")

        assert result.is_valid is True
        assert result.is_role_based is False
        assert result.is_disposable is False


@pytest.mark.asyncio
class TestEmailSearch:
    """Test email search functionality."""

    async def test_email_search_with_validation(self):
        """Test email search returns validation results."""
        search = EmailSearch()
        results = await search.search("test@example.com")

        # Should have at least validation result
        assert len(results) >= 1

        # Check validation result
        validation_result = results[0]
        assert validation_result.source == "email:validation"
        assert validation_result.identifier == "test@example.com"
        assert validation_result.metadata["is_valid"] is True
        assert validation_result.metadata["domain"] == "example.com"

    async def test_invalid_email_returns_empty(self):
        """Test that invalid emails return no results."""
        search = EmailSearch()
        results = await search.search("notanemail")

        assert len(results) == 0

    async def test_email_search_includes_reputation(self):
        """Test email search includes reputation check."""
        search = EmailSearch()
        results = await search.search("test@gmail.com")

        # Find reputation result
        reputation_results = [r for r in results if r.source == "email:reputation"]
        assert len(reputation_results) > 0

        rep_result = reputation_results[0]
        assert "reputation_score" in rep_result.metadata
        assert "is_major_provider" in rep_result.metadata
        assert rep_result.metadata["is_major_provider"] is True

    async def test_disposable_email_reputation(self):
        """Test that disposable emails get lower reputation scores."""
        search = EmailSearch()
        results = await search.search("test@mailinator.com")

        # Find reputation result
        reputation_results = [r for r in results if r.source == "email:reputation"]
        assert len(reputation_results) > 0

        rep_result = reputation_results[0]
        assert rep_result.metadata["is_disposable"] is True
        # Disposable emails should have lower scores
        assert rep_result.metadata["reputation_score"] < 0.5

    async def test_email_case_insensitive(self):
        """Test that email search is case-insensitive."""
        search = EmailSearch()
        results1 = await search.search("Test@Example.COM")
        results2 = await search.search("test@example.com")

        # Both should produce validation results
        assert len(results1) > 0
        assert len(results2) > 0

        # Emails should be normalized to lowercase
        assert results1[0].identifier == "test@example.com"
        assert results2[0].identifier == "test@example.com"

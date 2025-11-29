"""Tests for the variant generator."""

from src.core.variant_generator import generate_variants


def test_generate_variants_basic():
    variants = generate_variants("test", max_variants=10)
    assert "test" in variants
    assert len(variants) <= 10


def test_generate_variants_separators():
    variants = generate_variants("user", max_variants=100)
    assert "user_" in variants or "user." in variants or "user-" in variants


def test_generate_variants_substitutions():
    # Test with a username that has 'o' -> '0' substitution
    variants = generate_variants("john", max_variants=100)
    # The substitution of 'o' -> '0' creates 'j0hn'
    assert "j0hn" in variants


def test_generate_variants_max_cap():
    variants = generate_variants("name", max_variants=5)
    assert len(variants) <= 5

"""Tests for the data models."""

from datetime import datetime, timezone

import pytest

from src.core.data_models import Result, SearchSession


def test_result_creation():
    result = Result(
        source="test_source",
        identifier="testuser",
        url="https://example.com/testuser",
        confidence=0.9,
    )
    assert result.source == "test_source"
    assert result.identifier == "testuser"
    assert result.confidence == 0.9
    assert isinstance(result.timestamp, datetime)


def test_result_confidence_clamping():
    """Test that confidence values are clamped to [0, 1] range."""
    # Test clamping high value
    result_high = Result(source="test", identifier="user", confidence=1.5)
    assert result_high.confidence == 1.0

    # Test clamping low value
    result_low = Result(source="test", identifier="user", confidence=-0.5)
    assert result_low.confidence == 0.0

    # Test valid values are unchanged
    result_normal = Result(source="test", identifier="user", confidence=0.7)
    assert result_normal.confidence == 0.7


def test_result_empty_source_raises():
    """Test that empty source raises ValueError."""
    with pytest.raises(ValueError, match="source cannot be empty"):
        Result(source="", identifier="user")


def test_result_empty_identifier_raises():
    """Test that empty identifier raises ValueError."""
    with pytest.raises(ValueError, match="identifier cannot be empty"):
        Result(source="test", identifier="")


def test_result_to_dict():
    result = Result(
        source="test_source",
        identifier="testuser",
        url="https://example.com",
        metadata={"key": "value"},
    )
    data = result.to_dict()
    assert data["source"] == "test_source"
    assert data["metadata"]["key"] == "value"
    assert "timestamp" in data


def test_result_from_dict():
    """Test creating Result from dictionary."""
    data = {
        "source": "test_source",
        "identifier": "testuser",
        "url": "https://example.com",
        "confidence": 0.8,
        "metadata": {"key": "value"},
    }
    result = Result.from_dict(data)
    assert result.source == "test_source"
    assert result.identifier == "testuser"
    assert result.confidence == 0.8
    assert result.metadata["key"] == "value"


def test_result_from_dict_missing_fields():
    """Test that from_dict raises error for missing required fields."""
    with pytest.raises(ValueError, match="requires 'source' and 'identifier' fields"):
        Result.from_dict({"source": "test"})


def test_result_to_json():
    """Test JSON serialization."""
    result = Result(
        source="test_source",
        identifier="testuser",
        metadata={"key": "value"},
    )
    json_str = result.to_json()
    assert "test_source" in json_str
    assert "testuser" in json_str


def test_result_merge_metadata():
    """Test merging metadata."""
    result = Result(
        source="test_source",
        identifier="testuser",
        metadata={"key1": "value1"},
    )
    result.merge_metadata({"key2": "value2"})
    assert result.metadata["key1"] == "value1"
    assert result.metadata["key2"] == "value2"


def test_result_repr():
    """Test string representation."""
    result = Result(source="test", identifier="user", confidence=0.5)
    repr_str = repr(result)
    assert "test" in repr_str
    assert "user" in repr_str
    assert "0.50" in repr_str


def test_search_session_creation():
    """Test SearchSession creation."""
    session = SearchSession(
        session_id="sess-123",
        query="testuser",
        search_type="username",
    )
    assert session.session_id == "sess-123"
    assert session.query == "testuser"
    assert session.search_type == "username"
    assert session.result_count == 0


def test_search_session_add_result():
    """Test adding results to session."""
    session = SearchSession(
        session_id="sess-123",
        query="testuser",
        search_type="username",
    )
    result = Result(source="test", identifier="testuser")
    session.add_result(result)
    assert session.result_count == 1


def test_search_session_complete():
    """Test completing a session."""
    session = SearchSession(
        session_id="sess-123",
        query="testuser",
        search_type="username",
    )
    assert session.completed_at is None
    session.complete()
    assert session.completed_at is not None
    assert session.duration_ms is not None
    assert session.duration_ms >= 0


def test_search_session_to_dict():
    """Test session serialization."""
    session = SearchSession(
        session_id="sess-123",
        query="testuser",
        search_type="username",
    )
    session.add_result(Result(source="test", identifier="testuser"))
    session.complete()

    data = session.to_dict()
    assert data["session_id"] == "sess-123"
    assert data["result_count"] == 1
    assert len(data["results"]) == 1

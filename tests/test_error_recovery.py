"""Tests for the error recovery module."""

import asyncio
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock

from src.core.error_recovery import (
    ErrorSeverity,
    SearchError,
    PartialSearchResult,
    RetryQueue,
    ErrorRecoveryManager,
    classify_error,
    is_recoverable_error,
)
from src.core.data_models import Result


class TestSearchError:
    """Tests for SearchError class."""

    def test_init(self):
        """Test initialization."""
        error = SearchError(
            module="test_module",
            query="test_query",
            error_type="TestError",
            message="Test error message",
        )
        assert error.module == "test_module"
        assert error.query == "test_query"
        assert error.error_type == "TestError"
        assert error.severity == ErrorSeverity.MEDIUM

    def test_can_retry(self):
        """Test retry capability check."""
        error = SearchError(
            module="test",
            query="query",
            error_type="Error",
            message="msg",
            recoverable=True,
            retry_count=0,
            max_retries=3,
        )
        assert error.can_retry() is True

    def test_cannot_retry_max_reached(self):
        """Test retry blocked when max reached."""
        error = SearchError(
            module="test",
            query="query",
            error_type="Error",
            message="msg",
            recoverable=True,
            retry_count=3,
            max_retries=3,
        )
        assert error.can_retry() is False

    def test_cannot_retry_not_recoverable(self):
        """Test retry blocked when not recoverable."""
        error = SearchError(
            module="test",
            query="query",
            error_type="Error",
            message="msg",
            recoverable=False,
        )
        assert error.can_retry() is False

    def test_to_dict(self):
        """Test serialization to dictionary."""
        error = SearchError(
            module="test",
            query="query",
            error_type="Error",
            message="msg",
            severity=ErrorSeverity.HIGH,
        )
        d = error.to_dict()

        assert d["module"] == "test"
        assert d["severity"] == "high"
        assert "timestamp" in d


class TestPartialSearchResult:
    """Tests for PartialSearchResult class."""

    def test_init(self):
        """Test initialization."""
        result = PartialSearchResult(query="test")
        assert result.query == "test"
        assert result.results == []
        assert result.errors == []

    def test_is_complete(self):
        """Test is_complete property."""
        result = PartialSearchResult(query="test")
        result.modules_completed.append("module1")
        assert result.is_complete is True

        result.modules_failed.append("module2")
        assert result.is_complete is False

    def test_is_partial(self):
        """Test is_partial property."""
        result = PartialSearchResult(query="test")
        result.results.append(Result(source="test", identifier="id", confidence=0.5))
        result.modules_failed.append("module1")
        assert result.is_partial is True

    def test_is_failed(self):
        """Test is_failed property."""
        result = PartialSearchResult(query="test")
        result.modules_failed.append("module1")
        assert result.is_failed is True

    def test_success_rate(self):
        """Test success rate calculation."""
        result = PartialSearchResult(query="test")
        result.modules_completed.extend(["m1", "m2", "m3"])
        result.modules_failed.append("m4")

        assert result.success_rate == 0.75

    def test_success_rate_no_modules(self):
        """Test success rate with no modules."""
        result = PartialSearchResult(query="test")
        assert result.success_rate == 0.0

    def test_add_result(self):
        """Test adding a result."""
        result = PartialSearchResult(query="test")
        result.add_result(Result(source="test", identifier="id", confidence=0.5))
        assert len(result.results) == 1

    def test_add_results(self):
        """Test adding results from a module."""
        result = PartialSearchResult(query="test")
        results = [
            Result(source="test", identifier="id1", confidence=0.5),
            Result(source="test", identifier="id2", confidence=0.6),
        ]
        result.add_results(results, "module1")

        assert len(result.results) == 2
        assert "module1" in result.modules_completed

    def test_add_error(self):
        """Test adding an error."""
        result = PartialSearchResult(query="test")
        error = SearchError(
            module="module1",
            query="test",
            error_type="Error",
            message="msg",
        )
        result.add_error(error)

        assert len(result.errors) == 1
        assert "module1" in result.modules_failed

    def test_get_retryable_errors(self):
        """Test getting retryable errors."""
        result = PartialSearchResult(query="test")

        recoverable = SearchError(
            module="m1",
            query="q",
            error_type="E",
            message="m",
            recoverable=True,
            retry_count=0,
            max_retries=3,
        )
        non_recoverable = SearchError(
            module="m2",
            query="q",
            error_type="E",
            message="m",
            recoverable=False,
        )

        result.add_error(recoverable)
        result.add_error(non_recoverable)

        retryable = result.get_retryable_errors()
        assert len(retryable) == 1
        assert retryable[0].module == "m1"

    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = PartialSearchResult(query="test")
        result.modules_completed.append("m1")
        d = result.to_dict()

        assert d["query"] == "test"
        assert d["result_count"] == 0
        assert "modules_completed" in d


class TestRetryQueue:
    """Tests for RetryQueue class."""

    def test_init(self):
        """Test initialization."""
        queue = RetryQueue(max_retries=5, base_delay=2.0)
        assert queue.max_retries == 5
        assert queue.base_delay == 2.0

    def test_enqueue(self):
        """Test enqueueing a failed operation."""
        queue = RetryQueue()
        error = SearchError(
            module="m",
            query="q",
            error_type="E",
            message="m",
            recoverable=True,
            retry_count=0,
            max_retries=3,
        )

        result = queue.enqueue(error, lambda: None)
        assert result is True
        assert queue.pending_count() == 1

    def test_enqueue_max_retries_exceeded(self):
        """Test that enqueue fails when max retries exceeded."""
        queue = RetryQueue()
        error = SearchError(
            module="m",
            query="q",
            error_type="E",
            message="m",
            recoverable=True,
            retry_count=3,
            max_retries=3,
        )

        result = queue.enqueue(error, lambda: None)
        assert result is False
        assert queue.pending_count() == 0

    def test_calculate_delay_linear(self):
        """Test linear delay calculation."""
        queue = RetryQueue(base_delay=1.0, exponential_backoff=False)

        assert queue._calculate_delay(1) == 1.0
        assert queue._calculate_delay(2) == 1.0
        assert queue._calculate_delay(5) == 1.0

    def test_calculate_delay_exponential(self):
        """Test exponential backoff delay calculation."""
        queue = RetryQueue(base_delay=1.0, exponential_backoff=True)

        assert queue._calculate_delay(1) == 1.0
        assert queue._calculate_delay(2) == 2.0
        assert queue._calculate_delay(3) == 4.0

    def test_calculate_delay_max(self):
        """Test delay capped at max_delay."""
        queue = RetryQueue(base_delay=1.0, max_delay=5.0, exponential_backoff=True)

        assert queue._calculate_delay(10) == 5.0

    @pytest.mark.asyncio
    async def test_process_success(self):
        """Test processing with successful retry."""
        queue = RetryQueue(base_delay=0.01)  # Short delay for test

        error = SearchError(
            module="m",
            query="q",
            error_type="E",
            message="m",
            recoverable=True,
            retry_count=0,
            max_retries=3,
        )

        async def success_func():
            return [Result(source="test", identifier="id", confidence=0.5)]

        queue.enqueue(error, success_func)
        results = await queue.process()

        assert len(results) == 1
        error, outcome = results[0]
        assert outcome is not None

    @pytest.mark.asyncio
    async def test_process_failure(self):
        """Test processing with failed retry."""
        queue = RetryQueue(base_delay=0.01, max_retries=1)

        error = SearchError(
            module="m",
            query="q",
            error_type="E",
            message="m",
            recoverable=True,
            retry_count=0,
            max_retries=1,
        )

        async def fail_func():
            raise Exception("Still failing")

        queue.enqueue(error, fail_func)
        results = await queue.process()

        assert len(results) == 1
        error, outcome = results[0]
        assert outcome is None

    def test_clear(self):
        """Test clearing the queue."""
        queue = RetryQueue()
        error = SearchError(
            module="m",
            query="q",
            error_type="E",
            message="m",
            recoverable=True,
            retry_count=0,
            max_retries=3,
        )
        queue.enqueue(error, lambda: None)

        count = queue.clear()
        assert count == 1
        assert queue.pending_count() == 0


class TestErrorRecoveryManager:
    """Tests for ErrorRecoveryManager class."""

    def test_init(self):
        """Test initialization."""
        manager = ErrorRecoveryManager(
            collect_partial=True,
            auto_retry=False,
            max_retries=5,
        )
        assert manager.collect_partial is True
        assert manager.auto_retry is False

    def test_handle_error(self):
        """Test error handling."""
        manager = ErrorRecoveryManager()

        error = manager.handle_error(
            module="test_module",
            query="test_query",
            exception=ValueError("Test error"),
            severity=ErrorSeverity.HIGH,
        )

        assert error.module == "test_module"
        assert error.error_type == "ValueError"
        assert error.severity == ErrorSeverity.HIGH

    def test_register_error_handler(self):
        """Test registering an error handler."""
        manager = ErrorRecoveryManager()
        handled = []

        def handler(error):
            handled.append(error)

        manager.register_error_handler("ValueError", handler)
        manager.handle_error(
            module="test",
            query="query",
            exception=ValueError("Test"),
        )

        assert len(handled) == 1

    @pytest.mark.asyncio
    async def test_execute_with_recovery(self):
        """Test executing modules with recovery."""
        manager = ErrorRecoveryManager(auto_retry=False)

        async def success_module(query):
            return [Result(source="success", identifier=query, confidence=0.9)]

        async def fail_module(query):
            raise ConnectionError("Network error")

        modules = {
            "success": success_module,
            "fail": fail_module,
        }

        result = await manager.execute_with_recovery(modules, "test_query")

        assert len(result.results) == 1
        assert len(result.errors) == 1
        assert "success" in result.modules_completed
        assert "fail" in result.modules_failed


class TestClassifyError:
    """Tests for classify_error function."""

    def test_network_error(self):
        """Test classifying network errors."""
        assert classify_error(ConnectionError("test")) == ErrorSeverity.MEDIUM
        assert classify_error(TimeoutError("test")) == ErrorSeverity.MEDIUM

    def test_rate_limit_error(self):
        """Test classifying rate limit errors."""

        class RateLimitError(Exception):
            pass

        assert classify_error(RateLimitError("test")) == ErrorSeverity.LOW

    def test_auth_error(self):
        """Test classifying authentication errors."""

        class AuthenticationError(Exception):
            pass

        assert classify_error(AuthenticationError("test")) == ErrorSeverity.HIGH


class TestIsRecoverableError:
    """Tests for is_recoverable_error function."""

    def test_non_recoverable_errors(self):
        """Test non-recoverable error types."""
        assert is_recoverable_error(ValueError("test")) is False
        assert is_recoverable_error(TypeError("test")) is False
        assert is_recoverable_error(KeyError("test")) is False

    def test_recoverable_errors(self):
        """Test recoverable error types."""
        assert is_recoverable_error(ConnectionError("test")) is True
        assert is_recoverable_error(TimeoutError("test")) is True

    def test_permanent_failure_message(self):
        """Test detection of permanent failures from message."""

        class GenericError(Exception):
            pass

        assert is_recoverable_error(GenericError("not found")) is False
        assert is_recoverable_error(GenericError("invalid api key")) is False
        assert is_recoverable_error(GenericError("unauthorized")) is False

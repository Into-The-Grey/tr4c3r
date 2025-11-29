"""Error recovery utilities for TR4C3R.

This module provides error recovery mechanisms for handling failures
during search operations, including partial result collection and
retry queuing.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from src.core.data_models import Result

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ErrorSeverity(Enum):
    """Severity levels for errors."""

    LOW = "low"  # Minor issue, can continue
    MEDIUM = "medium"  # Notable issue, degraded results
    HIGH = "high"  # Major issue, partial failure
    CRITICAL = "critical"  # Complete failure


@dataclass
class SearchError:
    """Represents an error that occurred during a search."""

    module: str
    query: str
    error_type: str
    message: str
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    recoverable: bool = True
    retry_count: int = 0
    max_retries: int = 3
    details: Dict[str, Any] = field(default_factory=dict)

    def can_retry(self) -> bool:
        """Check if this error can be retried."""
        return self.recoverable and self.retry_count < self.max_retries

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "module": self.module,
            "query": self.query,
            "error_type": self.error_type,
            "message": self.message,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "recoverable": self.recoverable,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "details": self.details,
        }


@dataclass
class PartialSearchResult:
    """Result of a search that may have partial failures."""

    query: str
    results: List[Result] = field(default_factory=list)
    errors: List[SearchError] = field(default_factory=list)
    modules_completed: List[str] = field(default_factory=list)
    modules_failed: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None

    @property
    def is_complete(self) -> bool:
        """Check if all modules completed without errors."""
        return len(self.modules_failed) == 0

    @property
    def is_partial(self) -> bool:
        """Check if some modules failed but we have some results."""
        return len(self.modules_failed) > 0 and len(self.results) > 0

    @property
    def is_failed(self) -> bool:
        """Check if all modules failed."""
        return len(self.modules_failed) > 0 and len(self.results) == 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate of modules."""
        total = len(self.modules_completed) + len(self.modules_failed)
        if total == 0:
            return 0.0
        return len(self.modules_completed) / total

    @property
    def elapsed_seconds(self) -> float:
        """Calculate elapsed time."""
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

    def mark_complete(self) -> None:
        """Mark the search as complete."""
        self.end_time = datetime.now(timezone.utc)

    def add_result(self, result: Result) -> None:
        """Add a result."""
        self.results.append(result)

    def add_results(self, results: List[Result], module: str) -> None:
        """Add results from a module."""
        self.results.extend(results)
        if module not in self.modules_completed:
            self.modules_completed.append(module)

    def add_error(self, error: SearchError) -> None:
        """Add an error."""
        self.errors.append(error)
        if error.module not in self.modules_failed:
            self.modules_failed.append(error.module)

    def get_errors_by_severity(self, severity: ErrorSeverity) -> List[SearchError]:
        """Get errors of a specific severity."""
        return [e for e in self.errors if e.severity == severity]

    def get_retryable_errors(self) -> List[SearchError]:
        """Get errors that can be retried."""
        return [e for e in self.errors if e.can_retry()]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "query": self.query,
            "result_count": len(self.results),
            "error_count": len(self.errors),
            "modules_completed": self.modules_completed,
            "modules_failed": self.modules_failed,
            "is_complete": self.is_complete,
            "is_partial": self.is_partial,
            "success_rate": self.success_rate,
            "elapsed_seconds": self.elapsed_seconds,
            "errors": [e.to_dict() for e in self.errors],
        }


class RetryQueue:
    """Queue for retrying failed search operations."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_backoff: bool = True,
    ) -> None:
        """Initialize retry queue.

        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Base delay between retries in seconds
            max_delay: Maximum delay between retries in seconds
            exponential_backoff: Use exponential backoff for delays
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff
        self._queue: List[Tuple[SearchError, Callable, Tuple, Dict]] = []
        self.logger = logging.getLogger(self.__class__.__name__)

    def enqueue(
        self,
        error: SearchError,
        func: Callable,
        args: Tuple = (),
        kwargs: Optional[Dict] = None,
    ) -> bool:
        """Add a failed operation to the retry queue.

        Args:
            error: The error that occurred
            func: The function to retry
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function

        Returns:
            True if added to queue, False if max retries exceeded
        """
        if not error.can_retry():
            self.logger.debug(
                "Not queuing %s: max retries exceeded (%d/%d)",
                error.module,
                error.retry_count,
                error.max_retries,
            )
            return False

        error.retry_count += 1
        self._queue.append((error, func, args, kwargs or {}))
        self.logger.info(
            "Queued %s for retry (%d/%d)",
            error.module,
            error.retry_count,
            error.max_retries,
        )
        return True

    def _calculate_delay(self, retry_count: int) -> float:
        """Calculate delay for a retry attempt."""
        if self.exponential_backoff:
            delay = self.base_delay * (2 ** (retry_count - 1))
        else:
            delay = self.base_delay
        return min(delay, self.max_delay)

    async def process(self) -> List[Tuple[SearchError, Any]]:
        """Process all items in the retry queue.

        Returns:
            List of (error, result) tuples. Result is None if retry failed.
        """
        results: List[Tuple[SearchError, Any]] = []

        while self._queue:
            error, func, args, kwargs = self._queue.pop(0)

            delay = self._calculate_delay(error.retry_count)
            self.logger.debug(
                "Waiting %.1fs before retrying %s (attempt %d/%d)",
                delay,
                error.module,
                error.retry_count,
                error.max_retries,
            )
            await asyncio.sleep(delay)

            try:
                if inspect.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                self.logger.info("Retry succeeded for %s", error.module)
                results.append((error, result))

            except Exception as e:
                self.logger.warning(
                    "Retry failed for %s: %s",
                    error.module,
                    str(e),
                )
                error.message = str(e)

                # Re-queue if still can retry
                if error.can_retry():
                    error.retry_count += 1
                    self._queue.append((error, func, args, kwargs))
                else:
                    results.append((error, None))

        return results

    def pending_count(self) -> int:
        """Get number of pending retries."""
        return len(self._queue)

    def clear(self) -> int:
        """Clear the queue and return count of cleared items."""
        count = len(self._queue)
        self._queue.clear()
        return count


class ErrorRecoveryManager:
    """Manages error recovery for search operations."""

    def __init__(
        self,
        collect_partial: bool = True,
        auto_retry: bool = True,
        max_retries: int = 2,
    ) -> None:
        """Initialize error recovery manager.

        Args:
            collect_partial: Whether to collect partial results
            auto_retry: Whether to automatically retry failed operations
            max_retries: Maximum retry attempts
        """
        self.collect_partial = collect_partial
        self.auto_retry = auto_retry
        self.retry_queue = RetryQueue(max_retries=max_retries)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._error_handlers: Dict[str, Callable[[SearchError], None]] = {}

    def register_error_handler(
        self,
        error_type: str,
        handler: Callable[[SearchError], None],
    ) -> None:
        """Register a handler for a specific error type.

        Args:
            error_type: The error type to handle
            handler: Function to call when error occurs
        """
        self._error_handlers[error_type] = handler

    def handle_error(
        self,
        module: str,
        query: str,
        exception: Exception,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recoverable: bool = True,
    ) -> SearchError:
        """Handle an error from a search module.

        Args:
            module: Name of the module that failed
            query: The search query
            exception: The exception that was raised
            severity: Error severity level
            recoverable: Whether the error is recoverable

        Returns:
            SearchError object
        """
        error_type = type(exception).__name__
        error = SearchError(
            module=module,
            query=query,
            error_type=error_type,
            message=str(exception),
            severity=severity,
            recoverable=recoverable,
            max_retries=self.retry_queue.max_retries,
            details={"exception_class": type(exception).__module__ + "." + error_type},
        )

        # Log the error
        log_level = {
            ErrorSeverity.LOW: logging.DEBUG,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
        }.get(severity, logging.ERROR)

        self.logger.log(
            log_level,
            "Search error in %s for query '%s': %s (%s)",
            module,
            query,
            error.message,
            error_type,
        )

        # Call registered handler if exists
        if error_type in self._error_handlers:
            try:
                self._error_handlers[error_type](error)
            except Exception as e:
                self.logger.warning("Error handler failed: %s", e)

        return error

    async def execute_with_recovery(
        self,
        modules: Dict[str, Callable],
        query: str,
    ) -> PartialSearchResult:
        """Execute multiple search modules with error recovery.

        Args:
            modules: Dictionary of module_name -> search_function
            query: The search query

        Returns:
            PartialSearchResult with results and any errors
        """
        result = PartialSearchResult(query=query)

        # Execute all modules concurrently
        tasks = {}
        for name, func in modules.items():
            tasks[name] = asyncio.create_task(self._safe_execute(name, func, query))

        # Gather results
        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, outcome in zip(tasks.keys(), completed):
            if isinstance(outcome, Exception):
                # This shouldn't happen due to _safe_execute, but handle it
                error = self.handle_error(name, query, outcome)
                result.add_error(error)
            elif isinstance(outcome, tuple):
                module_results, module_error = outcome
                if module_results:
                    result.add_results(module_results, name)
                if module_error:
                    result.add_error(module_error)
            else:
                self.logger.warning("Unexpected result type from %s: %s", name, type(outcome))

        # Process retry queue if auto_retry is enabled
        if self.auto_retry and result.get_retryable_errors():
            await self._process_retries(result, modules)

        result.mark_complete()
        return result

    async def _safe_execute(
        self,
        module_name: str,
        func: Callable,
        query: str,
    ) -> Tuple[List[Result], Optional[SearchError]]:
        """Safely execute a search function.

        Args:
            module_name: Name of the module
            func: The search function
            query: The search query

        Returns:
            Tuple of (results, error) - one may be empty/None
        """
        try:
            if inspect.iscoroutinefunction(func):
                results = await func(query)
            else:
                results = func(query)
            return (results if isinstance(results, list) else [], None)
        except Exception as e:
            error = self.handle_error(module_name, query, e)
            return ([], error)

    async def _process_retries(
        self,
        result: PartialSearchResult,
        modules: Dict[str, Callable],
    ) -> None:
        """Process retries for failed modules.

        Args:
            result: The partial search result
            modules: Available search modules
        """
        for error in result.get_retryable_errors():
            if error.module in modules:
                self.retry_queue.enqueue(
                    error,
                    modules[error.module],
                    args=(error.query,),
                )

        if self.retry_queue.pending_count() > 0:
            retry_results = await self.retry_queue.process()

            for error, retry_outcome in retry_results:
                if retry_outcome and isinstance(retry_outcome, list):
                    # Successful retry
                    result.results.extend(retry_outcome)
                    if error.module in result.modules_failed:
                        result.modules_failed.remove(error.module)
                    if error.module not in result.modules_completed:
                        result.modules_completed.append(error.module)
                    # Remove the error since we recovered
                    if error in result.errors:
                        result.errors.remove(error)


def classify_error(exception: Exception) -> ErrorSeverity:
    """Classify an exception by severity.

    Args:
        exception: The exception to classify

    Returns:
        ErrorSeverity level
    """
    error_type = type(exception).__name__

    # Network-related errors (usually recoverable)
    network_errors = {
        "ConnectionError",
        "TimeoutError",
        "ConnectTimeout",
        "ReadTimeout",
        "HTTPStatusError",
    }
    if error_type in network_errors:
        return ErrorSeverity.MEDIUM

    # Rate limiting (recoverable with backoff)
    if "RateLimit" in error_type or "429" in str(exception):
        return ErrorSeverity.LOW

    # Authentication errors (usually not recoverable without intervention)
    if "Auth" in error_type or "401" in str(exception) or "403" in str(exception):
        return ErrorSeverity.HIGH

    # Server errors (may be recoverable)
    if "500" in str(exception) or "502" in str(exception) or "503" in str(exception):
        return ErrorSeverity.MEDIUM

    # Default
    return ErrorSeverity.MEDIUM


def is_recoverable_error(exception: Exception) -> bool:
    """Determine if an exception is recoverable.

    Args:
        exception: The exception to check

    Returns:
        True if the error is likely recoverable with retry
    """
    error_type = type(exception).__name__

    # Non-recoverable errors
    non_recoverable = {
        "ValueError",
        "TypeError",
        "AttributeError",
        "KeyError",
        "AuthenticationError",
        "PermissionError",
        "NotImplementedError",
    }

    if error_type in non_recoverable:
        return False

    # Check error message for permanent failures
    message = str(exception).lower()
    permanent_markers = [
        "not found",
        "invalid api key",
        "unauthorized",
        "forbidden",
        "not implemented",
    ]

    return not any(marker in message for marker in permanent_markers)

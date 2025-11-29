"""Logging configuration for TR4C3R.

This module defines comprehensive logging infrastructure including:
- Standard application logging with rotation
- Structured JSON logging for machine parsing
- Audit logging for compliance and security
- Performance logging for monitoring
- Configurable log levels per handler

Modules should call ``configure_logging`` once at startup.
"""

import json
import logging
import time
from datetime import datetime, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TypeVar, cast
from contextlib import contextmanager

# Type variables for decorators
F = TypeVar("F", bound=Callable[..., Any])


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON-formatted log string
        """
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields from record
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


class AuditLogger:
    """Dedicated audit logger for compliance and security monitoring."""

    def __init__(self, log_file: Optional[Path] = None):
        """Initialize audit logger.

        Args:
            log_file: Path to audit log file
        """
        self.logger = logging.getLogger("tr4c3r.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to root logger

        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=10,
            )
            handler.setFormatter(JSONFormatter())
            self.logger.addHandler(handler)

    def log_search(
        self,
        user_id: str,
        search_type: str,
        identifier: str,
        purpose: Optional[str] = None,
        results_count: int = 0,
    ) -> None:
        """Log a search operation.

        Args:
            user_id: User performing the search
            search_type: Type of search (email, phone, username, etc.)
            identifier: What was searched for
            purpose: Stated purpose for the search
            results_count: Number of results found
        """
        self.logger.info(
            "Search performed",
            extra={
                "extra_fields": {
                    "event_type": "search",
                    "user_id": user_id,
                    "search_type": search_type,
                    "identifier": identifier,
                    "purpose": purpose,
                    "results_count": results_count,
                }
            },
        )

    def log_export(
        self,
        user_id: str,
        export_format: str,
        data_types: list,
        record_count: int,
    ) -> None:
        """Log a data export operation.

        Args:
            user_id: User performing export
            export_format: Format of export (JSON, CSV, etc.)
            data_types: Types of data exported
            record_count: Number of records exported
        """
        self.logger.info(
            "Data exported",
            extra={
                "extra_fields": {
                    "event_type": "export",
                    "user_id": user_id,
                    "export_format": export_format,
                    "data_types": data_types,
                    "record_count": record_count,
                }
            },
        )

    def log_api_key_usage(
        self,
        user_id: str,
        api_name: str,
        operation: str,
        success: bool,
    ) -> None:
        """Log API key usage.

        Args:
            user_id: User making the API call
            api_name: Name of the API service
            operation: Operation performed
            success: Whether the operation succeeded
        """
        self.logger.info(
            "API key used",
            extra={
                "extra_fields": {
                    "event_type": "api_usage",
                    "user_id": user_id,
                    "api_name": api_name,
                    "operation": operation,
                    "success": success,
                }
            },
        )


class PerformanceLogger:
    """Logger for performance metrics and monitoring."""

    def __init__(self, log_file: Optional[Path] = None):
        """Initialize performance logger.

        Args:
            log_file: Path to performance log file
        """
        self.logger = logging.getLogger("tr4c3r.performance")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
            )
            handler.setFormatter(JSONFormatter())
            self.logger.addHandler(handler)

    def log_operation(
        self,
        operation: str,
        duration_ms: float,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an operation's performance.

        Args:
            operation: Name of the operation
            duration_ms: Duration in milliseconds
            success: Whether the operation succeeded
            metadata: Additional metadata
        """
        log_data = {
            "event_type": "performance",
            "operation": operation,
            "duration_ms": duration_ms,
            "success": success,
        }
        if metadata:
            log_data.update(metadata)

        self.logger.info(
            f"Operation completed: {operation}",
            extra={"extra_fields": log_data},
        )


def timing_decorator(func: F) -> F:
    """Decorator to measure and log function execution time.

    Args:
        func: Function to measure

    Returns:
        Wrapped function that logs execution time
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            success = True
            return result
        except Exception as e:
            success = False
            raise
        finally:
            duration_ms = (time.time() - start_time) * 1000
            logger = logging.getLogger(f"{func.__module__}.{func.__name__}")
            logger.debug(f"Function {func.__name__} took {duration_ms:.2f}ms (success={success})")

    return cast(F, wrapper)


@contextmanager
def log_performance(operation: str, logger: Optional[logging.Logger] = None):
    """Context manager for logging operation performance.

    Args:
        operation: Name of the operation
        logger: Logger to use (default: root logger)

    Example:
        with log_performance("database_query"):
            # perform operation
            results = db.query()
    """
    if logger is None:
        logger = logging.getLogger()

    start_time = time.time()
    try:
        yield
        success = True
    except Exception:
        success = False
        raise
    finally:
        duration_ms = (time.time() - start_time) * 1000
        logger.info(f"{operation} completed in {duration_ms:.2f}ms (success={success})")


def configure_logging(
    log_file: Optional[Path] = None,
    level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
    use_json: bool = False,
    console_output: bool = True,
) -> None:
    """Configure root logging handlers with optional JSON formatting.

    Parameters
    ----------
    log_file: Path, optional
        If provided, logs will be written to this file with rotation.  The
        directory will be created if it does not exist.
    level: int
        Logging level (e.g. ``logging.INFO`` or ``logging.DEBUG``).
    max_bytes: int
        Maximum size of each log file before rotation.
    backup_count: int
        Number of rotated log files to keep.
    use_json: bool
        If True, use JSON structured logging format.
    console_output: bool
        If True, enable console output handler.
    """
    # Prevent duplicate handlers if configure_logging is called multiple times
    root = logging.getLogger()
    if root.handlers:
        return

    root.setLevel(level)

    # Choose formatter
    if use_json:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

    # File handler
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def setup_audit_logging(log_dir: Path = Path("logs")) -> AuditLogger:
    """Set up audit logging for compliance tracking.

    Args:
        log_dir: Directory for audit logs

    Returns:
        Configured audit logger instance
    """
    audit_log = log_dir / "audit.log"
    return AuditLogger(audit_log)


def setup_performance_logging(log_dir: Path = Path("logs")) -> PerformanceLogger:
    """Set up performance logging for monitoring.

    Args:
        log_dir: Directory for performance logs

    Returns:
        Configured performance logger instance
    """
    perf_log = log_dir / "performance.log"
    return PerformanceLogger(perf_log)


def configure_comprehensive_logging(
    log_dir: Path = Path("logs"),
    level: int = logging.INFO,
    use_json: bool = False,
    console_output: bool = True,
) -> tuple[AuditLogger, PerformanceLogger]:
    """Configure all logging subsystems for TR4C3R.

    Sets up:
    - Standard application logging
    - Audit logging for compliance
    - Performance logging for monitoring

    Args:
        log_dir: Base directory for log files
        level: Logging level for application logs
        use_json: Use JSON structured logging
        console_output: Enable console output

    Returns:
        Tuple of (audit_logger, performance_logger)
    """
    # Configure main application logging
    main_log = log_dir / "tr4c3r.log"
    configure_logging(
        log_file=main_log,
        level=level,
        use_json=use_json,
        console_output=console_output,
    )

    # Set up audit logging
    audit_logger = setup_audit_logging(log_dir)

    # Set up performance logging
    performance_logger = setup_performance_logging(log_dir)

    logger = logging.getLogger(__name__)
    logger.info(
        f"Comprehensive logging configured: "
        f"main={main_log}, audit={log_dir}/audit.log, perf={log_dir}/performance.log"
    )

    return audit_logger, performance_logger

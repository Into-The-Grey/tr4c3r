"""Tests for comprehensive logging infrastructure."""

import json
import logging
import tempfile
import time
from pathlib import Path

import pytest

from src.core.logging_setup import (
    AuditLogger,
    JSONFormatter,
    PerformanceLogger,
    configure_comprehensive_logging,
    configure_logging,
    log_performance,
    setup_audit_logging,
    setup_performance_logging,
    timing_decorator,
)


class TestJSONFormatter:
    """Tests for JSON structured logging formatter."""

    def test_json_formatter_basic(self):
        """Test basic JSON formatting."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.module = "test_module"
        record.funcName = "test_function"

        result = formatter.format(record)
        log_data = json.loads(result)

        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test.logger"
        assert log_data["message"] == "Test message"
        assert log_data["module"] == "test_module"
        assert log_data["function"] == "test_function"
        assert log_data["line"] == 42
        assert "timestamp" in log_data

    def test_json_formatter_with_extra_fields(self):
        """Test JSON formatting with extra fields."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.module = "test_module"
        record.funcName = "test_function"
        record.extra_fields = {"user_id": "test123", "operation": "search"}

        result = formatter.format(record)
        log_data = json.loads(result)

        assert log_data["user_id"] == "test123"
        assert log_data["operation"] == "search"

    def test_json_formatter_with_exception(self):
        """Test JSON formatting with exception info."""
        formatter = JSONFormatter()
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=42,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        record.module = "test_module"
        record.funcName = "test_function"

        result = formatter.format(record)
        log_data = json.loads(result)

        assert "exception" in log_data
        assert "ValueError: Test error" in log_data["exception"]


class TestAuditLogger:
    """Tests for audit logging functionality."""

    def test_audit_logger_initialization(self):
        """Test audit logger initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.log"
            audit_logger = AuditLogger(log_file)

            assert audit_logger.logger.name == "tr4c3r.audit"
            assert audit_logger.logger.level == logging.INFO
            assert not audit_logger.logger.propagate

    def test_audit_logger_log_search(self):
        """Test logging search operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.log"
            audit_logger = AuditLogger(log_file)

            audit_logger.log_search(
                user_id="user123",
                search_type="email",
                identifier="test@example.com",
                purpose="Investigation",
                results_count=5,
            )

            # Read the log file
            with open(log_file) as f:
                log_lines = f.readlines()

            assert len(log_lines) == 1
            log_data = json.loads(log_lines[0])
            assert log_data["event_type"] == "search"
            assert log_data["user_id"] == "user123"
            assert log_data["search_type"] == "email"
            assert log_data["identifier"] == "test@example.com"
            assert log_data["purpose"] == "Investigation"
            assert log_data["results_count"] == 5

    def test_audit_logger_log_export(self):
        """Test logging export operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.log"
            audit_logger = AuditLogger(log_file)

            audit_logger.log_export(
                user_id="user123",
                export_format="JSON",
                data_types=["email", "phone"],
                record_count=10,
            )

            with open(log_file) as f:
                log_lines = f.readlines()

            assert len(log_lines) == 1
            log_data = json.loads(log_lines[0])
            assert log_data["event_type"] == "export"
            assert log_data["export_format"] == "JSON"
            assert log_data["data_types"] == ["email", "phone"]
            assert log_data["record_count"] == 10

    def test_audit_logger_log_api_key_usage(self):
        """Test logging API key usage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.log"
            audit_logger = AuditLogger(log_file)

            audit_logger.log_api_key_usage(
                user_id="user123",
                api_name="haveibeenpwned",
                operation="check_email",
                success=True,
            )

            with open(log_file) as f:
                log_lines = f.readlines()

            assert len(log_lines) == 1
            log_data = json.loads(log_lines[0])
            assert log_data["event_type"] == "api_usage"
            assert log_data["api_name"] == "haveibeenpwned"
            assert log_data["operation"] == "check_email"
            assert log_data["success"] is True


class TestPerformanceLogger:
    """Tests for performance logging functionality."""

    def test_performance_logger_initialization(self):
        """Test performance logger initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "performance.log"
            perf_logger = PerformanceLogger(log_file)

            assert perf_logger.logger.name == "tr4c3r.performance"
            assert perf_logger.logger.level == logging.INFO
            assert not perf_logger.logger.propagate

    def test_performance_logger_log_operation(self):
        """Test logging operation performance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "performance.log"
            perf_logger = PerformanceLogger(log_file)

            perf_logger.log_operation(
                operation="database_query",
                duration_ms=125.5,
                success=True,
                metadata={"query_type": "search", "rows": 100},
            )

            with open(log_file) as f:
                log_lines = f.readlines()

            assert len(log_lines) == 1
            log_data = json.loads(log_lines[0])
            assert log_data["event_type"] == "performance"
            assert log_data["operation"] == "database_query"
            assert log_data["duration_ms"] == 125.5
            assert log_data["success"] is True
            assert log_data["query_type"] == "search"
            assert log_data["rows"] == 100


class TestTimingDecorator:
    """Tests for timing decorator."""

    def test_timing_decorator_success(self, caplog):
        """Test timing decorator on successful function."""

        @timing_decorator
        def test_function():
            time.sleep(0.01)
            return "success"

        with caplog.at_level(logging.DEBUG):
            result = test_function()

        assert result == "success"
        assert "test_function took" in caplog.text
        assert "success=True" in caplog.text

    def test_timing_decorator_exception(self, caplog):
        """Test timing decorator on function that raises exception."""

        @timing_decorator
        def test_function():
            time.sleep(0.01)
            raise ValueError("Test error")

        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ValueError):
                test_function()

        assert "test_function took" in caplog.text
        assert "success=False" in caplog.text


class TestLogPerformance:
    """Tests for log_performance context manager."""

    def test_log_performance_success(self, caplog):
        """Test log_performance context manager with successful operation."""
        with caplog.at_level(logging.INFO):
            with log_performance("test_operation"):
                time.sleep(0.01)

        assert "test_operation completed" in caplog.text
        assert "success=True" in caplog.text

    def test_log_performance_exception(self, caplog):
        """Test log_performance context manager with exception."""
        with caplog.at_level(logging.INFO):
            with pytest.raises(ValueError):
                with log_performance("test_operation"):
                    time.sleep(0.01)
                    raise ValueError("Test error")

        assert "test_operation completed" in caplog.text
        assert "success=False" in caplog.text

    def test_log_performance_custom_logger(self, caplog):
        """Test log_performance with custom logger."""
        custom_logger = logging.getLogger("custom")

        with caplog.at_level(logging.INFO):
            with log_performance("test_operation", logger=custom_logger):
                time.sleep(0.01)

        assert "custom" in caplog.text
        assert "test_operation completed" in caplog.text


class TestConfigureLogging:
    """Tests for logging configuration functions."""

    def test_configure_logging_basic(self):
        """Test basic logging configuration."""
        # Clear existing handlers
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            configure_logging(log_file=log_file)

            # Verify handlers were added
            assert len(root.handlers) == 2  # Console + file
            assert root.level == logging.INFO

    def test_configure_logging_json_format(self):
        """Test logging configuration with JSON format."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            configure_logging(log_file=log_file, use_json=True)

            # Log a message and verify JSON format
            logging.info("Test message")

            with open(log_file) as f:
                log_line = f.readline()

            log_data = json.loads(log_line)
            assert log_data["message"] == "Test message"
            assert "timestamp" in log_data

    def test_configure_logging_no_console(self):
        """Test logging configuration without console output."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            configure_logging(log_file=log_file, console_output=False)

            # Should only have file handler
            assert len(root.handlers) == 1

    def test_configure_logging_prevents_duplicates(self):
        """Test that configure_logging prevents duplicate handlers."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            configure_logging(log_file=log_file)
            initial_count = len(root.handlers)

            # Call again - should not add more handlers
            configure_logging(log_file=log_file)
            assert len(root.handlers) == initial_count


class TestSetupHelpers:
    """Tests for logging setup helper functions."""

    def test_setup_audit_logging(self):
        """Test setup_audit_logging helper."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            audit_logger = setup_audit_logging(log_dir)

            assert isinstance(audit_logger, AuditLogger)
            assert audit_logger.logger.name == "tr4c3r.audit"

    def test_setup_performance_logging(self):
        """Test setup_performance_logging helper."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            perf_logger = setup_performance_logging(log_dir)

            assert isinstance(perf_logger, PerformanceLogger)
            assert perf_logger.logger.name == "tr4c3r.performance"

    def test_configure_comprehensive_logging(self):
        """Test comprehensive logging configuration."""
        # Clear root logger
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            audit_logger, perf_logger = configure_comprehensive_logging(log_dir)

            # Verify all loggers were set up
            assert isinstance(audit_logger, AuditLogger)
            assert isinstance(perf_logger, PerformanceLogger)

            # Verify log files were created
            assert (log_dir / "tr4c3r.log").exists()
            assert (log_dir / "audit.log").exists()
            assert (log_dir / "performance.log").exists()

    def test_configure_comprehensive_logging_json(self):
        """Test comprehensive logging with JSON format."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            audit_logger, perf_logger = configure_comprehensive_logging(log_dir, use_json=True)

            # Log a message and verify JSON format
            logging.info("Test message")

            with open(log_dir / "tr4c3r.log") as f:
                log_line = f.readline()

            log_data = json.loads(log_line)
            assert "message" in log_data
            assert "timestamp" in log_data


class TestIntegrationScenarios:
    """Integration tests for logging infrastructure."""

    def test_full_logging_workflow(self):
        """Test complete logging workflow with all components."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            audit_logger, perf_logger = configure_comprehensive_logging(log_dir, use_json=True)

            # Log various operations
            audit_logger.log_search(
                user_id="user123",
                search_type="email",
                identifier="test@example.com",
                purpose="Testing",
                results_count=3,
            )

            perf_logger.log_operation(operation="test_op", duration_ms=100.5, success=True)

            logging.info("Application started")

            # Verify all log files exist and have content
            assert (log_dir / "tr4c3r.log").stat().st_size > 0
            assert (log_dir / "audit.log").stat().st_size > 0
            assert (log_dir / "performance.log").stat().st_size > 0

            # Verify JSON format
            with open(log_dir / "audit.log") as f:
                audit_data = json.loads(f.readline())
            assert audit_data["event_type"] == "search"

            with open(log_dir / "performance.log") as f:
                perf_data = json.loads(f.readline())
            assert perf_data["event_type"] == "performance"

    def test_logging_with_timing_decorator(self):
        """Test integration of logging with timing decorator."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            configure_comprehensive_logging(log_dir, level=logging.DEBUG)

            @timing_decorator
            def sample_operation():
                time.sleep(0.01)
                return "completed"

            result = sample_operation()
            assert result == "completed"

            # Verify log was written
            with open(log_dir / "tr4c3r.log") as f:
                log_content = f.read()
            assert "sample_operation took" in log_content

    def test_logging_with_context_manager(self):
        """Test integration of logging with context manager."""
        root = logging.getLogger()
        root.handlers.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            configure_comprehensive_logging(log_dir)

            with log_performance("database_query"):
                time.sleep(0.01)

            # Verify log was written
            with open(log_dir / "tr4c3r.log") as f:
                log_content = f.read()
            assert "database_query completed" in log_content
            assert "success=True" in log_content

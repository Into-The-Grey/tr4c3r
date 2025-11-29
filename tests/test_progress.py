"""Tests for the progress reporting module."""

import pytest
import io
import time
from unittest.mock import MagicMock

from src.core.progress import (
    ProgressUpdate,
    ProgressReporter,
    NullProgressReporter,
    LoggingProgressReporter,
    ConsoleProgressReporter,
    CallbackProgressReporter,
    ProgressTracker,
    get_progress_reporter,
)


class TestProgressUpdate:
    """Tests for ProgressUpdate dataclass."""

    def test_init(self):
        """Test initialization."""
        update = ProgressUpdate(current=5, total=10, message="Testing")
        assert update.current == 5
        assert update.total == 10
        assert update.message == "Testing"

    def test_percentage(self):
        """Test percentage calculation."""
        update = ProgressUpdate(current=3, total=10)
        assert update.percentage == 30.0

    def test_percentage_zero_total(self):
        """Test percentage with zero total."""
        update = ProgressUpdate(current=0, total=0)
        assert update.percentage == 0.0

    def test_eta_seconds(self):
        """Test ETA calculation."""
        update = ProgressUpdate(current=5, total=10, elapsed_seconds=10.0)
        eta = update.eta_seconds
        assert eta is not None
        assert eta == pytest.approx(10.0, rel=0.1)

    def test_eta_no_progress(self):
        """Test ETA when no progress made."""
        update = ProgressUpdate(current=0, total=10, elapsed_seconds=0.0)
        assert update.eta_seconds is None


class TestNullProgressReporter:
    """Tests for NullProgressReporter."""

    def test_all_methods_work(self):
        """Test that all methods work without error."""
        reporter = NullProgressReporter()

        # These should all work silently
        reporter.start(100, "Test")
        reporter.update(10, "Progress")
        reporter.error("Error")
        reporter.finish("Done")


class TestLoggingProgressReporter:
    """Tests for LoggingProgressReporter."""

    def test_start(self, caplog):
        """Test start logging."""
        reporter = LoggingProgressReporter()
        reporter.start(100, "Test task")

        assert reporter.total == 100
        assert reporter.current == 0
        assert reporter.description == "Test task"

    def test_update(self):
        """Test update."""
        reporter = LoggingProgressReporter()
        reporter.start(100, "Test")
        reporter.update(10, "Progress")

        assert reporter.current == 10

    def test_error(self):
        """Test error recording."""
        reporter = LoggingProgressReporter()
        reporter.start(100, "Test")
        reporter.error("Something went wrong")

        assert reporter.errors == 1

    def test_finish(self):
        """Test finish."""
        reporter = LoggingProgressReporter()
        reporter.start(100, "Test")
        reporter.update(100)
        reporter.finish("Complete")

        # Check state is updated
        assert reporter.current == 100


class TestConsoleProgressReporter:
    """Tests for ConsoleProgressReporter."""

    def test_init(self):
        """Test initialization."""
        output = io.StringIO()
        reporter = ConsoleProgressReporter(width=50, file=output)

        assert reporter.width == 50
        assert reporter.file == output

    def test_format_time_short(self):
        """Test time formatting for short durations."""
        reporter = ConsoleProgressReporter()
        formatted = reporter._format_time(90)
        assert formatted == "01:30"

    def test_format_time_long(self):
        """Test time formatting for long durations."""
        reporter = ConsoleProgressReporter()
        formatted = reporter._format_time(3665)  # 1:01:05
        assert formatted == "01:01:05"

    def test_render_bar_unicode(self):
        """Test progress bar rendering with unicode."""
        reporter = ConsoleProgressReporter(width=10, use_unicode=True)
        bar = reporter._render_bar(50)
        assert "█" in bar
        assert "░" in bar

    def test_render_bar_ascii(self):
        """Test progress bar rendering with ASCII."""
        reporter = ConsoleProgressReporter(width=10, use_unicode=False)
        bar = reporter._render_bar(50)
        assert "#" in bar
        assert "-" in bar

    def test_start_output(self):
        """Test start produces output."""
        output = io.StringIO()
        reporter = ConsoleProgressReporter(file=output)
        reporter.start(100, "Test")

        content = output.getvalue()
        assert "Test" in content
        assert "0%" in content

    def test_update_output(self):
        """Test update produces output."""
        output = io.StringIO()
        reporter = ConsoleProgressReporter(file=output)
        reporter.start(100, "Test")
        reporter.update(50)

        content = output.getvalue()
        assert "50" in content

    def test_finish_output(self):
        """Test finish produces output with newline."""
        output = io.StringIO()
        reporter = ConsoleProgressReporter(file=output)
        reporter.start(100, "Test")
        reporter.finish("Done")

        content = output.getvalue()
        assert "Done" in content
        assert content.endswith("\n")


class TestCallbackProgressReporter:
    """Tests for CallbackProgressReporter."""

    def test_callback_called(self):
        """Test that callback is called."""
        updates = []
        reporter = CallbackProgressReporter(callback=updates.append)

        reporter.start(100, "Test")
        reporter.update(10, "Progress")
        reporter.finish("Done")

        assert len(updates) == 3
        assert updates[0].message == "Started"
        assert updates[1].current == 10
        assert "Completed" in updates[2].message

    def test_callback_receives_update(self):
        """Test callback receives ProgressUpdate objects."""
        last_update = None

        def capture(update):
            nonlocal last_update
            last_update = update

        reporter = CallbackProgressReporter(callback=capture)
        reporter.start(100, "Test")
        reporter.update(50, "Halfway")

        assert isinstance(last_update, ProgressUpdate)
        assert last_update.current == 50
        assert last_update.total == 100


class TestProgressTracker:
    """Tests for ProgressTracker."""

    def test_register_module(self):
        """Test registering modules."""
        reporter = NullProgressReporter()
        tracker = ProgressTracker(reporter=reporter)

        tracker.register_module("module1", 10)
        tracker.register_module("module2", 20)

        assert tracker.modules["module1"] == 10
        assert tracker.modules["module2"] == 20

    def test_update_module(self):
        """Test updating module progress."""
        reporter = NullProgressReporter()
        tracker = ProgressTracker(reporter=reporter)

        tracker.register_module("module1", 10)
        tracker.update_module("module1", 5)

        assert tracker.completed["module1"] == 5

    def test_module_error(self):
        """Test recording module errors."""
        reporter = MagicMock(spec=ProgressReporter)
        tracker = ProgressTracker(reporter=reporter)

        tracker.register_module("module1", 10)
        tracker.module_error("module1")

        assert tracker.errors["module1"] == 1
        reporter.error.assert_called_once()

    def test_finish(self):
        """Test finishing tracking."""
        reporter = MagicMock(spec=ProgressReporter)
        tracker = ProgressTracker(reporter=reporter)

        tracker.register_module("module1", 10)
        tracker.update_module("module1", 10)
        tracker.finish()

        reporter.finish.assert_called_once()


class TestGetProgressReporter:
    """Tests for get_progress_reporter factory function."""

    def test_none_style(self):
        """Test 'none' style returns NullProgressReporter."""
        reporter = get_progress_reporter("none")
        assert isinstance(reporter, NullProgressReporter)

    def test_logging_style(self):
        """Test 'logging' style returns LoggingProgressReporter."""
        reporter = get_progress_reporter("logging")
        assert isinstance(reporter, LoggingProgressReporter)

    def test_console_style(self):
        """Test 'console' style returns ConsoleProgressReporter."""
        reporter = get_progress_reporter("console")
        assert isinstance(reporter, ConsoleProgressReporter)

    def test_auto_style(self):
        """Test 'auto' style returns appropriate reporter."""
        reporter = get_progress_reporter("auto")
        assert isinstance(reporter, ProgressReporter)


class TestProgressReporterEdgeCases:
    """Edge case tests for progress reporters."""

    def test_update_beyond_total(self):
        """Test updating beyond total."""
        reporter = LoggingProgressReporter()
        reporter.start(100, "Test")
        reporter.update(150)  # More than total

        assert reporter.current == 150  # Should still work

    def test_negative_update(self):
        """Test negative update increment."""
        reporter = LoggingProgressReporter()
        reporter.start(100, "Test")
        reporter.update(50)
        reporter.update(-10)  # Decrease

        assert reporter.current == 40

    def test_empty_description(self):
        """Test with empty description."""
        output = io.StringIO()
        reporter = ConsoleProgressReporter(file=output)
        reporter.start(100, "")

        assert reporter.description == "Progress"  # Default

    def test_zero_total(self):
        """Test with zero total items."""
        reporter = LoggingProgressReporter()
        reporter.start(0, "Test")
        reporter.update(0)
        reporter.finish()

        # Should not crash
        assert reporter.total == 0

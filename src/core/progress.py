"""Progress reporting for TR4C3R.

This module provides progress tracking and reporting for long-running
operations like multi-site searches.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProgressUpdate:
    """Represents a progress update."""

    current: int
    total: int
    message: str = ""
    module: str = ""
    elapsed_seconds: float = 0.0
    errors: int = 0

    @property
    def percentage(self) -> float:
        """Calculate percentage complete."""
        return (self.current / self.total * 100) if self.total > 0 else 0.0

    @property
    def eta_seconds(self) -> Optional[float]:
        """Estimate time remaining."""
        if self.current == 0 or self.elapsed_seconds == 0:
            return None
        rate = self.current / self.elapsed_seconds
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else None


class ProgressReporter(ABC):
    """Abstract base class for progress reporters."""

    @abstractmethod
    def start(self, total: int, description: str = "") -> None:
        """Start progress tracking."""
        pass

    @abstractmethod
    def update(self, increment: int = 1, message: str = "") -> None:
        """Update progress."""
        pass

    @abstractmethod
    def error(self, message: str = "") -> None:
        """Report an error."""
        pass

    @abstractmethod
    def finish(self, message: str = "") -> None:
        """Finish progress tracking."""
        pass


class NullProgressReporter(ProgressReporter):
    """Progress reporter that does nothing (for silent operation)."""

    def start(self, total: int, description: str = "") -> None:
        pass

    def update(self, increment: int = 1, message: str = "") -> None:
        pass

    def error(self, message: str = "") -> None:
        pass

    def finish(self, message: str = "") -> None:
        pass


class LoggingProgressReporter(ProgressReporter):
    """Progress reporter that logs updates."""

    def __init__(self, log_level: int = logging.INFO) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.log_level = log_level
        self.total = 0
        self.current = 0
        self.description = ""
        self.start_time = 0.0
        self.errors = 0

    def start(self, total: int, description: str = "") -> None:
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.errors = 0
        self.logger.log(self.log_level, "Starting: %s (0/%d)", description, total)

    def update(self, increment: int = 1, message: str = "") -> None:
        self.current += increment
        pct = (self.current / self.total * 100) if self.total > 0 else 0
        msg = f"{self.description}: {self.current}/{self.total} ({pct:.1f}%)"
        if message:
            msg += f" - {message}"
        self.logger.log(self.log_level, msg)

    def error(self, message: str = "") -> None:
        self.errors += 1
        self.logger.warning("Error during %s: %s", self.description, message)

    def finish(self, message: str = "") -> None:
        elapsed = time.time() - self.start_time
        msg = f"Completed: {self.description} ({self.current}/{self.total}) in {elapsed:.2f}s"
        if self.errors:
            msg += f" with {self.errors} errors"
        if message:
            msg += f" - {message}"
        self.logger.log(self.log_level, msg)


class ConsoleProgressReporter(ProgressReporter):
    """Progress reporter for console output with progress bar."""

    def __init__(
        self,
        width: int = 40,
        use_unicode: bool = True,
        file: Any = None,
    ) -> None:
        self.width = width
        self.use_unicode = use_unicode
        self.file = file or sys.stderr
        self.total = 0
        self.current = 0
        self.description = ""
        self.start_time = 0.0
        self.errors = 0
        self._last_line_len = 0

    def _format_time(self, seconds: float) -> str:
        """Format seconds as MM:SS or HH:MM:SS."""
        if seconds < 3600:
            return f"{int(seconds // 60):02d}:{int(seconds % 60):02d}"
        return (
            f"{int(seconds // 3600):02d}:{int((seconds % 3600) // 60):02d}:{int(seconds % 60):02d}"
        )

    def _render_bar(self, percentage: float) -> str:
        """Render a progress bar."""
        filled = int(self.width * percentage / 100)
        empty = self.width - filled

        if self.use_unicode:
            bar = "█" * filled + "░" * empty
        else:
            bar = "#" * filled + "-" * empty

        return f"[{bar}]"

    def _write(self, text: str, end: str = "") -> None:
        """Write to output, clearing previous line."""
        # Clear previous line if needed
        clear = " " * max(0, self._last_line_len - len(text))
        self.file.write(f"\r{text}{clear}{end}")
        self.file.flush()
        self._last_line_len = len(text)

    def start(self, total: int, description: str = "") -> None:
        self.total = total
        self.current = 0
        self.description = description[:20] if description else "Progress"
        self.start_time = time.time()
        self.errors = 0
        self._write(f"{self.description}: {self._render_bar(0)} 0%")

    def update(self, increment: int = 1, message: str = "") -> None:
        self.current += increment
        pct = (self.current / self.total * 100) if self.total > 0 else 0
        elapsed = time.time() - self.start_time

        # Calculate ETA
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta = f" ETA {self._format_time(remaining)}"
        else:
            eta = ""

        bar = self._render_bar(pct)
        status = f"{self.description}: {bar} {pct:5.1f}% ({self.current}/{self.total}){eta}"
        self._write(status)

    def error(self, message: str = "") -> None:
        self.errors += 1
        # Don't interrupt the progress bar for errors

    def finish(self, message: str = "") -> None:
        elapsed = time.time() - self.start_time
        pct = (self.current / self.total * 100) if self.total > 0 else 100

        bar = self._render_bar(pct)
        status = f"{self.description}: {bar} {pct:.1f}% - Done in {self._format_time(elapsed)}"
        if self.errors:
            status += f" ({self.errors} errors)"
        if message:
            status += f" - {message}"

        self._write(status, end="\n")


class TqdmProgressReporter(ProgressReporter):
    """Progress reporter using tqdm (if available)."""

    def __init__(self, **tqdm_kwargs: Any) -> None:
        self.tqdm_kwargs = tqdm_kwargs
        self._pbar: Any = None
        self.errors = 0

    def start(self, total: int, description: str = "") -> None:
        try:
            from tqdm import tqdm

            self._pbar = tqdm(total=total, desc=description, **self.tqdm_kwargs)
            self.errors = 0
        except ImportError:
            # Fall back to console progress
            logger.warning("tqdm not available, using console progress")
            self._fallback = ConsoleProgressReporter()
            self._fallback.start(total, description)

    def update(self, increment: int = 1, message: str = "") -> None:
        if self._pbar is not None:
            self._pbar.update(increment)
            if message:
                self._pbar.set_postfix_str(message)
        elif hasattr(self, "_fallback"):
            self._fallback.update(increment, message)

    def error(self, message: str = "") -> None:
        self.errors += 1

    def finish(self, message: str = "") -> None:
        if self._pbar is not None:
            if message:
                self._pbar.set_postfix_str(message)
            self._pbar.close()
            self._pbar = None
        elif hasattr(self, "_fallback"):
            self._fallback.finish(message)


class CallbackProgressReporter(ProgressReporter):
    """Progress reporter that calls a callback function."""

    def __init__(
        self,
        callback: Callable[[ProgressUpdate], None],
    ) -> None:
        self.callback = callback
        self.total = 0
        self.current = 0
        self.description = ""
        self.start_time = 0.0
        self.errors = 0

    def _send_update(self, message: str = "") -> None:
        update = ProgressUpdate(
            current=self.current,
            total=self.total,
            message=message,
            module=self.description,
            elapsed_seconds=time.time() - self.start_time,
            errors=self.errors,
        )
        self.callback(update)

    def start(self, total: int, description: str = "") -> None:
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.errors = 0
        self._send_update("Started")

    def update(self, increment: int = 1, message: str = "") -> None:
        self.current += increment
        self._send_update(message)

    def error(self, message: str = "") -> None:
        self.errors += 1
        self._send_update(f"Error: {message}")

    def finish(self, message: str = "") -> None:
        self._send_update(f"Completed: {message}" if message else "Completed")


@dataclass
class ProgressTracker:
    """Tracks progress across multiple concurrent operations."""

    reporter: ProgressReporter
    modules: Dict[str, int] = field(default_factory=dict)
    completed: Dict[str, int] = field(default_factory=dict)
    errors: Dict[str, int] = field(default_factory=dict)
    start_time: float = 0.0

    def __post_init__(self) -> None:
        self.start_time = time.time()

    def register_module(self, name: str, total: int) -> None:
        """Register a module with its total work items."""
        self.modules[name] = total
        self.completed[name] = 0
        self.errors[name] = 0

    def update_module(self, name: str, completed: int = 1) -> None:
        """Update progress for a module."""
        self.completed[name] = self.completed.get(name, 0) + completed
        self._report()

    def module_error(self, name: str) -> None:
        """Record an error for a module."""
        self.errors[name] = self.errors.get(name, 0) + 1
        self.reporter.error(f"{name} error")

    def _report(self) -> None:
        """Report overall progress."""
        total_items = sum(self.modules.values())
        completed_items = sum(self.completed.values())
        self.reporter.update(
            0,
            f"{completed_items}/{total_items} items from {len(self.modules)} modules",
        )

    def finish(self) -> None:
        """Finish tracking."""
        elapsed = time.time() - self.start_time
        total_items = sum(self.modules.values())
        completed_items = sum(self.completed.values())
        total_errors = sum(self.errors.values())
        self.reporter.finish(
            f"{completed_items}/{total_items} items in {elapsed:.1f}s " f"({total_errors} errors)"
        )


def get_progress_reporter(
    style: str = "auto",
    **kwargs: Any,
) -> ProgressReporter:
    """Get a progress reporter based on style.

    Args:
        style: One of "auto", "tqdm", "console", "logging", "none"
        **kwargs: Additional arguments passed to the reporter

    Returns:
        ProgressReporter instance
    """
    if style == "none":
        return NullProgressReporter()

    if style == "logging":
        return LoggingProgressReporter(**kwargs)

    if style == "console":
        return ConsoleProgressReporter(**kwargs)

    if style == "tqdm":
        return TqdmProgressReporter(**kwargs)

    # Auto-detect best option
    if sys.stdout.isatty():
        try:
            from tqdm import tqdm

            return TqdmProgressReporter(**kwargs)
        except ImportError:
            return ConsoleProgressReporter(**kwargs)
    else:
        return LoggingProgressReporter(**kwargs)

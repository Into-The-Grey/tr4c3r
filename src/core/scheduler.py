"""Scheduled and automated search functionality for TR4C3R.

This module provides the ability to schedule recurring searches for monitoring
targets over time. It supports various scheduling patterns (cron-like, intervals),
persistence of schedules, and notification when new information appears.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union
import re

logger = logging.getLogger(__name__)


class ScheduleType(Enum):
    """Types of scheduling patterns."""

    INTERVAL = "interval"  # Every N minutes/hours/days
    DAILY = "daily"  # Once per day at specific time
    WEEKLY = "weekly"  # Once per week on specific day
    CRON = "cron"  # Cron-like expression
    ONCE = "once"  # Run once at specific time


class SearchType(Enum):
    """Types of searches that can be scheduled."""

    USERNAME = "username"
    EMAIL = "email"
    NAME = "name"
    PHONE = "phone"
    ALL = "all"


class ScheduleStatus(Enum):
    """Status of a scheduled search."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class ScheduleConfig:
    """Configuration for a scheduled search."""

    schedule_type: ScheduleType
    interval_minutes: Optional[int] = None  # For INTERVAL type
    time_of_day: Optional[str] = None  # HH:MM for DAILY/WEEKLY
    day_of_week: Optional[int] = None  # 0-6 for WEEKLY (0=Monday)
    cron_expression: Optional[str] = None  # For CRON type
    run_at: Optional[datetime] = None  # For ONCE type
    timezone: str = "UTC"

    def get_next_run(self, from_time: Optional[datetime] = None) -> datetime:
        """Calculate the next run time based on schedule configuration.

        Args:
            from_time: Base time for calculation (default: now)

        Returns:
            Next scheduled run time
        """
        now = from_time or datetime.now(timezone.utc)

        if self.schedule_type == ScheduleType.INTERVAL:
            if not self.interval_minutes:
                raise ValueError("interval_minutes required for INTERVAL schedule")
            return now + timedelta(minutes=self.interval_minutes)

        elif self.schedule_type == ScheduleType.DAILY:
            if not self.time_of_day:
                raise ValueError("time_of_day required for DAILY schedule")
            hour, minute = map(int, self.time_of_day.split(":"))
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run

        elif self.schedule_type == ScheduleType.WEEKLY:
            if not self.time_of_day or self.day_of_week is None:
                raise ValueError("time_of_day and day_of_week required for WEEKLY schedule")
            hour, minute = map(int, self.time_of_day.split(":"))
            days_ahead = self.day_of_week - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            next_run += timedelta(days=days_ahead)
            return next_run

        elif self.schedule_type == ScheduleType.ONCE:
            if not self.run_at:
                raise ValueError("run_at required for ONCE schedule")
            return self.run_at

        elif self.schedule_type == ScheduleType.CRON:
            # Simple cron parsing for common patterns
            return self._parse_cron(now)

        raise ValueError(f"Unknown schedule type: {self.schedule_type}")

    def _parse_cron(self, from_time: datetime) -> datetime:
        """Parse cron expression and get next run time.

        Supports simplified cron: minute hour day month weekday
        """
        if not self.cron_expression:
            raise ValueError("cron_expression required for CRON schedule")

        parts = self.cron_expression.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 parts: min hour day month weekday")

        minute, hour, day, month, weekday = parts

        # For now, support simple patterns
        next_run = from_time + timedelta(minutes=1)

        # Try to find next matching time (up to 366 days ahead)
        for _ in range(366 * 24 * 60):
            if self._cron_matches(next_run, minute, hour, day, month, weekday):
                return next_run
            next_run += timedelta(minutes=1)

        raise ValueError("Could not find next cron run time within a year")

    def _cron_matches(
        self, dt: datetime, minute: str, hour: str, day: str, month: str, weekday: str
    ) -> bool:
        """Check if datetime matches cron pattern."""

        def matches_field(value: int, pattern: str) -> bool:
            if pattern == "*":
                return True
            if pattern.isdigit():
                return value == int(pattern)
            if "/" in pattern:
                _, step = pattern.split("/")
                return value % int(step) == 0
            if "-" in pattern:
                start, end = map(int, pattern.split("-"))
                return start <= value <= end
            if "," in pattern:
                return value in [int(x) for x in pattern.split(",")]
            return False

        return (
            matches_field(dt.minute, minute)
            and matches_field(dt.hour, hour)
            and matches_field(dt.day, day)
            and matches_field(dt.month, month)
            and matches_field(dt.weekday(), weekday)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "schedule_type": self.schedule_type.value,
            "interval_minutes": self.interval_minutes,
            "time_of_day": self.time_of_day,
            "day_of_week": self.day_of_week,
            "cron_expression": self.cron_expression,
            "run_at": self.run_at.isoformat() if self.run_at else None,
            "timezone": self.timezone,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduleConfig":
        """Create from dictionary."""
        return cls(
            schedule_type=ScheduleType(data["schedule_type"]),
            interval_minutes=data.get("interval_minutes"),
            time_of_day=data.get("time_of_day"),
            day_of_week=data.get("day_of_week"),
            cron_expression=data.get("cron_expression"),
            run_at=datetime.fromisoformat(data["run_at"]) if data.get("run_at") else None,
            timezone=data.get("timezone", "UTC"),
        )


@dataclass
class ScheduledSearch:
    """A scheduled search job."""

    id: str
    name: str
    search_type: SearchType
    query: str
    schedule: ScheduleConfig
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    max_runs: Optional[int] = None  # None = unlimited
    expires_at: Optional[datetime] = None
    notify_on_new: bool = True
    notify_channels: List[str] = field(default_factory=list)  # email, slack, webhook
    options: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.next_run is None:
            self.next_run = self.schedule.get_next_run()

    def is_due(self, now: Optional[datetime] = None) -> bool:
        """Check if this search is due to run."""
        if self.status != ScheduleStatus.ACTIVE:
            return False

        now = now or datetime.now(timezone.utc)

        if self.expires_at and now >= self.expires_at:
            return False

        if self.max_runs and self.run_count >= self.max_runs:
            return False

        if self.next_run and now >= self.next_run:
            return True

        return False

    def update_after_run(self) -> None:
        """Update schedule after a run completes."""
        self.last_run = datetime.now(timezone.utc)
        self.run_count += 1

        # Check if we should stop
        if self.max_runs and self.run_count >= self.max_runs:
            self.status = ScheduleStatus.COMPLETED
            self.next_run = None
        elif self.schedule.schedule_type == ScheduleType.ONCE:
            self.status = ScheduleStatus.COMPLETED
            self.next_run = None
        else:
            self.next_run = self.schedule.get_next_run(self.last_run)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "search_type": self.search_type.value,
            "query": self.query,
            "schedule": self.schedule.to_dict(),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "max_runs": self.max_runs,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "notify_on_new": self.notify_on_new,
            "notify_channels": self.notify_channels,
            "options": self.options,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledSearch":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            search_type=SearchType(data["search_type"]),
            query=data["query"],
            schedule=ScheduleConfig.from_dict(data["schedule"]),
            status=ScheduleStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            run_count=data.get("run_count", 0),
            max_runs=data.get("max_runs"),
            expires_at=(
                datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
            ),
            notify_on_new=data.get("notify_on_new", True),
            notify_channels=data.get("notify_channels", []),
            options=data.get("options", {}),
            tags=data.get("tags", []),
        )


@dataclass
class SearchRun:
    """Record of a scheduled search execution."""

    id: str
    schedule_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, success, failed
    result_count: int = 0
    new_result_count: int = 0
    error_message: Optional[str] = None
    result_hash: Optional[str] = None  # Hash of results for change detection

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "schedule_id": self.schedule_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "result_count": self.result_count,
            "new_result_count": self.new_result_count,
            "error_message": self.error_message,
            "result_hash": self.result_hash,
        }


class ScheduleStore:
    """Persistent storage for scheduled searches using SQLite."""

    def __init__(self, db_path: str = "tr4c3r_schedules.db"):
        """Initialize the schedule store.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.logger = logging.getLogger(self.__class__.__name__)
        self._initialize_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scheduled searches table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scheduled_searches (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    search_type TEXT NOT NULL,
                    query TEXT NOT NULL,
                    schedule_data TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    last_run TEXT,
                    next_run TEXT,
                    run_count INTEGER DEFAULT 0,
                    max_runs INTEGER,
                    expires_at TEXT,
                    notify_on_new INTEGER DEFAULT 1,
                    notify_channels TEXT,
                    options TEXT,
                    tags TEXT
                )
            """
            )

            # Search runs history table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS search_runs (
                    id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    result_count INTEGER DEFAULT 0,
                    new_result_count INTEGER DEFAULT 0,
                    error_message TEXT,
                    result_hash TEXT,
                    FOREIGN KEY (schedule_id) REFERENCES scheduled_searches(id)
                )
            """
            )

            # Result hashes for change detection
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS result_snapshots (
                    schedule_id TEXT NOT NULL,
                    result_hash TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    result_count INTEGER,
                    PRIMARY KEY (schedule_id, result_hash)
                )
            """
            )

            # Indexes
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_schedules_status ON scheduled_searches(status)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON scheduled_searches(next_run)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_schedule ON search_runs(schedule_id)"
            )

            self.logger.info(f"Schedule store initialized: {self.db_path}")

    def save_schedule(self, schedule: ScheduledSearch) -> None:
        """Save or update a scheduled search."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO scheduled_searches (
                    id, name, search_type, query, schedule_data, status,
                    created_at, last_run, next_run, run_count, max_runs,
                    expires_at, notify_on_new, notify_channels, options, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    schedule.id,
                    schedule.name,
                    schedule.search_type.value,
                    schedule.query,
                    json.dumps(schedule.schedule.to_dict()),
                    schedule.status.value,
                    schedule.created_at.isoformat(),
                    schedule.last_run.isoformat() if schedule.last_run else None,
                    schedule.next_run.isoformat() if schedule.next_run else None,
                    schedule.run_count,
                    schedule.max_runs,
                    schedule.expires_at.isoformat() if schedule.expires_at else None,
                    1 if schedule.notify_on_new else 0,
                    json.dumps(schedule.notify_channels),
                    json.dumps(schedule.options),
                    json.dumps(schedule.tags),
                ),
            )
            self.logger.debug(f"Saved schedule: {schedule.id}")

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledSearch]:
        """Get a scheduled search by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scheduled_searches WHERE id = ?", (schedule_id,))
            row = cursor.fetchone()

            if row:
                return self._row_to_schedule(row)
            return None

    def get_all_schedules(self, status: Optional[ScheduleStatus] = None) -> List[ScheduledSearch]:
        """Get all scheduled searches, optionally filtered by status."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if status:
                cursor.execute(
                    "SELECT * FROM scheduled_searches WHERE status = ? ORDER BY next_run",
                    (status.value,),
                )
            else:
                cursor.execute("SELECT * FROM scheduled_searches ORDER BY next_run")

            return [self._row_to_schedule(row) for row in cursor.fetchall()]

    def get_due_schedules(self, now: Optional[datetime] = None) -> List[ScheduledSearch]:
        """Get all schedules that are due to run."""
        now = now or datetime.now(timezone.utc)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM scheduled_searches
                WHERE status = 'active'
                AND next_run <= ?
                AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY next_run
            """,
                (now.isoformat(), now.isoformat()),
            )

            schedules = []
            for row in cursor.fetchall():
                schedule = self._row_to_schedule(row)
                if schedule.is_due(now):
                    schedules.append(schedule)

            return schedules

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a scheduled search."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scheduled_searches WHERE id = ?", (schedule_id,))
            deleted = cursor.rowcount > 0
            if deleted:
                self.logger.info(f"Deleted schedule: {schedule_id}")
            return deleted

    def save_run(self, run: SearchRun) -> None:
        """Save a search run record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO search_runs (
                    id, schedule_id, started_at, completed_at, status,
                    result_count, new_result_count, error_message, result_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    run.id,
                    run.schedule_id,
                    run.started_at.isoformat(),
                    run.completed_at.isoformat() if run.completed_at else None,
                    run.status,
                    run.result_count,
                    run.new_result_count,
                    run.error_message,
                    run.result_hash,
                ),
            )

    def get_runs(self, schedule_id: str, limit: int = 100) -> List[SearchRun]:
        """Get run history for a schedule."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM search_runs
                WHERE schedule_id = ?
                ORDER BY started_at DESC
                LIMIT ?
            """,
                (schedule_id, limit),
            )

            runs = []
            for row in cursor.fetchall():
                runs.append(
                    SearchRun(
                        id=row["id"],
                        schedule_id=row["schedule_id"],
                        started_at=datetime.fromisoformat(row["started_at"]),
                        completed_at=(
                            datetime.fromisoformat(row["completed_at"])
                            if row["completed_at"]
                            else None
                        ),
                        status=row["status"],
                        result_count=row["result_count"],
                        new_result_count=row["new_result_count"],
                        error_message=row["error_message"],
                        result_hash=row["result_hash"],
                    )
                )
            return runs

    def get_last_result_hash(self, schedule_id: str) -> Optional[str]:
        """Get the last result hash for change detection."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT result_hash FROM result_snapshots
                WHERE schedule_id = ?
                ORDER BY captured_at DESC
                LIMIT 1
            """,
                (schedule_id,),
            )
            row = cursor.fetchone()
            return row["result_hash"] if row else None

    def save_result_snapshot(self, schedule_id: str, result_hash: str, result_count: int) -> None:
        """Save a result snapshot for change detection."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO result_snapshots (schedule_id, result_hash, captured_at, result_count)
                VALUES (?, ?, ?, ?)
            """,
                (schedule_id, result_hash, datetime.now(timezone.utc).isoformat(), result_count),
            )

    def _row_to_schedule(self, row: sqlite3.Row) -> ScheduledSearch:
        """Convert a database row to ScheduledSearch object."""
        return ScheduledSearch(
            id=row["id"],
            name=row["name"],
            search_type=SearchType(row["search_type"]),
            query=row["query"],
            schedule=ScheduleConfig.from_dict(json.loads(row["schedule_data"])),
            status=ScheduleStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_run=datetime.fromisoformat(row["last_run"]) if row["last_run"] else None,
            next_run=datetime.fromisoformat(row["next_run"]) if row["next_run"] else None,
            run_count=row["run_count"],
            max_runs=row["max_runs"],
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            notify_on_new=bool(row["notify_on_new"]),
            notify_channels=json.loads(row["notify_channels"]) if row["notify_channels"] else [],
            options=json.loads(row["options"]) if row["options"] else {},
            tags=json.loads(row["tags"]) if row["tags"] else [],
        )


class SearchScheduler:
    """Main scheduler for running scheduled searches."""

    def __init__(
        self,
        store: Optional[ScheduleStore] = None,
        check_interval: int = 60,  # seconds
    ):
        """Initialize the scheduler.

        Args:
            store: Schedule storage (creates default if None)
            check_interval: How often to check for due schedules
        """
        self.store = store or ScheduleStore()
        self.check_interval = check_interval
        self.logger = logging.getLogger(self.__class__.__name__)

        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._search_callback: Optional[Callable] = None
        self._notify_callback: Optional[Callable] = None
        self._lock = asyncio.Lock()

    def set_search_callback(self, callback: Callable) -> None:
        """Set the callback function for executing searches.

        The callback should have signature:
            async def search(search_type: str, query: str, options: dict) -> List[Result]
        """
        self._search_callback = callback

    def set_notify_callback(self, callback: Callable) -> None:
        """Set the callback function for sending notifications.

        The callback should have signature:
            async def notify(schedule: ScheduledSearch, run: SearchRun, new_results: List)
        """
        self._notify_callback = callback

    def create_schedule(
        self,
        name: str,
        search_type: SearchType,
        query: str,
        schedule: ScheduleConfig,
        **kwargs,
    ) -> ScheduledSearch:
        """Create a new scheduled search.

        Args:
            name: Human-readable name for the schedule
            search_type: Type of search to perform
            query: Search query
            schedule: Scheduling configuration
            **kwargs: Additional options (notify_on_new, tags, etc.)

        Returns:
            Created ScheduledSearch object
        """
        import uuid

        scheduled = ScheduledSearch(
            id=str(uuid.uuid4()),
            name=name,
            search_type=search_type,
            query=query,
            schedule=schedule,
            notify_on_new=kwargs.get("notify_on_new", True),
            notify_channels=kwargs.get("notify_channels", []),
            options=kwargs.get("options", {}),
            tags=kwargs.get("tags", []),
            max_runs=kwargs.get("max_runs"),
            expires_at=kwargs.get("expires_at"),
        )

        self.store.save_schedule(scheduled)
        self.logger.info(f"Created schedule: {scheduled.id} - {name}")

        return scheduled

    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a scheduled search."""
        schedule = self.store.get_schedule(schedule_id)
        if schedule:
            schedule.status = ScheduleStatus.PAUSED
            self.store.save_schedule(schedule)
            self.logger.info(f"Paused schedule: {schedule_id}")
            return True
        return False

    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused scheduled search."""
        schedule = self.store.get_schedule(schedule_id)
        if schedule and schedule.status == ScheduleStatus.PAUSED:
            schedule.status = ScheduleStatus.ACTIVE
            schedule.next_run = schedule.schedule.get_next_run()
            self.store.save_schedule(schedule)
            self.logger.info(f"Resumed schedule: {schedule_id}")
            return True
        return False

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a scheduled search."""
        return self.store.delete_schedule(schedule_id)

    def list_schedules(self, status: Optional[ScheduleStatus] = None) -> List[ScheduledSearch]:
        """List all scheduled searches."""
        return self.store.get_all_schedules(status)

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledSearch]:
        """Get a specific scheduled search."""
        return self.store.get_schedule(schedule_id)

    def get_run_history(self, schedule_id: str, limit: int = 100) -> List[SearchRun]:
        """Get run history for a schedule."""
        return self.store.get_runs(schedule_id, limit)

    async def run_schedule_now(self, schedule_id: str) -> Optional[SearchRun]:
        """Manually trigger a scheduled search immediately."""
        schedule = self.store.get_schedule(schedule_id)
        if not schedule:
            return None

        return await self._execute_schedule(schedule)

    async def start(self) -> None:
        """Start the scheduler background loop."""
        if self._running:
            self.logger.warning("Scheduler is already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        self.logger.info("Scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler background loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self.logger.info("Scheduler stopped")

    async def _run_loop(self) -> None:
        """Main scheduler loop that checks for and executes due schedules."""
        self.logger.info(f"Scheduler loop started (check interval: {self.check_interval}s)")

        while self._running:
            try:
                await self._check_and_run_due()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}", exc_info=True)
                await asyncio.sleep(self.check_interval)

    async def _check_and_run_due(self) -> None:
        """Check for and execute any due scheduled searches."""
        async with self._lock:
            due_schedules = self.store.get_due_schedules()

            if due_schedules:
                self.logger.info(f"Found {len(due_schedules)} due schedule(s)")

            for schedule in due_schedules:
                try:
                    await self._execute_schedule(schedule)
                except Exception as e:
                    self.logger.error(f"Failed to execute schedule {schedule.id}: {e}")

    async def _execute_schedule(self, schedule: ScheduledSearch) -> SearchRun:
        """Execute a single scheduled search."""
        import uuid

        self.logger.info(f"Executing schedule: {schedule.name} ({schedule.id})")

        run = SearchRun(
            id=str(uuid.uuid4()),
            schedule_id=schedule.id,
            started_at=datetime.now(timezone.utc),
        )
        self.store.save_run(run)

        try:
            # Execute search
            if self._search_callback:
                results = await self._search_callback(
                    schedule.search_type.value,
                    schedule.query,
                    schedule.options,
                )
            else:
                # No callback set - simulate empty results
                self.logger.warning("No search callback set, returning empty results")
                results = []

            # Calculate result hash for change detection
            result_hash = self._hash_results(results)
            last_hash = self.store.get_last_result_hash(schedule.id)

            # Detect new results
            new_count = 0
            if last_hash and result_hash != last_hash:
                new_count = len(results)  # Simplified - could do more detailed diff
            elif not last_hash:
                new_count = len(results)

            # Update run record
            run.completed_at = datetime.now(timezone.utc)
            run.status = "success"
            run.result_count = len(results)
            run.new_result_count = new_count
            run.result_hash = result_hash
            self.store.save_run(run)

            # Save snapshot
            self.store.save_result_snapshot(schedule.id, result_hash, len(results))

            # Update schedule
            schedule.update_after_run()
            self.store.save_schedule(schedule)

            # Send notifications if there are new results
            if new_count > 0 and schedule.notify_on_new and self._notify_callback:
                await self._notify_callback(schedule, run, results)

            self.logger.info(
                f"Schedule {schedule.name} completed: {len(results)} results, " f"{new_count} new"
            )

        except Exception as e:
            run.completed_at = datetime.now(timezone.utc)
            run.status = "failed"
            run.error_message = str(e)
            self.store.save_run(run)

            schedule.status = ScheduleStatus.FAILED
            self.store.save_schedule(schedule)

            self.logger.error(f"Schedule {schedule.name} failed: {e}")

        return run

    def _hash_results(self, results: List[Any]) -> str:
        """Create a hash of search results for change detection."""
        if not results:
            return hashlib.md5(b"empty").hexdigest()

        # Sort and serialize results for consistent hashing
        try:
            serialized = json.dumps(
                [
                    r.to_dict() if hasattr(r, "to_dict") else str(r)
                    for r in sorted(results, key=lambda x: str(getattr(x, "identifier", x)))
                ],
                sort_keys=True,
            )
            return hashlib.md5(serialized.encode()).hexdigest()
        except Exception:
            # Fallback to simple string hash
            return hashlib.md5(str(results).encode()).hexdigest()


# Convenience functions for creating common schedules


def every_minutes(minutes: int) -> ScheduleConfig:
    """Create an interval schedule that runs every N minutes."""
    return ScheduleConfig(
        schedule_type=ScheduleType.INTERVAL,
        interval_minutes=minutes,
    )


def every_hours(hours: int) -> ScheduleConfig:
    """Create an interval schedule that runs every N hours."""
    return ScheduleConfig(
        schedule_type=ScheduleType.INTERVAL,
        interval_minutes=hours * 60,
    )


def every_days(days: int) -> ScheduleConfig:
    """Create an interval schedule that runs every N days."""
    return ScheduleConfig(
        schedule_type=ScheduleType.INTERVAL,
        interval_minutes=days * 24 * 60,
    )


def daily_at(time_str: str) -> ScheduleConfig:
    """Create a daily schedule at a specific time (HH:MM format)."""
    return ScheduleConfig(
        schedule_type=ScheduleType.DAILY,
        time_of_day=time_str,
    )


def weekly_on(day: int, time_str: str) -> ScheduleConfig:
    """Create a weekly schedule on a specific day (0=Monday) at time."""
    return ScheduleConfig(
        schedule_type=ScheduleType.WEEKLY,
        day_of_week=day,
        time_of_day=time_str,
    )


def once_at(run_time: datetime) -> ScheduleConfig:
    """Create a one-time schedule at a specific datetime."""
    return ScheduleConfig(
        schedule_type=ScheduleType.ONCE,
        run_at=run_time,
    )


def cron(expression: str) -> ScheduleConfig:
    """Create a cron-based schedule."""
    return ScheduleConfig(
        schedule_type=ScheduleType.CRON,
        cron_expression=expression,
    )


# Global scheduler instance
_scheduler: Optional[SearchScheduler] = None


def get_scheduler() -> SearchScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = SearchScheduler()
    return _scheduler

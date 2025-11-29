"""
Bulk/Batch Search Support for TR4C3R.

Comprehensive batch processing system for running multiple searches:
- CSV/JSON/TXT input file support
- Parallel processing with concurrency control
- Progress tracking and resumable operations
- Result aggregation and export
- Rate limit management across batches
- Error handling with retry logic
"""

import asyncio
import csv
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Union

logger = logging.getLogger(__name__)


class BatchStatus(Enum):
    """Status of a batch job."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InputFormat(Enum):
    """Supported input file formats."""

    CSV = "csv"
    JSON = "json"
    TXT = "txt"
    NEWLINE = "newline"  # One item per line


class OutputFormat(Enum):
    """Supported output formats."""

    JSON = "json"
    CSV = "csv"
    SQLITE = "sqlite"
    COMBINED_JSON = "combined_json"


@dataclass
class BatchItem:
    """A single item in a batch job."""

    id: str
    query: str
    search_type: str  # email, phone, username, etc.
    status: str = "pending"  # pending, running, completed, failed, skipped
    result: Optional[dict] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "query": self.query,
            "search_type": self.search_type,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "retry_count": self.retry_count,
            "metadata": self.metadata,
        }


@dataclass
class BatchJob:
    """A batch job containing multiple items."""

    id: str
    name: str
    status: BatchStatus = BatchStatus.PENDING
    items: list = field(default_factory=list)
    total_items: int = 0
    completed_items: int = 0
    failed_items: int = 0
    skipped_items: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    options: dict = field(default_factory=dict)

    @property
    def progress(self) -> float:
        if self.total_items == 0:
            return 0.0
        return (
            (self.completed_items + self.failed_items + self.skipped_items) / self.total_items * 100
        )

    @property
    def remaining_items(self) -> int:
        return self.total_items - self.completed_items - self.failed_items - self.skipped_items

    @property
    def estimated_time_remaining(self) -> Optional[timedelta]:
        if not self.started_at or self.remaining_items == 0:
            return None

        elapsed = datetime.now() - self.started_at
        processed = self.completed_items + self.failed_items + self.skipped_items

        if processed == 0:
            return None

        avg_time_per_item = elapsed / processed
        return avg_time_per_item * self.remaining_items

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "total_items": self.total_items,
            "completed_items": self.completed_items,
            "failed_items": self.failed_items,
            "skipped_items": self.skipped_items,
            "progress": self.progress,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "options": self.options,
            "estimated_remaining": (
                str(self.estimated_time_remaining) if self.estimated_time_remaining else None
            ),
        }


class BatchInputParser:
    """Parses various input formats for batch processing."""

    @staticmethod
    def detect_format(file_path: str) -> InputFormat:
        """Detect file format from extension."""
        ext = Path(file_path).suffix.lower()
        if ext == ".csv":
            return InputFormat.CSV
        elif ext == ".json":
            return InputFormat.JSON
        elif ext == ".txt":
            return InputFormat.TXT
        else:
            return InputFormat.NEWLINE

    @staticmethod
    def parse_csv(
        file_path: str,
        query_column: str = "query",
        type_column: Optional[str] = "type",
        default_type: str = "email",
    ) -> list[BatchItem]:
        """Parse CSV file into batch items."""
        items = []

        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for idx, row in enumerate(reader):
                query = row.get(query_column, "").strip()
                if not query:
                    continue

                search_type = row.get(type_column, default_type) if type_column else default_type

                item_id = hashlib.sha256(f"{query}:{idx}".encode()).hexdigest()[:12]

                # Extract any extra columns as metadata
                metadata = {k: v for k, v in row.items() if k not in [query_column, type_column]}

                items.append(
                    BatchItem(id=item_id, query=query, search_type=search_type, metadata=metadata)
                )

        return items

    @staticmethod
    def parse_json(file_path: str, default_type: str = "email") -> list[BatchItem]:
        """Parse JSON file into batch items."""
        items = []

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Handle both array and object with items key
        if isinstance(data, dict):
            data = data.get("items", data.get("queries", []))

        for idx, item in enumerate(data):
            if isinstance(item, str):
                # Simple string list
                query = item.strip()
                search_type = default_type
                metadata = {}
            elif isinstance(item, dict):
                query = item.get("query", item.get("value", "")).strip()
                search_type = item.get("type", item.get("search_type", default_type))
                metadata = {
                    k: v
                    for k, v in item.items()
                    if k not in ["query", "value", "type", "search_type"]
                }
            else:
                continue

            if not query:
                continue

            item_id = hashlib.sha256(f"{query}:{idx}".encode()).hexdigest()[:12]

            items.append(
                BatchItem(id=item_id, query=query, search_type=search_type, metadata=metadata)
            )

        return items

    @staticmethod
    def parse_txt(file_path: str, default_type: str = "email") -> list[BatchItem]:
        """Parse text file (one query per line) into batch items."""
        items = []

        with open(file_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                query = line.strip()
                if not query or query.startswith("#"):  # Skip empty lines and comments
                    continue

                # Check for type prefix (e.g., "email:john@example.com")
                if ":" in query and query.split(":")[0] in [
                    "email",
                    "phone",
                    "username",
                    "ip",
                    "domain",
                ]:
                    search_type, query = query.split(":", 1)
                    query = query.strip()
                else:
                    search_type = default_type

                item_id = hashlib.sha256(f"{query}:{idx}".encode()).hexdigest()[:12]

                items.append(BatchItem(id=item_id, query=query, search_type=search_type))

        return items

    @classmethod
    def parse_file(
        cls, file_path: str, format: Optional[InputFormat] = None, **kwargs
    ) -> list[BatchItem]:
        """Parse any supported file format into batch items."""
        if format is None:
            format = cls.detect_format(file_path)

        if format == InputFormat.CSV:
            return cls.parse_csv(file_path, **kwargs)
        elif format == InputFormat.JSON:
            return cls.parse_json(file_path, **kwargs)
        elif format in (InputFormat.TXT, InputFormat.NEWLINE):
            return cls.parse_txt(file_path, **kwargs)
        else:
            raise ValueError(f"Unsupported format: {format}")


class BatchOutputWriter:
    """Writes batch results in various formats."""

    @staticmethod
    def write_json(job: BatchJob, output_path: str, include_items: bool = True):
        """Write results to JSON file."""
        data = job.to_dict()

        if include_items:
            data["items"] = [item.to_dict() for item in job.items]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    @staticmethod
    def write_csv(job: BatchJob, output_path: str):
        """Write results to CSV file."""
        if not job.items:
            return

        # Determine all possible columns
        all_keys = set()
        for item in job.items:
            all_keys.add("id")
            all_keys.add("query")
            all_keys.add("search_type")
            all_keys.add("status")
            all_keys.add("error")
            if item.result:
                for key in item.result.keys():
                    all_keys.add(f"result_{key}")
            for key in item.metadata.keys():
                all_keys.add(f"meta_{key}")

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
            writer.writeheader()

            for item in job.items:
                row = {
                    "id": item.id,
                    "query": item.query,
                    "search_type": item.search_type,
                    "status": item.status,
                    "error": item.error,
                }

                if item.result:
                    for key, value in item.result.items():
                        row[f"result_{key}"] = (
                            json.dumps(value) if isinstance(value, (dict, list)) else value
                        )

                for key, value in item.metadata.items():
                    row[f"meta_{key}"] = value

                writer.writerow(row)

    @staticmethod
    def write_sqlite(job: BatchJob, output_path: str):
        """Write results to SQLite database."""
        conn = sqlite3.connect(output_path)
        cursor = conn.cursor()

        # Create job table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS batch_jobs (
                id TEXT PRIMARY KEY,
                name TEXT,
                status TEXT,
                total_items INTEGER,
                completed_items INTEGER,
                failed_items INTEGER,
                created_at TEXT,
                completed_at TEXT,
                options TEXT
            )
        """
        )

        # Create items table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS batch_items (
                id TEXT PRIMARY KEY,
                job_id TEXT,
                query TEXT,
                search_type TEXT,
                status TEXT,
                result TEXT,
                error TEXT,
                started_at TEXT,
                completed_at TEXT,
                metadata TEXT,
                FOREIGN KEY (job_id) REFERENCES batch_jobs(id)
            )
        """
        )

        # Insert job
        cursor.execute(
            """
            INSERT OR REPLACE INTO batch_jobs
            (id, name, status, total_items, completed_items, failed_items, created_at, completed_at, options)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                job.id,
                job.name,
                job.status.value,
                job.total_items,
                job.completed_items,
                job.failed_items,
                job.created_at.isoformat(),
                job.completed_at.isoformat() if job.completed_at else None,
                json.dumps(job.options),
            ),
        )

        # Insert items
        for item in job.items:
            cursor.execute(
                """
                INSERT OR REPLACE INTO batch_items
                (id, job_id, query, search_type, status, result, error, started_at, completed_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    item.id,
                    job.id,
                    item.query,
                    item.search_type,
                    item.status,
                    json.dumps(item.result) if item.result else None,
                    item.error,
                    item.started_at.isoformat() if item.started_at else None,
                    item.completed_at.isoformat() if item.completed_at else None,
                    json.dumps(item.metadata),
                ),
            )

        conn.commit()
        conn.close()

    @classmethod
    def write(cls, job: BatchJob, output_path: str, format: OutputFormat):
        """Write results in specified format."""
        if format == OutputFormat.JSON:
            cls.write_json(job, output_path)
        elif format == OutputFormat.CSV:
            cls.write_csv(job, output_path)
        elif format == OutputFormat.SQLITE:
            cls.write_sqlite(job, output_path)
        elif format == OutputFormat.COMBINED_JSON:
            cls.write_json(job, output_path, include_items=True)
        else:
            raise ValueError(f"Unsupported output format: {format}")


class BatchProcessor:
    """
    Processes batch search jobs with concurrency control.

    Features:
    - Parallel processing with configurable concurrency
    - Rate limiting and backoff
    - Progress tracking
    - Resumable operations
    - Error handling with retry
    """

    def __init__(
        self,
        search_function: Callable,
        max_concurrency: int = 5,
        rate_limit_per_minute: int = 60,
        max_retries: int = 3,
        retry_delay: float = 5.0,
        db_path: str = "batch_jobs.db",
    ):
        """
        Initialize batch processor.

        Args:
            search_function: Async function to execute searches
            max_concurrency: Maximum concurrent searches
            rate_limit_per_minute: Max requests per minute
            max_retries: Max retry attempts for failed items
            retry_delay: Delay between retries (seconds)
            db_path: Path to persistence database
        """
        self.search_function = search_function
        self.max_concurrency = max_concurrency
        self.rate_limit_per_minute = rate_limit_per_minute
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.db_path = db_path

        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rate_limiter = RateLimiter(rate_limit_per_minute, 60)
        self._active_jobs: dict[str, BatchJob] = {}
        self._stop_flags: dict[str, threading.Event] = {}
        self._progress_callbacks: dict[str, Callable] = {}

        self._init_db()

    def _init_db(self):
        """Initialize persistence database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                name TEXT,
                status TEXT,
                data TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """
        )

        conn.commit()
        conn.close()

    def create_job(
        self, name: str, items: list[BatchItem], options: Optional[dict] = None
    ) -> BatchJob:
        """
        Create a new batch job.

        Args:
            name: Job name
            items: List of batch items
            options: Job options

        Returns:
            Created BatchJob
        """
        job_id = hashlib.sha256(f"{name}:{datetime.now().isoformat()}".encode()).hexdigest()[:16]

        job = BatchJob(
            id=job_id, name=name, items=items, total_items=len(items), options=options or {}
        )

        self._save_job(job)

        return job

    def create_job_from_file(
        self,
        name: str,
        file_path: str,
        format: Optional[InputFormat] = None,
        options: Optional[dict] = None,
        **parser_kwargs,
    ) -> BatchJob:
        """
        Create a batch job from an input file.

        Args:
            name: Job name
            file_path: Path to input file
            format: Input file format (auto-detected if None)
            options: Job options
            **parser_kwargs: Additional parser arguments

        Returns:
            Created BatchJob
        """
        items = BatchInputParser.parse_file(file_path, format, **parser_kwargs)
        return self.create_job(name, items, options)

    async def run_job(
        self, job: BatchJob, progress_callback: Optional[Callable] = None
    ) -> BatchJob:
        """
        Run a batch job.

        Args:
            job: The job to run
            progress_callback: Called with progress updates

        Returns:
            Completed job
        """
        if job.status == BatchStatus.RUNNING:
            raise RuntimeError(f"Job {job.id} is already running")

        job.status = BatchStatus.RUNNING
        job.started_at = datetime.now()
        self._active_jobs[job.id] = job
        self._stop_flags[job.id] = threading.Event()

        if progress_callback:
            self._progress_callbacks[job.id] = progress_callback

        try:
            # Get pending items
            pending_items = [
                item
                for item in job.items
                if item.status in ("pending", "failed") and item.retry_count < self.max_retries
            ]

            # Process items concurrently
            tasks = [self._process_item(job, item) for item in pending_items]

            await asyncio.gather(*tasks, return_exceptions=True)

            # Determine final status
            if self._stop_flags[job.id].is_set():
                job.status = BatchStatus.CANCELLED
            elif job.failed_items > 0 and job.completed_items == 0:
                job.status = BatchStatus.FAILED
            else:
                job.status = BatchStatus.COMPLETED

            job.completed_at = datetime.now()

        except Exception as e:
            logger.error(f"Batch job {job.id} failed: {e}")
            job.status = BatchStatus.FAILED
            raise
        finally:
            self._active_jobs.pop(job.id, None)
            self._stop_flags.pop(job.id, None)
            self._progress_callbacks.pop(job.id, None)
            self._save_job(job)

        return job

    async def _process_item(self, job: BatchJob, item: BatchItem):
        """Process a single batch item."""
        # Check for stop signal
        if self._stop_flags.get(job.id, threading.Event()).is_set():
            item.status = "skipped"
            job.skipped_items += 1
            return

        async with self._semaphore:
            # Apply rate limiting
            await self._rate_limiter.acquire()

            item.status = "running"
            item.started_at = datetime.now()

            try:
                # Execute search
                result = await self.search_function(item.query, item.search_type)

                item.result = result if isinstance(result, dict) else {"data": result}
                item.status = "completed"
                item.completed_at = datetime.now()
                job.completed_items += 1

            except Exception as e:
                logger.error(f"Item {item.id} failed: {e}")
                item.error = str(e)
                item.retry_count += 1

                if item.retry_count < self.max_retries:
                    item.status = "pending"  # Will be retried
                    await asyncio.sleep(self.retry_delay * item.retry_count)
                else:
                    item.status = "failed"
                    job.failed_items += 1

            # Notify progress
            if job.id in self._progress_callbacks:
                try:
                    callback = self._progress_callbacks[job.id]
                    callback(job, item)
                except Exception:
                    pass

            # Periodic save
            if (job.completed_items + job.failed_items) % 10 == 0:
                self._save_job(job)

    def pause_job(self, job_id: str):
        """Pause a running job."""
        if job_id in self._stop_flags:
            self._stop_flags[job_id].set()
            if job_id in self._active_jobs:
                self._active_jobs[job_id].status = BatchStatus.PAUSED

    def resume_job(self, job_id: str) -> Optional[BatchJob]:
        """Resume a paused job."""
        job = self.load_job(job_id)
        if job and job.status == BatchStatus.PAUSED:
            job.status = BatchStatus.PENDING
            return job
        return None

    def cancel_job(self, job_id: str):
        """Cancel a job."""
        self.pause_job(job_id)
        if job_id in self._active_jobs:
            self._active_jobs[job_id].status = BatchStatus.CANCELLED

    def _save_job(self, job: BatchJob):
        """Save job to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO jobs (id, name, status, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                job.id,
                job.name,
                job.status.value,
                json.dumps(
                    {
                        "items": [item.to_dict() for item in job.items],
                        "options": job.options,
                        "stats": {
                            "total": job.total_items,
                            "completed": job.completed_items,
                            "failed": job.failed_items,
                            "skipped": job.skipped_items,
                        },
                    }
                ),
                job.created_at.isoformat(),
                datetime.now().isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    def load_job(self, job_id: str) -> Optional[BatchJob]:
        """Load a job from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        data = json.loads(row[3])

        items = [
            BatchItem(
                id=item["id"],
                query=item["query"],
                search_type=item["search_type"],
                status=item["status"],
                result=item.get("result"),
                error=item.get("error"),
                started_at=(
                    datetime.fromisoformat(item["started_at"]) if item.get("started_at") else None
                ),
                completed_at=(
                    datetime.fromisoformat(item["completed_at"])
                    if item.get("completed_at")
                    else None
                ),
                retry_count=item.get("retry_count", 0),
                metadata=item.get("metadata", {}),
            )
            for item in data.get("items", [])
        ]

        stats = data.get("stats", {})

        return BatchJob(
            id=row[0],
            name=row[1],
            status=BatchStatus(row[2]),
            items=items,
            total_items=stats.get("total", len(items)),
            completed_items=stats.get("completed", 0),
            failed_items=stats.get("failed", 0),
            skipped_items=stats.get("skipped", 0),
            created_at=datetime.fromisoformat(row[4]),
            options=data.get("options", {}),
        )

    def list_jobs(self, limit: int = 50) -> list[dict]:
        """List all jobs."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, name, status, created_at, updated_at
            FROM jobs
            ORDER BY created_at DESC
            LIMIT ?
        """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": row[0],
                "name": row[1],
                "status": row[2],
                "created_at": row[3],
                "updated_at": row[4],
            }
            for row in rows
        ]

    def delete_job(self, job_id: str):
        """Delete a job from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        conn.commit()
        conn.close()

    def export_results(
        self, job: BatchJob, output_path: str, format: OutputFormat = OutputFormat.JSON
    ):
        """Export job results to file."""
        BatchOutputWriter.write(job, output_path, format)


class RateLimiter:
    """Token bucket rate limiter for batch processing."""

    def __init__(self, rate: int, period: float):
        """
        Initialize rate limiter.

        Args:
            rate: Number of tokens per period
            period: Time period in seconds
        """
        self.rate = rate
        self.period = period
        self.tokens = rate
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquire a rate limit token."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update

            # Refill tokens
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate / self.period)
            self.last_update = now

            if self.tokens < 1:
                # Wait for token
                wait_time = (1 - self.tokens) * self.period / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class BatchSearchManager:
    """
    High-level manager for batch searches.

    Provides a simple interface for common batch operations.
    """

    def __init__(self, db_path: str = "batch_searches.db"):
        self.db_path = db_path
        self._processors: dict[str, BatchProcessor] = {}

    def register_search_type(
        self,
        search_type: str,
        search_function: Callable,
        max_concurrency: int = 5,
        rate_limit_per_minute: int = 60,
    ):
        """
        Register a search type with its processing function.

        Args:
            search_type: Type identifier (e.g., "email", "phone")
            search_function: Async function to perform search
            max_concurrency: Max concurrent searches
            rate_limit_per_minute: Rate limit
        """
        self._processors[search_type] = BatchProcessor(
            search_function=search_function,
            max_concurrency=max_concurrency,
            rate_limit_per_minute=rate_limit_per_minute,
            db_path=self.db_path,
        )

    async def process_file(
        self,
        file_path: str,
        name: Optional[str] = None,
        default_search_type: str = "email",
        output_path: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.JSON,
        progress_callback: Optional[Callable] = None,
    ) -> BatchJob:
        """
        Process a file of queries.

        Args:
            file_path: Path to input file
            name: Job name (defaults to filename)
            default_search_type: Default search type if not specified
            output_path: Path to save results
            output_format: Output format
            progress_callback: Progress callback function

        Returns:
            Completed BatchJob
        """
        if name is None:
            name = Path(file_path).stem

        # Parse input file
        items = BatchInputParser.parse_file(file_path, default_type=default_search_type)

        # Group items by search type
        items_by_type: dict[str, list[BatchItem]] = {}
        for item in items:
            if item.search_type not in items_by_type:
                items_by_type[item.search_type] = []
            items_by_type[item.search_type].append(item)

        # Process each type
        all_items = []
        for search_type, type_items in items_by_type.items():
            if search_type not in self._processors:
                logger.warning(f"No processor for search type: {search_type}")
                for item in type_items:
                    item.status = "skipped"
                    item.error = f"Unknown search type: {search_type}"
                all_items.extend(type_items)
                continue

            processor = self._processors[search_type]
            job = processor.create_job(f"{name}_{search_type}", type_items)
            job = await processor.run_job(job, progress_callback)
            all_items.extend(job.items)

        # Create combined job
        combined_job = BatchJob(
            id=hashlib.sha256(f"combined:{name}:{datetime.now().isoformat()}".encode()).hexdigest()[
                :16
            ],
            name=name,
            status=BatchStatus.COMPLETED,
            items=all_items,
            total_items=len(all_items),
            completed_items=sum(1 for i in all_items if i.status == "completed"),
            failed_items=sum(1 for i in all_items if i.status == "failed"),
            skipped_items=sum(1 for i in all_items if i.status == "skipped"),
            completed_at=datetime.now(),
        )

        # Export results
        if output_path:
            BatchOutputWriter.write(combined_job, output_path, output_format)

        return combined_job

    async def process_list(
        self,
        queries: list[str],
        search_type: str,
        name: str = "batch_search",
        progress_callback: Optional[Callable] = None,
    ) -> BatchJob:
        """
        Process a list of queries.

        Args:
            queries: List of query strings
            search_type: Search type
            name: Job name
            progress_callback: Progress callback

        Returns:
            Completed BatchJob
        """
        if search_type not in self._processors:
            raise ValueError(f"Unknown search type: {search_type}")

        items = [
            BatchItem(
                id=hashlib.sha256(f"{q}:{i}".encode()).hexdigest()[:12],
                query=q,
                search_type=search_type,
            )
            for i, q in enumerate(queries)
        ]

        processor = self._processors[search_type]
        job = processor.create_job(name, items)
        return await processor.run_job(job, progress_callback)

    def get_job_status(self, job_id: str) -> Optional[dict]:
        """Get status of a job."""
        for processor in self._processors.values():
            job = processor.load_job(job_id)
            if job:
                return job.to_dict()
        return None

    def list_all_jobs(self, limit: int = 50) -> list[dict]:
        """List all jobs across all processors."""
        all_jobs = []
        for processor in self._processors.values():
            all_jobs.extend(processor.list_jobs(limit))

        # Sort by created_at and limit
        all_jobs.sort(key=lambda x: x["created_at"], reverse=True)
        return all_jobs[:limit]


# Example search function for testing
async def example_search(query: str, search_type: str) -> dict:
    """Example search function for testing."""
    await asyncio.sleep(0.1)  # Simulate API call
    return {"query": query, "type": search_type, "found": True, "results": [f"Result for {query}"]}

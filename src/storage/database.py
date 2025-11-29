"""Database layer for TR4C3R using SQLite.

This module provides database functionality for persisting search results,
maintaining search history, and caching data for performance.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional

from src.core.data_models import Result


class Database:
    """SQLite database manager for TR4C3R."""

    def __init__(self, db_path: str = "tr4c3r.db"):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.logger = logging.getLogger(self.__class__.__name__)
        self._initialize_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager for database connections.

        Yields:
            SQLite connection with row factory set
        """
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

            # Search history table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS search_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_type TEXT NOT NULL,
                    query TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    result_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """
            )

            # Results table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER,
                    source TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    url TEXT,
                    confidence REAL,
                    timestamp TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (search_id) REFERENCES search_history(id)
                )
            """
            )

            # Cache table for API responses
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT UNIQUE NOT NULL,
                    cache_value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    hit_count INTEGER DEFAULT 0
                )
            """
            )

            # Indexes for performance
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_search_type 
                ON search_history(search_type)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_search_query 
                ON search_history(query)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_results_search_id 
                ON results(search_id)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_results_source 
                ON results(source)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cache_key 
                ON cache(cache_key)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cache_expires 
                ON cache(expires_at)
            """
            )

            self.logger.info(f"Database initialized at {self.db_path}")

    def save_search(
        self, search_type: str, query: str, results: List[Result], metadata: Optional[Dict] = None
    ) -> int:
        """
        Save a search and its results to the database.

        Args:
            search_type: Type of search (email, phone, name, username, etc.)
            query: The search query
            results: List of Result objects
            metadata: Optional metadata about the search

        Returns:
            Search ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert search history
            cursor.execute(
                """
                INSERT INTO search_history (search_type, query, result_count, metadata)
                VALUES (?, ?, ?, ?)
            """,
                (search_type, query, len(results), json.dumps(metadata) if metadata else None),
            )

            search_id = cursor.lastrowid
            if search_id is None:
                raise RuntimeError("Failed to insert search record")

            # Insert results
            for result in results:
                cursor.execute(
                    """
                    INSERT INTO results 
                    (search_id, source, identifier, url, confidence, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        search_id,
                        result.source,
                        result.identifier,
                        result.url,
                        result.confidence,
                        result.timestamp.isoformat(),
                        json.dumps(result.metadata),
                    ),
                )

            self.logger.info(
                f"Saved search {search_id}: {search_type} query '{query}' "
                f"with {len(results)} results"
            )

            return search_id

    def get_search_history(self, search_type: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """
        Retrieve search history.

        Args:
            search_type: Filter by search type (optional)
            limit: Maximum number of records to return

        Returns:
            List of search history records
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if search_type:
                cursor.execute(
                    """
                    SELECT * FROM search_history
                    WHERE search_type = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (search_type, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM search_history
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_search_results(self, search_id: int) -> List[Result]:
        """
        Retrieve results for a specific search.

        Args:
            search_id: The search ID

        Returns:
            List of Result objects
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM results
                WHERE search_id = ?
                ORDER BY confidence DESC
            """,
                (search_id,),
            )

            rows = cursor.fetchall()

            results = []
            for row in rows:
                result = Result(
                    source=row["source"],
                    identifier=row["identifier"],
                    url=row["url"],
                    confidence=row["confidence"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )
                results.append(result)

            return results

    def cache_set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        """
        Store a value in cache.

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl_seconds: Time to live in seconds (None = no expiration)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now(timezone.utc).timestamp() + ttl_seconds

            cursor.execute(
                """
                INSERT OR REPLACE INTO cache (cache_key, cache_value, expires_at, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (key, value, expires_at),
            )

            self.logger.debug(f"Cached value for key: {key}")

    def cache_get(self, key: str) -> Optional[str]:
        """
        Retrieve a value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT cache_value, expires_at, hit_count
                FROM cache
                WHERE cache_key = ?
            """,
                (key,),
            )

            row = cursor.fetchone()

            if not row:
                return None

            # Check expiration
            if row["expires_at"]:
                current_time = datetime.now(timezone.utc).timestamp()
                if current_time > row["expires_at"]:
                    # Expired - delete and return None
                    cursor.execute("DELETE FROM cache WHERE cache_key = ?", (key,))
                    return None

            # Update hit count
            cursor.execute(
                """
                UPDATE cache
                SET hit_count = hit_count + 1
                WHERE cache_key = ?
            """,
                (key,),
            )

            self.logger.debug(f"Cache hit for key: {key}")
            return row["cache_value"]

    def cache_clear(self, pattern: Optional[str] = None) -> int:
        """
        Clear cache entries.

        Args:
            pattern: SQL LIKE pattern to match keys (None = clear all)

        Returns:
            Number of entries deleted
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if pattern:
                cursor.execute(
                    """
                    DELETE FROM cache
                    WHERE cache_key LIKE ?
                """,
                    (pattern,),
                )
            else:
                cursor.execute("DELETE FROM cache")

            deleted = cursor.rowcount
            self.logger.info(f"Cleared {deleted} cache entries")
            return deleted

    def export_search(self, search_id: int, format: str = "json") -> str:
        """
        Export search results in various formats.

        Args:
            search_id: The search ID to export
            format: Export format (json, csv, xml)

        Returns:
            Formatted string of results
        """
        # Get search info
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM search_history WHERE id = ?
            """,
                (search_id,),
            )
            search_info = dict(cursor.fetchone())

        # Get results
        results = self.get_search_results(search_id)

        if format == "json":
            export_data = {
                "search": search_info,
                "results": [
                    {
                        "source": r.source,
                        "identifier": r.identifier,
                        "url": r.url,
                        "confidence": r.confidence,
                        "timestamp": r.timestamp.isoformat(),
                        "metadata": r.metadata,
                    }
                    for r in results
                ],
            }
            return json.dumps(export_data, indent=2)

        elif format == "csv":
            lines = ["source,identifier,url,confidence,timestamp"]
            for r in results:
                lines.append(
                    f"{r.source},{r.identifier},{r.url},"
                    f"{r.confidence},{r.timestamp.isoformat()}"
                )
            return "\n".join(lines)

        elif format == "xml":
            xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
            xml_lines.append("<search>")
            xml_lines.append(f"  <type>{search_info['search_type']}</type>")
            xml_lines.append(f"  <query>{search_info['query']}</query>")
            xml_lines.append("  <results>")
            for r in results:
                xml_lines.append("    <result>")
                xml_lines.append(f"      <source>{r.source}</source>")
                xml_lines.append(f"      <identifier>{r.identifier}</identifier>")
                xml_lines.append(f"      <url>{r.url}</url>")
                xml_lines.append(f"      <confidence>{r.confidence}</confidence>")
                xml_lines.append(f"      <timestamp>{r.timestamp.isoformat()}</timestamp>")
                xml_lines.append("    </result>")
            xml_lines.append("  </results>")
            xml_lines.append("</search>")
            return "\n".join(xml_lines)

        else:
            raise ValueError(f"Unsupported export format: {format}")

    def get_statistics(self) -> Dict:
        """
        Get database statistics.

        Returns:
            Dictionary with database statistics
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            # Total searches
            cursor.execute("SELECT COUNT(*) as count FROM search_history")
            stats["total_searches"] = cursor.fetchone()["count"]

            # Total results
            cursor.execute("SELECT COUNT(*) as count FROM results")
            stats["total_results"] = cursor.fetchone()["count"]

            # Searches by type
            cursor.execute(
                """
                SELECT search_type, COUNT(*) as count
                FROM search_history
                GROUP BY search_type
            """
            )
            stats["searches_by_type"] = {
                row["search_type"]: row["count"] for row in cursor.fetchall()
            }

            # Cache statistics
            cursor.execute("SELECT COUNT(*) as count FROM cache")
            stats["cache_entries"] = cursor.fetchone()["count"]

            cursor.execute("SELECT SUM(hit_count) as total FROM cache")
            stats["cache_hits"] = cursor.fetchone()["total"] or 0

            # Database size
            stats["database_size_bytes"] = Path(self.db_path).stat().st_size

            return stats

    def cleanup_expired_cache(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            current_time = datetime.now(timezone.utc).timestamp()

            cursor.execute(
                """
                DELETE FROM cache
                WHERE expires_at IS NOT NULL
                AND expires_at <= ?
            """,
                (current_time,),
            )

            deleted = cursor.rowcount
            self.logger.info(f"Cleaned up {deleted} expired cache entries")
            return deleted

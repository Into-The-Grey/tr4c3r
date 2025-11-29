"""Data models used throughout TR4C3R.

The Result class defines a common representation for OSINT query results.
Each result records where it came from, what type of identifier was queried,
and any metadata returned by the source.  Additional models may be added
later as the project grows (e.g. for relationships, users, or configuration).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Result:
    """Represents a single OSINT lookup result.

    Attributes
    ----------
    source: str
        Name of the module or external service that produced this result.
    identifier: str
        The identifier that was queried (username, email, phone number, etc.).
    url: Optional[str]
        A URL pointing to the resource where the identifier was found.
    confidence: float
        A value between 0 and 1 indicating how confident the module is that
        this result belongs to the target identifier.
    timestamp: datetime
        The time when the result was obtained.
    metadata: Dict[str, Any]
        Additional data returned by the source (e.g. profile details, breach
        information).  Modules are free to store arbitrary JSON‑serialisable
        values here.
    """

    source: str
    identifier: str
    url: Optional[str] = None
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize and validate source
        if not self.source:
            raise ValueError("source cannot be empty")
        self.source = str(self.source).strip()

        # Normalize identifier
        if not self.identifier:
            raise ValueError("identifier cannot be empty")
        self.identifier = str(self.identifier).strip()

        # Normalize URL
        if self.url is not None:
            self.url = str(self.url).strip() or None

        # Clamp confidence to [0, 1] with warning instead of raising
        if self.confidence < 0.0:
            logger.warning(
                "Confidence %f clamped to 0.0 for result from %s",
                self.confidence,
                self.source,
            )
            self.confidence = 0.0
        elif self.confidence > 1.0:
            logger.warning(
                "Confidence %f clamped to 1.0 for result from %s",
                self.confidence,
                self.source,
            )
            self.confidence = 1.0

        # Ensure metadata is a dict
        if self.metadata is None:
            self.metadata = {}
        elif not isinstance(self.metadata, dict):
            logger.warning(
                "Converting non-dict metadata to dict for result from %s",
                self.source,
            )
            self.metadata = {"value": self.metadata}

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the result to a JSON‑serialisable dictionary."""
        return {
            "source": self.source,
            "identifier": self.identifier,
            "url": self.url,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize the result to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Result":
        """Create a Result from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary containing result data.

        Returns
        -------
        Result
            New Result instance.

        Raises
        ------
        ValueError
            If required fields are missing.
        """
        if "source" not in data or "identifier" not in data:
            raise ValueError("Result requires 'source' and 'identifier' fields")

        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)

        return cls(
            source=data["source"],
            identifier=data["identifier"],
            url=data.get("url"),
            confidence=float(data.get("confidence", 1.0)),
            timestamp=timestamp,
            metadata=data.get("metadata", {}),
        )

    def merge_metadata(self, other_metadata: Dict[str, Any]) -> None:
        """Merge additional metadata into this result.

        Parameters
        ----------
        other_metadata : dict
            Additional metadata to merge.
        """
        if other_metadata:
            self.metadata.update(other_metadata)

    def __repr__(self) -> str:
        return (
            f"Result(source={self.source!r}, identifier={self.identifier!r}, "
            f"confidence={self.confidence:.2f})"
        )


@dataclass
class SearchSession:
    """Represents a search session with multiple results.

    Attributes
    ----------
    session_id : str
        Unique identifier for this search session.
    query : str
        The original search query.
    search_type : str
        Type of search performed (email, username, phone, etc.).
    started_at : datetime
        When the search started.
    completed_at : Optional[datetime]
        When the search completed.
    results : List[Result]
        Results found during this session.
    metadata : Dict[str, Any]
        Additional session metadata.
    """

    session_id: str
    query: str
    search_type: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    results: List[Result] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_result(self, result: Result) -> None:
        """Add a result to this session."""
        self.results.append(result)

    def complete(self) -> None:
        """Mark this session as completed."""
        self.completed_at = datetime.now(timezone.utc)

    @property
    def duration_ms(self) -> Optional[float]:
        """Get the duration of this session in milliseconds."""
        if self.completed_at is None:
            return None
        delta = self.completed_at - self.started_at
        return delta.total_seconds() * 1000

    @property
    def result_count(self) -> int:
        """Get the number of results in this session."""
        return len(self.results)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the session to a dictionary."""
        return {
            "session_id": self.session_id,
            "query": self.query,
            "search_type": self.search_type,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "result_count": self.result_count,
            "results": [r.to_dict() for r in self.results],
            "metadata": self.metadata,
        }

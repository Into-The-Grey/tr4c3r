"""
Search Result Tagging and Notes System for TR4C3R.

Comprehensive annotation system for OSINT results:
- Tagging with hierarchical categories
- Rich notes with formatting
- Annotations and highlights
- Bookmarking important results
- Investigation notes and timelines
- Collaboration support (multi-user notes)
- Export annotations with results
"""

import hashlib
import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class TagCategory(Enum):
    """Predefined tag categories."""

    PRIORITY = "priority"
    STATUS = "status"
    RISK_LEVEL = "risk_level"
    SOURCE_TYPE = "source_type"
    INVESTIGATION = "investigation"
    ENTITY_TYPE = "entity_type"
    CUSTOM = "custom"


class NoteType(Enum):
    """Types of notes."""

    GENERAL = "general"
    ANALYSIS = "analysis"
    FINDING = "finding"
    TODO = "todo"
    WARNING = "warning"
    CONCLUSION = "conclusion"
    TIMELINE = "timeline"


class BookmarkType(Enum):
    """Types of bookmarks."""

    IMPORTANT = "important"
    FOLLOW_UP = "follow_up"
    EVIDENCE = "evidence"
    SUSPICIOUS = "suspicious"
    CLEARED = "cleared"


@dataclass
class Tag:
    """A tag for categorizing results."""

    id: str
    name: str
    category: TagCategory = TagCategory.CUSTOM
    color: str = "#6c757d"  # Default gray
    description: Optional[str] = None
    parent_id: Optional[str] = None  # For hierarchical tags
    usage_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    created_by: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "color": self.color,
            "description": self.description,
            "parent_id": self.parent_id,
            "usage_count": self.usage_count,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
        }


@dataclass
class Note:
    """A note attached to a result."""

    id: str
    result_id: str
    content: str
    note_type: NoteType = NoteType.GENERAL
    title: Optional[str] = None
    author: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    is_pinned: bool = False
    attachments: list = field(default_factory=list)
    mentions: list = field(default_factory=list)  # @user mentions

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "result_id": self.result_id,
            "content": self.content,
            "note_type": self.note_type.value,
            "title": self.title,
            "author": self.author,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "is_pinned": self.is_pinned,
            "attachments": self.attachments,
            "mentions": self.mentions,
        }


@dataclass
class Bookmark:
    """A bookmark for quick access to results."""

    id: str
    result_id: str
    bookmark_type: BookmarkType = BookmarkType.IMPORTANT
    label: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    created_by: Optional[str] = None
    folder: Optional[str] = None  # For organizing bookmarks

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "result_id": self.result_id,
            "bookmark_type": self.bookmark_type.value,
            "label": self.label,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "folder": self.folder,
        }


@dataclass
class Annotation:
    """An annotation highlighting specific content."""

    id: str
    result_id: str
    field_path: str  # JSON path to the annotated field
    start_offset: Optional[int] = None  # For text highlighting
    end_offset: Optional[int] = None
    highlight_color: str = "#ffff00"  # Yellow
    comment: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    created_by: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "result_id": self.result_id,
            "field_path": self.field_path,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "highlight_color": self.highlight_color,
            "comment": self.comment,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
        }


@dataclass
class Investigation:
    """An investigation grouping multiple results."""

    id: str
    name: str
    description: Optional[str] = None
    status: str = "active"  # active, closed, archived
    result_ids: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    collaborators: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "result_ids": self.result_ids,
            "timeline": self.timeline,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
            "collaborators": self.collaborators,
            "metadata": self.metadata,
        }


class TaggingSystem:
    """
    Manages tags for search results.

    Features:
    - Hierarchical tag structure
    - Tag categories
    - Tag suggestions based on content
    - Bulk tagging operations
    """

    # Predefined tags
    DEFAULT_TAGS = [
        # Priority
        {"name": "critical", "category": TagCategory.PRIORITY, "color": "#dc3545"},
        {"name": "high", "category": TagCategory.PRIORITY, "color": "#fd7e14"},
        {"name": "medium", "category": TagCategory.PRIORITY, "color": "#ffc107"},
        {"name": "low", "category": TagCategory.PRIORITY, "color": "#28a745"},
        # Status
        {"name": "verified", "category": TagCategory.STATUS, "color": "#28a745"},
        {"name": "unverified", "category": TagCategory.STATUS, "color": "#6c757d"},
        {"name": "disputed", "category": TagCategory.STATUS, "color": "#dc3545"},
        {"name": "needs-review", "category": TagCategory.STATUS, "color": "#17a2b8"},
        # Risk Level
        {"name": "high-risk", "category": TagCategory.RISK_LEVEL, "color": "#dc3545"},
        {"name": "medium-risk", "category": TagCategory.RISK_LEVEL, "color": "#fd7e14"},
        {"name": "low-risk", "category": TagCategory.RISK_LEVEL, "color": "#28a745"},
        # Entity Type
        {"name": "person", "category": TagCategory.ENTITY_TYPE, "color": "#007bff"},
        {"name": "organization", "category": TagCategory.ENTITY_TYPE, "color": "#6610f2"},
        {"name": "location", "category": TagCategory.ENTITY_TYPE, "color": "#20c997"},
        {"name": "infrastructure", "category": TagCategory.ENTITY_TYPE, "color": "#fd7e14"},
    ]

    def __init__(self, db_path: str = "tagging.db"):
        self.db_path = db_path
        self._init_db()
        self._init_default_tags()

    def _init_db(self):
        """Initialize database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Tags table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tags (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                color TEXT,
                description TEXT,
                parent_id TEXT,
                usage_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                created_by TEXT,
                FOREIGN KEY (parent_id) REFERENCES tags(id)
            )
        """
        )

        # Result-Tag associations
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS result_tags (
                result_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                added_at TEXT NOT NULL,
                added_by TEXT,
                PRIMARY KEY (result_id, tag_id),
                FOREIGN KEY (tag_id) REFERENCES tags(id)
            )
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_result_tags_result ON result_tags(result_id)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_result_tags_tag ON result_tags(tag_id)")

        conn.commit()
        conn.close()

    def _init_default_tags(self):
        """Initialize default tags."""
        for tag_def in self.DEFAULT_TAGS:
            try:
                self.create_tag(
                    name=tag_def["name"], category=tag_def["category"], color=tag_def["color"]
                )
            except sqlite3.IntegrityError:
                pass  # Tag already exists

    def create_tag(
        self,
        name: str,
        category: TagCategory = TagCategory.CUSTOM,
        color: str = "#6c757d",
        description: Optional[str] = None,
        parent_id: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Tag:
        """Create a new tag."""
        tag_id = hashlib.sha256(name.encode()).hexdigest()[:12]

        tag = Tag(
            id=tag_id,
            name=name.lower().replace(" ", "-"),
            category=category,
            color=color,
            description=description,
            parent_id=parent_id,
            created_by=created_by,
        )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO tags (id, name, category, color, description, parent_id, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                tag.id,
                tag.name,
                tag.category.value,
                tag.color,
                tag.description,
                tag.parent_id,
                tag.created_at.isoformat(),
                tag.created_by,
            ),
        )

        conn.commit()
        conn.close()

        return tag

    def get_tag(self, tag_id: str) -> Optional[Tag]:
        """Get a tag by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM tags WHERE id = ?", (tag_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Tag(
            id=row[0],
            name=row[1],
            category=TagCategory(row[2]),
            color=row[3],
            description=row[4],
            parent_id=row[5],
            usage_count=row[6],
            created_at=datetime.fromisoformat(row[7]),
            created_by=row[8],
        )

    def get_tag_by_name(self, name: str) -> Optional[Tag]:
        """Get a tag by name."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM tags WHERE name = ?", (name.lower().replace(" ", "-"),))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Tag(
            id=row[0],
            name=row[1],
            category=TagCategory(row[2]),
            color=row[3],
            description=row[4],
            parent_id=row[5],
            usage_count=row[6],
            created_at=datetime.fromisoformat(row[7]),
            created_by=row[8],
        )

    def list_tags(
        self, category: Optional[TagCategory] = None, search: Optional[str] = None
    ) -> list[Tag]:
        """List all tags with optional filtering."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM tags WHERE 1=1"
        params = []

        if category:
            query += " AND category = ?"
            params.append(category.value)

        if search:
            query += " AND name LIKE ?"
            params.append(f"%{search}%")

        query += " ORDER BY usage_count DESC, name ASC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            Tag(
                id=row[0],
                name=row[1],
                category=TagCategory(row[2]),
                color=row[3],
                description=row[4],
                parent_id=row[5],
                usage_count=row[6],
                created_at=datetime.fromisoformat(row[7]),
                created_by=row[8],
            )
            for row in rows
        ]

    def add_tag_to_result(self, result_id: str, tag_id: str, added_by: Optional[str] = None):
        """Add a tag to a result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Add association
        cursor.execute(
            """
            INSERT OR IGNORE INTO result_tags (result_id, tag_id, added_at, added_by)
            VALUES (?, ?, ?, ?)
        """,
            (result_id, tag_id, datetime.now().isoformat(), added_by),
        )

        # Update usage count
        cursor.execute("UPDATE tags SET usage_count = usage_count + 1 WHERE id = ?", (tag_id,))

        conn.commit()
        conn.close()

    def remove_tag_from_result(self, result_id: str, tag_id: str):
        """Remove a tag from a result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM result_tags WHERE result_id = ? AND tag_id = ?
        """,
            (result_id, tag_id),
        )

        if cursor.rowcount > 0:
            cursor.execute("UPDATE tags SET usage_count = usage_count - 1 WHERE id = ?", (tag_id,))

        conn.commit()
        conn.close()

    def get_result_tags(self, result_id: str) -> list[Tag]:
        """Get all tags for a result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT t.* FROM tags t
            JOIN result_tags rt ON t.id = rt.tag_id
            WHERE rt.result_id = ?
            ORDER BY t.name
        """,
            (result_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [
            Tag(
                id=row[0],
                name=row[1],
                category=TagCategory(row[2]),
                color=row[3],
                description=row[4],
                parent_id=row[5],
                usage_count=row[6],
                created_at=datetime.fromisoformat(row[7]),
                created_by=row[8],
            )
            for row in rows
        ]

    def find_results_by_tags(self, tag_ids: list[str], match_all: bool = True) -> list[str]:
        """Find result IDs that have the specified tags."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if match_all:
            # Results must have ALL specified tags
            placeholders = ",".join("?" * len(tag_ids))
            cursor.execute(
                f"""
                SELECT result_id FROM result_tags
                WHERE tag_id IN ({placeholders})
                GROUP BY result_id
                HAVING COUNT(DISTINCT tag_id) = ?
            """,
                (*tag_ids, len(tag_ids)),
            )
        else:
            # Results must have ANY of the specified tags
            placeholders = ",".join("?" * len(tag_ids))
            cursor.execute(
                f"""
                SELECT DISTINCT result_id FROM result_tags
                WHERE tag_id IN ({placeholders})
            """,
                tag_ids,
            )

        result_ids = [row[0] for row in cursor.fetchall()]
        conn.close()

        return result_ids

    def suggest_tags(self, content: str) -> list[Tag]:
        """Suggest tags based on content analysis."""
        content_lower = content.lower()
        suggestions = []

        # Simple keyword matching for suggestions
        keyword_tags = {
            "breach": "high-risk",
            "leaked": "high-risk",
            "password": "high-risk",
            "verified": "verified",
            "suspicious": "needs-review",
            "person": "person",
            "company": "organization",
            "organization": "organization",
            "address": "location",
            "server": "infrastructure",
            "domain": "infrastructure",
        }

        for keyword, tag_name in keyword_tags.items():
            if keyword in content_lower:
                tag = self.get_tag_by_name(tag_name)
                if tag and tag not in suggestions:
                    suggestions.append(tag)

        return suggestions[:5]  # Limit to 5 suggestions

    def bulk_tag(self, result_ids: list[str], tag_ids: list[str], added_by: Optional[str] = None):
        """Add multiple tags to multiple results."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.now().isoformat()

        for result_id in result_ids:
            for tag_id in tag_ids:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO result_tags (result_id, tag_id, added_at, added_by)
                    VALUES (?, ?, ?, ?)
                """,
                    (result_id, tag_id, now, added_by),
                )

                if cursor.rowcount > 0:
                    cursor.execute(
                        "UPDATE tags SET usage_count = usage_count + 1 WHERE id = ?", (tag_id,)
                    )

        conn.commit()
        conn.close()


class NotesSystem:
    """
    Manages notes and annotations for search results.

    Features:
    - Rich text notes
    - Note types and categorization
    - Pinned notes
    - Collaboration with mentions
    """

    def __init__(self, db_path: str = "notes.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Notes table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                result_id TEXT NOT NULL,
                content TEXT NOT NULL,
                note_type TEXT NOT NULL,
                title TEXT,
                author TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                is_pinned BOOLEAN DEFAULT 0,
                attachments TEXT,
                mentions TEXT
            )
        """
        )

        # Annotations table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS annotations (
                id TEXT PRIMARY KEY,
                result_id TEXT NOT NULL,
                field_path TEXT NOT NULL,
                start_offset INTEGER,
                end_offset INTEGER,
                highlight_color TEXT,
                comment TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT
            )
        """
        )

        # Bookmarks table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookmarks (
                id TEXT PRIMARY KEY,
                result_id TEXT UNIQUE NOT NULL,
                bookmark_type TEXT NOT NULL,
                label TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT,
                folder TEXT
            )
        """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_result ON notes(result_id)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_annotations_result ON annotations(result_id)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_folder ON bookmarks(folder)")

        conn.commit()
        conn.close()

    def create_note(
        self,
        result_id: str,
        content: str,
        note_type: NoteType = NoteType.GENERAL,
        title: Optional[str] = None,
        author: Optional[str] = None,
        is_pinned: bool = False,
    ) -> Note:
        """Create a new note."""
        note_id = hashlib.sha256(f"{result_id}:{datetime.now().isoformat()}".encode()).hexdigest()[
            :16
        ]

        # Extract mentions (@username)
        mentions = re.findall(r"@(\w+)", content)

        note = Note(
            id=note_id,
            result_id=result_id,
            content=content,
            note_type=note_type,
            title=title,
            author=author,
            is_pinned=is_pinned,
            mentions=mentions,
        )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO notes
            (id, result_id, content, note_type, title, author, created_at, is_pinned, attachments, mentions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                note.id,
                note.result_id,
                note.content,
                note.note_type.value,
                note.title,
                note.author,
                note.created_at.isoformat(),
                note.is_pinned,
                json.dumps(note.attachments),
                json.dumps(note.mentions),
            ),
        )

        conn.commit()
        conn.close()

        return note

    def update_note(
        self,
        note_id: str,
        content: Optional[str] = None,
        title: Optional[str] = None,
        is_pinned: Optional[bool] = None,
    ) -> Optional[Note]:
        """Update an existing note."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        updates = []
        params = []

        if content is not None:
            updates.append("content = ?")
            params.append(content)
            updates.append("mentions = ?")
            params.append(json.dumps(re.findall(r"@(\w+)", content)))

        if title is not None:
            updates.append("title = ?")
            params.append(title)

        if is_pinned is not None:
            updates.append("is_pinned = ?")
            params.append(is_pinned)

        if updates:
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            params.append(note_id)

            cursor.execute(
                f"""
                UPDATE notes SET {', '.join(updates)} WHERE id = ?
            """,
                params,
            )
            conn.commit()

        conn.close()
        return self.get_note(note_id)

    def get_note(self, note_id: str) -> Optional[Note]:
        """Get a note by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Note(
            id=row[0],
            result_id=row[1],
            content=row[2],
            note_type=NoteType(row[3]),
            title=row[4],
            author=row[5],
            created_at=datetime.fromisoformat(row[6]),
            updated_at=datetime.fromisoformat(row[7]) if row[7] else None,
            is_pinned=bool(row[8]),
            attachments=json.loads(row[9]) if row[9] else [],
            mentions=json.loads(row[10]) if row[10] else [],
        )

    def get_result_notes(self, result_id: str, note_type: Optional[NoteType] = None) -> list[Note]:
        """Get all notes for a result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM notes WHERE result_id = ?"
        params = [result_id]

        if note_type:
            query += " AND note_type = ?"
            params.append(note_type.value)

        query += " ORDER BY is_pinned DESC, created_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            Note(
                id=row[0],
                result_id=row[1],
                content=row[2],
                note_type=NoteType(row[3]),
                title=row[4],
                author=row[5],
                created_at=datetime.fromisoformat(row[6]),
                updated_at=datetime.fromisoformat(row[7]) if row[7] else None,
                is_pinned=bool(row[8]),
                attachments=json.loads(row[9]) if row[9] else [],
                mentions=json.loads(row[10]) if row[10] else [],
            )
            for row in rows
        ]

    def delete_note(self, note_id: str):
        """Delete a note."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
        conn.close()

    def create_annotation(
        self,
        result_id: str,
        field_path: str,
        comment: Optional[str] = None,
        start_offset: Optional[int] = None,
        end_offset: Optional[int] = None,
        highlight_color: str = "#ffff00",
        created_by: Optional[str] = None,
    ) -> Annotation:
        """Create a new annotation."""
        annotation_id = hashlib.sha256(
            f"{result_id}:{field_path}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        annotation = Annotation(
            id=annotation_id,
            result_id=result_id,
            field_path=field_path,
            start_offset=start_offset,
            end_offset=end_offset,
            highlight_color=highlight_color,
            comment=comment,
            created_by=created_by,
        )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO annotations
            (id, result_id, field_path, start_offset, end_offset, highlight_color, comment, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                annotation.id,
                annotation.result_id,
                annotation.field_path,
                annotation.start_offset,
                annotation.end_offset,
                annotation.highlight_color,
                annotation.comment,
                annotation.created_at.isoformat(),
                annotation.created_by,
            ),
        )

        conn.commit()
        conn.close()

        return annotation

    def get_result_annotations(self, result_id: str) -> list[Annotation]:
        """Get all annotations for a result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM annotations WHERE result_id = ? ORDER BY field_path, start_offset
        """,
            (result_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [
            Annotation(
                id=row[0],
                result_id=row[1],
                field_path=row[2],
                start_offset=row[3],
                end_offset=row[4],
                highlight_color=row[5],
                comment=row[6],
                created_at=datetime.fromisoformat(row[7]),
                created_by=row[8],
            )
            for row in rows
        ]

    def create_bookmark(
        self,
        result_id: str,
        bookmark_type: BookmarkType = BookmarkType.IMPORTANT,
        label: Optional[str] = None,
        notes: Optional[str] = None,
        folder: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Bookmark:
        """Create or update a bookmark for a result."""
        bookmark_id = hashlib.sha256(result_id.encode()).hexdigest()[:16]

        bookmark = Bookmark(
            id=bookmark_id,
            result_id=result_id,
            bookmark_type=bookmark_type,
            label=label,
            notes=notes,
            folder=folder,
            created_by=created_by,
        )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO bookmarks
            (id, result_id, bookmark_type, label, notes, created_at, created_by, folder)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                bookmark.id,
                bookmark.result_id,
                bookmark.bookmark_type.value,
                bookmark.label,
                bookmark.notes,
                bookmark.created_at.isoformat(),
                bookmark.created_by,
                bookmark.folder,
            ),
        )

        conn.commit()
        conn.close()

        return bookmark

    def get_bookmarks(
        self, folder: Optional[str] = None, bookmark_type: Optional[BookmarkType] = None
    ) -> list[Bookmark]:
        """Get bookmarks with optional filtering."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM bookmarks WHERE 1=1"
        params = []

        if folder:
            query += " AND folder = ?"
            params.append(folder)

        if bookmark_type:
            query += " AND bookmark_type = ?"
            params.append(bookmark_type.value)

        query += " ORDER BY created_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            Bookmark(
                id=row[0],
                result_id=row[1],
                bookmark_type=BookmarkType(row[2]),
                label=row[3],
                notes=row[4],
                created_at=datetime.fromisoformat(row[5]),
                created_by=row[6],
                folder=row[7],
            )
            for row in rows
        ]

    def is_bookmarked(self, result_id: str) -> bool:
        """Check if a result is bookmarked."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM bookmarks WHERE result_id = ?", (result_id,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    def remove_bookmark(self, result_id: str):
        """Remove a bookmark."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM bookmarks WHERE result_id = ?", (result_id,))
        conn.commit()
        conn.close()

    def list_bookmark_folders(self) -> list[str]:
        """List all bookmark folders."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT folder FROM bookmarks WHERE folder IS NOT NULL")
        folders = [row[0] for row in cursor.fetchall()]
        conn.close()
        return folders


class InvestigationManager:
    """
    Manages investigations that group multiple results.

    Features:
    - Investigation creation and management
    - Timeline tracking
    - Collaboration support
    - Export capabilities
    """

    def __init__(self, db_path: str = "investigations.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                result_ids TEXT,
                timeline TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                created_by TEXT,
                collaborators TEXT,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status)"
        )

        conn.commit()
        conn.close()

    def create_investigation(
        self, name: str, description: Optional[str] = None, created_by: Optional[str] = None
    ) -> Investigation:
        """Create a new investigation."""
        investigation_id = hashlib.sha256(
            f"{name}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        investigation = Investigation(
            id=investigation_id, name=name, description=description, created_by=created_by
        )

        self._save_investigation(investigation)
        return investigation

    def _save_investigation(self, investigation: Investigation):
        """Save investigation to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO investigations
            (id, name, description, status, result_ids, timeline, created_at, updated_at, created_by, collaborators, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                investigation.id,
                investigation.name,
                investigation.description,
                investigation.status,
                json.dumps(investigation.result_ids),
                json.dumps(investigation.timeline),
                investigation.created_at.isoformat(),
                investigation.updated_at.isoformat() if investigation.updated_at else None,
                investigation.created_by,
                json.dumps(investigation.collaborators),
                json.dumps(investigation.metadata),
            ),
        )

        conn.commit()
        conn.close()

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        """Get an investigation by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Investigation(
            id=row[0],
            name=row[1],
            description=row[2],
            status=row[3],
            result_ids=json.loads(row[4]) if row[4] else [],
            timeline=json.loads(row[5]) if row[5] else [],
            created_at=datetime.fromisoformat(row[6]),
            updated_at=datetime.fromisoformat(row[7]) if row[7] else None,
            created_by=row[8],
            collaborators=json.loads(row[9]) if row[9] else [],
            metadata=json.loads(row[10]) if row[10] else {},
        )

    def list_investigations(self, status: Optional[str] = None) -> list[Investigation]:
        """List all investigations."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if status:
            cursor.execute(
                "SELECT * FROM investigations WHERE status = ? ORDER BY created_at DESC", (status,)
            )
        else:
            cursor.execute("SELECT * FROM investigations ORDER BY created_at DESC")

        rows = cursor.fetchall()
        conn.close()

        return [
            Investigation(
                id=row[0],
                name=row[1],
                description=row[2],
                status=row[3],
                result_ids=json.loads(row[4]) if row[4] else [],
                timeline=json.loads(row[5]) if row[5] else [],
                created_at=datetime.fromisoformat(row[6]),
                updated_at=datetime.fromisoformat(row[7]) if row[7] else None,
                created_by=row[8],
                collaborators=json.loads(row[9]) if row[9] else [],
                metadata=json.loads(row[10]) if row[10] else {},
            )
            for row in rows
        ]

    def add_result_to_investigation(
        self, investigation_id: str, result_id: str, note: Optional[str] = None
    ) -> Optional[Investigation]:
        """Add a result to an investigation."""
        investigation = self.get_investigation(investigation_id)
        if not investigation:
            return None

        if result_id not in investigation.result_ids:
            investigation.result_ids.append(result_id)

            # Add to timeline
            investigation.timeline.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "action": "result_added",
                    "result_id": result_id,
                    "note": note,
                }
            )

            investigation.updated_at = datetime.now()
            self._save_investigation(investigation)

        return investigation

    def add_timeline_event(
        self,
        investigation_id: str,
        event_type: str,
        description: str,
        metadata: Optional[dict] = None,
    ) -> Optional[Investigation]:
        """Add an event to the investigation timeline."""
        investigation = self.get_investigation(investigation_id)
        if not investigation:
            return None

        investigation.timeline.append(
            {
                "timestamp": datetime.now().isoformat(),
                "type": event_type,
                "description": description,
                "metadata": metadata or {},
            }
        )

        investigation.updated_at = datetime.now()
        self._save_investigation(investigation)

        return investigation

    def update_investigation_status(
        self, investigation_id: str, status: str
    ) -> Optional[Investigation]:
        """Update investigation status."""
        investigation = self.get_investigation(investigation_id)
        if not investigation:
            return None

        investigation.status = status
        investigation.updated_at = datetime.now()

        investigation.timeline.append(
            {
                "timestamp": datetime.now().isoformat(),
                "action": "status_changed",
                "new_status": status,
            }
        )

        self._save_investigation(investigation)
        return investigation

    def add_collaborator(self, investigation_id: str, user_id: str) -> Optional[Investigation]:
        """Add a collaborator to an investigation."""
        investigation = self.get_investigation(investigation_id)
        if not investigation:
            return None

        if user_id not in investigation.collaborators:
            investigation.collaborators.append(user_id)
            investigation.updated_at = datetime.now()
            self._save_investigation(investigation)

        return investigation

    def export_investigation(self, investigation_id: str) -> Optional[dict]:
        """Export investigation with all associated data."""
        investigation = self.get_investigation(investigation_id)
        if not investigation:
            return None

        return {"investigation": investigation.to_dict(), "exported_at": datetime.now().isoformat()}


class AnnotationManager:
    """
    Unified manager for all annotation features.

    Provides a single interface for tagging, notes, bookmarks,
    and investigations.
    """

    def __init__(self, db_path: str = "annotations.db"):
        self.tagging = TaggingSystem(db_path)
        self.notes = NotesSystem(db_path)
        self.investigations = InvestigationManager(db_path)

    def get_result_annotations(self, result_id: str) -> dict:
        """Get all annotations for a result."""
        return {
            "tags": [t.to_dict() for t in self.tagging.get_result_tags(result_id)],
            "notes": [n.to_dict() for n in self.notes.get_result_notes(result_id)],
            "annotations": [a.to_dict() for a in self.notes.get_result_annotations(result_id)],
            "is_bookmarked": self.notes.is_bookmarked(result_id),
        }

    def quick_tag(self, result_id: str, tag_names: list[str], added_by: Optional[str] = None):
        """Quickly add tags by name."""
        for name in tag_names:
            tag = self.tagging.get_tag_by_name(name)
            if not tag:
                # Create custom tag
                tag = self.tagging.create_tag(name, created_by=added_by)
            self.tagging.add_tag_to_result(result_id, tag.id, added_by)

    def quick_note(self, result_id: str, content: str, author: Optional[str] = None) -> Note:
        """Quickly add a note."""
        return self.notes.create_note(result_id, content, author=author)

    def quick_bookmark(self, result_id: str, created_by: Optional[str] = None) -> Bookmark:
        """Quickly bookmark a result."""
        return self.notes.create_bookmark(result_id, created_by=created_by)

    def export_with_annotations(self, result: dict, result_id: str) -> dict:
        """Export a result with all its annotations."""
        annotations = self.get_result_annotations(result_id)
        return {**result, "_annotations": annotations}

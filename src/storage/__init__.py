"""Storage layer for TR4C3R.

This package contains:
- Database models and migrations
- Repository patterns for data access
- Caching layer
- History and result persistence
"""

from src.storage.database import Database

__all__ = ["Database"]

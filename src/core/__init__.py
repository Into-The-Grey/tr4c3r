"""Core functionality for TR4C3R.

This package contains essential components: data models, HTTP client, logging,
orchestrator, and utility functions used across all modules.

New modules:
- cache: Caching layer for search results
- config: Configuration management with validation
- deduplication: Result deduplication utilities
- error_recovery: Error recovery and partial results
- progress: Progress reporting for long operations
- rate_limiter: Rate limiting for external APIs
"""

from .data_models import Result  # noqa: F401
from .http_client import AsyncHTTPClient  # noqa: F401
from .logging_setup import configure_logging  # noqa: F401
from .orchestrator import Orchestrator  # noqa: F401
from .variant_generator import generate_variants  # noqa: F401
from .config import Config, get_config, ValidationResult  # noqa: F401
from .cache import CacheManager, get_cache_manager, cached_search  # noqa: F401
from .deduplication import deduplicate_results, ResultDeduplicator  # noqa: F401
from .rate_limiter import RateLimiter, get_rate_limiter, rate_limited  # noqa: F401
from .progress import ProgressReporter, get_progress_reporter  # noqa: F401
from .error_recovery import (  # noqa: F401
    ErrorRecoveryManager,
    PartialSearchResult,
    SearchError,
    ErrorSeverity,
)

__all__ = [
    # Core
    "Result",
    "AsyncHTTPClient",
    "configure_logging",
    "Orchestrator",
    "generate_variants",
    # Config
    "Config",
    "get_config",
    "ValidationResult",
    # Caching
    "CacheManager",
    "get_cache_manager",
    "cached_search",
    # Deduplication
    "deduplicate_results",
    "ResultDeduplicator",
    # Rate Limiting
    "RateLimiter",
    "get_rate_limiter",
    "rate_limited",
    # Progress
    "ProgressReporter",
    "get_progress_reporter",
    # Error Recovery
    "ErrorRecoveryManager",
    "PartialSearchResult",
    "SearchError",
    "ErrorSeverity",
]

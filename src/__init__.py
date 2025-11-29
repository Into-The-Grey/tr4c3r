"""TR4C3R - Open-Source OSINT Platform.

A modular OSINT suite for searching usernames, emails, names, and phone numbers
across the public web, social media, and the dark web.
"""

__version__ = "0.1.0"
__author__ = "TR4C3R Contributors"

from src.core.orchestrator import Orchestrator
from src.core.data_models import Result

__all__ = ["Orchestrator", "Result", "__version__"]

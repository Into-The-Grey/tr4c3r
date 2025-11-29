"""Search modules for TR4C3R.

Each module provides specialized OSINT search capabilities:
- username: Search across social platforms and code repositories
- email: Query breach databases and email intelligence sources
- name: Find public records and mentions by full name
- phone: Reverse lookup phone numbers
- social: Dedicated social media platform searches
- darkweb: Query dark web indexes via Tor
"""

from .darkweb import DarkWebSearch  # noqa: F401
from .email import EmailSearch  # noqa: F401
from .name import NameSearch  # noqa: F401
from .phone import PhoneSearch  # noqa: F401
from .social import SocialMediaSearch  # noqa: F401
from .username import UsernameSearch  # noqa: F401

__all__ = [
    "UsernameSearch",
    "EmailSearch",
    "NameSearch",
    "PhoneSearch",
    "SocialMediaSearch",
    "DarkWebSearch",
]

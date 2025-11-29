"""Parsing utilities for TR4C3R.

Provides parsers for:
- HTML content
- JSON responses
- API responses
- Social media profiles
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse


@dataclass
class ParsedProfile:
    """Parsed social media profile data."""

    platform: str
    username: Optional[str] = None
    name: Optional[str] = None
    bio: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    posts: Optional[int] = None
    verified: bool = False
    profile_url: Optional[str] = None
    profile_image: Optional[str] = None
    created_at: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class ParsedURL:
    """Parsed URL components."""

    original: str
    scheme: str
    domain: str
    subdomain: Optional[str] = None
    path: str = "/"
    query: dict = field(default_factory=dict)
    fragment: Optional[str] = None
    port: Optional[int] = None


class URLParser:
    """Parses and analyzes URLs."""

    def parse(self, url: str) -> ParsedURL:
        """Parse a URL into components.

        Args:
            url: URL to parse

        Returns:
            ParsedURL with components
        """
        if not url:
            raise ValueError("URL cannot be empty")

        # Add scheme if missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "https://" + url

        parsed = urlparse(url)

        # Extract domain parts
        domain_parts = parsed.netloc.split(".")
        if len(domain_parts) > 2:
            subdomain = ".".join(domain_parts[:-2])
            domain = ".".join(domain_parts[-2:])
        else:
            subdomain = None
            domain = parsed.netloc

        # Handle port
        port = None
        if ":" in domain:
            domain, port_str = domain.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass

        # Parse query string
        query = parse_qs(parsed.query)
        # Flatten single-value lists
        query = {k: v[0] if len(v) == 1 else v for k, v in query.items()}

        return ParsedURL(
            original=url,
            scheme=parsed.scheme,
            domain=domain,
            subdomain=subdomain,
            path=parsed.path or "/",
            query=query,
            fragment=parsed.fragment or None,
            port=port,
        )

    def extract_platform(self, url: str) -> Optional[str]:
        """Extract social media platform from URL.

        Args:
            url: URL to analyze

        Returns:
            Platform name or None
        """
        platform_patterns = {
            "twitter": [r"twitter\.com", r"x\.com"],
            "facebook": [r"facebook\.com", r"fb\.com"],
            "instagram": [r"instagram\.com"],
            "linkedin": [r"linkedin\.com"],
            "github": [r"github\.com"],
            "reddit": [r"reddit\.com"],
            "youtube": [r"youtube\.com", r"youtu\.be"],
            "tiktok": [r"tiktok\.com"],
            "pinterest": [r"pinterest\.com"],
            "tumblr": [r"tumblr\.com"],
            "medium": [r"medium\.com"],
            "telegram": [r"t\.me", r"telegram\.me"],
            "discord": [r"discord\.gg", r"discord\.com"],
        }

        url_lower = url.lower()

        for platform, patterns in platform_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return platform

        return None

    def extract_username_from_url(self, url: str) -> Optional[str]:
        """Extract username from social media URL.

        Args:
            url: Social media profile URL

        Returns:
            Username or None
        """
        parsed = self.parse(url)
        path = parsed.path.strip("/")

        if not path:
            return None

        # Common patterns
        # Direct username: twitter.com/username
        if "/" not in path:
            # Exclude common non-username paths
            if path.lower() not in ["home", "explore", "search", "settings", "about", "help"]:
                return path

        # Profile path: instagram.com/p/username or github.com/users/username
        parts = path.split("/")
        if len(parts) >= 2:
            # GitHub pattern: /users/username
            if parts[0] in ["user", "users", "u", "profile"]:
                return parts[1]
            # Instagram/Twitter pattern: first part is username
            if parts[0] not in ["p", "post", "status", "explore", "search"]:
                return parts[0]

        return parts[0] if parts else None


class HTMLParser:
    """Simple HTML content parser."""

    @staticmethod
    def extract_text(html: str) -> str:
        """Extract plain text from HTML.

        Args:
            html: HTML content

        Returns:
            Plain text
        """
        if not html:
            return ""

        # Remove script and style elements
        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)

        # Replace common block elements with newlines
        html = re.sub(r"<(p|div|br|h[1-6]|li|tr)[^>]*>", "\n", html, flags=re.IGNORECASE)

        # Remove all remaining tags
        html = re.sub(r"<[^>]+>", "", html)

        # Decode common entities
        html = html.replace("&nbsp;", " ")
        html = html.replace("&amp;", "&")
        html = html.replace("&lt;", "<")
        html = html.replace("&gt;", ">")
        html = html.replace("&quot;", '"')
        html = html.replace("&#39;", "'")

        # Clean up whitespace
        html = re.sub(r"\n\s*\n", "\n\n", html)
        html = re.sub(r" +", " ", html)

        return html.strip()

    @staticmethod
    def extract_links(html: str) -> list[dict[str, str]]:
        """Extract all links from HTML.

        Args:
            html: HTML content

        Returns:
            List of link dictionaries with href and text
        """
        if not html:
            return []

        pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
        matches = re.findall(pattern, html, flags=re.DOTALL | re.IGNORECASE)

        links = []
        for href, text in matches:
            # Clean text
            text = HTMLParser.extract_text(text)
            links.append(
                {
                    "href": href,
                    "text": text.strip(),
                }
            )

        return links

    @staticmethod
    def extract_emails(html: str) -> list[str]:
        """Extract email addresses from HTML.

        Args:
            html: HTML content

        Returns:
            List of email addresses
        """
        if not html:
            return []

        # Get plain text first
        text = HTMLParser.extract_text(html)

        # Find emails
        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails = re.findall(pattern, text)

        return list(set(emails))

    @staticmethod
    def extract_meta(html: str) -> dict[str, str]:
        """Extract meta tags from HTML.

        Args:
            html: HTML content

        Returns:
            Dictionary of meta tag name/content pairs
        """
        if not html:
            return {}

        meta = {}

        # Standard meta tags
        pattern = r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']'
        for name, content in re.findall(pattern, html, flags=re.IGNORECASE):
            meta[name] = content

        # Reverse order (content before name)
        pattern = r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']([^"\']+)["\']'
        for content, name in re.findall(pattern, html, flags=re.IGNORECASE):
            meta[name] = content

        # OpenGraph tags
        pattern = r'<meta[^>]+property=["\']og:([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']'
        for name, content in re.findall(pattern, html, flags=re.IGNORECASE):
            meta[f"og:{name}"] = content

        # Twitter cards
        pattern = r'<meta[^>]+name=["\']twitter:([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']'
        for name, content in re.findall(pattern, html, flags=re.IGNORECASE):
            meta[f"twitter:{name}"] = content

        return meta


class JSONParser:
    """JSON response parser with path access."""

    def __init__(self, data: Any):
        """Initialize parser with data.

        Args:
            data: JSON data (string or parsed)
        """
        if isinstance(data, str):
            self.data = json.loads(data)
        else:
            self.data = data

    def get(self, path: str, default: Any = None) -> Any:
        """Get value at path.

        Args:
            path: Dot-separated path (e.g., "user.profile.name")
            default: Default value if path not found

        Returns:
            Value at path or default
        """
        current = self.data

        for key in path.split("."):
            if isinstance(current, dict):
                if key in current:
                    current = current[key]
                else:
                    return default
            elif isinstance(current, list):
                try:
                    index = int(key)
                    current = current[index]
                except (ValueError, IndexError):
                    return default
            else:
                return default

        return current

    def find_all(self, key: str) -> list[Any]:
        """Find all values for a key recursively.

        Args:
            key: Key to search for

        Returns:
            List of all values found
        """
        results = []
        self._find_recursive(self.data, key, results)
        return results

    def _find_recursive(self, obj: Any, key: str, results: list) -> None:
        """Recursively search for key."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key:
                    results.append(v)
                self._find_recursive(v, key, results)
        elif isinstance(obj, list):
            for item in obj:
                self._find_recursive(item, key, results)

    def extract(self, mappings: dict[str, str]) -> dict[str, Any]:
        """Extract multiple values using path mappings.

        Args:
            mappings: Dictionary of {output_key: path}

        Returns:
            Dictionary of extracted values
        """
        result = {}
        for output_key, path in mappings.items():
            result[output_key] = self.get(path)
        return result


class ProfileParser:
    """Parses social media profile data."""

    def __init__(self):
        """Initialize profile parser."""
        self.url_parser = URLParser()

    def parse_twitter(self, data: dict) -> ParsedProfile:
        """Parse Twitter API response.

        Args:
            data: Twitter API user data

        Returns:
            ParsedProfile
        """
        return ParsedProfile(
            platform="twitter",
            username=data.get("screen_name") or data.get("username"),
            name=data.get("name"),
            bio=data.get("description"),
            location=data.get("location"),
            website=data.get("url"),
            followers=data.get("followers_count"),
            following=data.get("friends_count"),
            posts=data.get("statuses_count"),
            verified=data.get("verified", False),
            profile_url=f"https://twitter.com/{data.get('screen_name', '')}",
            profile_image=data.get("profile_image_url_https"),
            created_at=data.get("created_at"),
        )

    def parse_github(self, data: dict) -> ParsedProfile:
        """Parse GitHub API response.

        Args:
            data: GitHub API user data

        Returns:
            ParsedProfile
        """
        return ParsedProfile(
            platform="github",
            username=data.get("login"),
            name=data.get("name"),
            bio=data.get("bio"),
            location=data.get("location"),
            website=data.get("blog"),
            followers=data.get("followers"),
            following=data.get("following"),
            posts=data.get("public_repos"),
            verified=False,
            profile_url=data.get("html_url"),
            profile_image=data.get("avatar_url"),
            created_at=data.get("created_at"),
            extra={
                "company": data.get("company"),
                "email": data.get("email"),
                "hireable": data.get("hireable"),
                "gists": data.get("public_gists"),
            },
        )

    def parse_generic(self, data: dict, platform: str) -> ParsedProfile:
        """Parse generic profile data.

        Args:
            data: Profile data dictionary
            platform: Platform name

        Returns:
            ParsedProfile
        """
        # Common field mappings
        username_fields = ["username", "screen_name", "login", "handle", "user_name"]
        name_fields = ["name", "full_name", "display_name", "displayName"]
        bio_fields = ["bio", "description", "about", "summary"]

        def find_field(fields: list[str]) -> Optional[str]:
            for f in fields:
                if f in data and data[f]:
                    return data[f]
            return None

        return ParsedProfile(
            platform=platform,
            username=find_field(username_fields),
            name=find_field(name_fields),
            bio=find_field(bio_fields),
            location=data.get("location"),
            website=data.get("website") or data.get("url"),
            followers=data.get("followers") or data.get("followers_count"),
            following=data.get("following") or data.get("following_count"),
            verified=data.get("verified", False),
            profile_image=data.get("avatar") or data.get("profile_image"),
        )


# Singleton instances
_url_parser = URLParser()
_html_parser = HTMLParser()
_profile_parser = ProfileParser()


def parse_url(url: str) -> ParsedURL:
    """Parse a URL."""
    return _url_parser.parse(url)


def extract_platform(url: str) -> Optional[str]:
    """Extract platform from URL."""
    return _url_parser.extract_platform(url)


def extract_username(url: str) -> Optional[str]:
    """Extract username from social media URL."""
    return _url_parser.extract_username_from_url(url)


def parse_html_text(html: str) -> str:
    """Extract text from HTML."""
    return HTMLParser.extract_text(html)


def parse_html_links(html: str) -> list[dict[str, str]]:
    """Extract links from HTML."""
    return HTMLParser.extract_links(html)


def parse_html_emails(html: str) -> list[str]:
    """Extract emails from HTML."""
    return HTMLParser.extract_emails(html)


def parse_json(data: Any, path: Optional[str] = None, default: Any = None) -> Any:
    """Parse JSON and optionally get value at path."""
    parser = JSONParser(data)
    if path:
        return parser.get(path, default)
    return parser.data


def parse_profile(data: dict, platform: str) -> ParsedProfile:
    """Parse profile data for a platform."""
    if platform == "twitter":
        return _profile_parser.parse_twitter(data)
    elif platform == "github":
        return _profile_parser.parse_github(data)
    else:
        return _profile_parser.parse_generic(data, platform)

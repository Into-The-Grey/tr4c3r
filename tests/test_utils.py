"""Tests for utility modules."""

import pytest

from src.utils.validators import (
    InputValidator,
    ValidationResult,
    detect_input_type,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ip,
    validate_phone,
    validate_url,
    validate_username,
)
from src.utils.formatters import (
    CSVFormatter,
    JSONFormatter,
    MarkdownFormatter,
    OutputFormat,
    ReportGenerator,
    TableFormatter,
    to_csv,
    to_json,
    to_markdown,
    to_table,
)
from src.utils.parsers import (
    HTMLParser,
    JSONParser,
    ParsedProfile,
    ProfileParser,
    URLParser,
    extract_platform,
    extract_username,
    parse_html_emails,
    parse_html_links,
    parse_html_text,
    parse_json,
    parse_url,
)


class TestEmailValidation:
    """Tests for email validation."""

    def test_valid_email(self):
        """Test valid email addresses."""
        result = validate_email("user@example.com")
        assert result.valid is True
        assert result.normalized == "user@example.com"
        assert result.details["domain"] == "example.com"
        assert result.details["tld"] == "com"

    def test_valid_email_with_plus(self):
        """Test email with plus addressing."""
        result = validate_email("user+tag@example.com")
        assert result.valid is True

    def test_invalid_email_no_at(self):
        """Test email without @ symbol."""
        result = validate_email("userexample.com")
        assert result.valid is False
        assert "Invalid" in result.error

    def test_invalid_email_no_domain(self):
        """Test email without domain."""
        result = validate_email("user@")
        assert result.valid is False

    def test_empty_email(self):
        """Test empty email."""
        result = validate_email("")
        assert result.valid is False
        assert "empty" in result.error.lower()

    def test_email_normalization(self):
        """Test email is lowercased."""
        result = validate_email("USER@EXAMPLE.COM")
        assert result.normalized == "user@example.com"


class TestPhoneValidation:
    """Tests for phone validation."""

    def test_valid_us_phone(self):
        """Test valid US phone number."""
        result = validate_phone("+14155551234")
        assert result.valid is True
        assert result.details["length"] == 11

    def test_phone_with_separators(self):
        """Test phone with various separators."""
        result = validate_phone("+1 (415) 555-1234")
        assert result.valid is True
        assert result.normalized == "+14155551234"

    def test_international_phone(self):
        """Test international phone number."""
        result = validate_phone("+44 20 7946 0958")
        assert result.valid is True

    def test_phone_too_short(self):
        """Test phone number too short."""
        result = validate_phone("12345")
        assert result.valid is False
        assert "7-15 digits" in result.error

    def test_phone_with_letters(self):
        """Test phone with non-digits."""
        result = validate_phone("+1-555-CALL")
        assert result.valid is False


class TestUsernameValidation:
    """Tests for username validation."""

    def test_valid_username(self):
        """Test valid username."""
        result = validate_username("john_doe")
        assert result.valid is True
        assert result.normalized == "john_doe"

    def test_username_with_numbers(self):
        """Test username with numbers."""
        result = validate_username("user123")
        assert result.valid is True

    def test_username_too_short(self):
        """Test username too short."""
        result = validate_username("ab")
        assert result.valid is False
        assert "at least 3" in result.error

    def test_username_too_long(self):
        """Test username too long."""
        result = validate_username("a" * 35)
        assert result.valid is False
        assert "at most 30" in result.error

    def test_username_invalid_chars(self):
        """Test username with invalid characters."""
        result = validate_username("user@name")
        assert result.valid is False


class TestURLValidation:
    """Tests for URL validation."""

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        result = validate_url("https://example.com/path")
        assert result.valid is True
        assert result.details["scheme"] == "https"
        assert result.details["domain"] == "example.com"

    def test_url_without_scheme(self):
        """Test URL without scheme gets HTTPS added."""
        result = validate_url("example.com")
        assert result.valid is True
        assert result.normalized.startswith("https://")

    def test_url_with_query(self):
        """Test URL with query parameters."""
        result = validate_url("https://example.com?q=test")
        assert result.valid is True
        assert result.details["query"] == "q=test"

    def test_empty_url(self):
        """Test empty URL."""
        result = validate_url("")
        assert result.valid is False


class TestIPValidation:
    """Tests for IP validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4 address."""
        result = validate_ip("192.168.1.1")
        assert result.valid is True
        assert result.details["version"] == 4

    def test_valid_ipv6(self):
        """Test valid IPv6 address."""
        result = validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result.valid is True
        assert result.details["version"] == 6

    def test_invalid_ipv4(self):
        """Test invalid IPv4."""
        result = validate_ip("256.1.1.1")
        assert result.valid is False

    def test_localhost(self):
        """Test localhost IP."""
        result = validate_ip("127.0.0.1")
        assert result.valid is True


class TestDomainValidation:
    """Tests for domain validation."""

    def test_valid_domain(self):
        """Test valid domain."""
        result = validate_domain("example.com")
        assert result.valid is True
        assert result.details["tld"] == "com"

    def test_subdomain(self):
        """Test domain with subdomain."""
        result = validate_domain("www.example.com")
        assert result.valid is True
        assert result.details["subdomain"] == "www"

    def test_domain_from_url(self):
        """Test extracting domain from URL."""
        result = validate_domain("https://example.com/path")
        assert result.valid is True
        assert result.normalized == "example.com"


class TestHashValidation:
    """Tests for hash validation."""

    def test_md5_hash(self):
        """Test MD5 hash."""
        result = validate_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result.valid is True
        assert result.details["type"] == "md5"

    def test_sha1_hash(self):
        """Test SHA1 hash."""
        result = validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert result.valid is True
        assert result.details["type"] == "sha1"

    def test_sha256_hash(self):
        """Test SHA256 hash."""
        result = validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result.valid is True
        assert result.details["type"] == "sha256"

    def test_invalid_hash(self):
        """Test invalid hash."""
        result = validate_hash("not-a-hash")
        assert result.valid is False


class TestInputTypeDetection:
    """Tests for input type detection."""

    def test_detect_email(self):
        """Test detecting email."""
        input_type, result = detect_input_type("user@example.com")
        assert input_type == "email"
        assert result.valid is True

    def test_detect_url(self):
        """Test detecting URL."""
        input_type, result = detect_input_type("https://example.com")
        assert input_type == "url"

    def test_detect_ip(self):
        """Test detecting IP."""
        input_type, result = detect_input_type("192.168.1.1")
        assert input_type == "ip"

    def test_detect_phone(self):
        """Test detecting phone."""
        input_type, result = detect_input_type("+14155551234")
        assert input_type == "phone"

    def test_detect_username(self):
        """Test detecting username."""
        input_type, result = detect_input_type("john_doe")
        assert input_type == "username"


class TestJSONFormatter:
    """Tests for JSON formatter."""

    def test_format_dict(self):
        """Test formatting dictionary."""
        data = {"name": "John", "age": 30}
        result = to_json(data)
        assert '"name": "John"' in result
        assert '"age": 30' in result

    def test_format_list(self):
        """Test formatting list."""
        data = [{"a": 1}, {"a": 2}]
        result = to_json(data)
        assert '"a": 1' in result


class TestTableFormatter:
    """Tests for table formatter."""

    def test_format_table(self):
        """Test formatting as table."""
        data = [
            {"name": "John", "age": 30},
            {"name": "Jane", "age": 25},
        ]
        result = to_table(data)
        assert "Name" in result
        assert "Age" in result
        assert "John" in result
        assert "Jane" in result

    def test_empty_data(self):
        """Test with empty data."""
        result = to_table([])
        assert "no data" in result


class TestCSVFormatter:
    """Tests for CSV formatter."""

    def test_format_csv(self):
        """Test formatting as CSV."""
        data = [
            {"name": "John", "age": 30},
            {"name": "Jane", "age": 25},
        ]
        result = to_csv(data)
        assert "name,age" in result
        assert "John,30" in result


class TestMarkdownFormatter:
    """Tests for Markdown formatter."""

    def test_format_markdown_table(self):
        """Test formatting as Markdown table."""
        data = [
            {"name": "John", "age": 30},
        ]
        result = to_markdown(data)
        assert "| Name | Age |" in result
        assert "| --- |" in result
        assert "| John | 30 |" in result


class TestURLParser:
    """Tests for URL parser."""

    def test_parse_url(self):
        """Test parsing URL."""
        result = parse_url("https://www.example.com/path?q=test")
        assert result.scheme == "https"
        assert result.domain == "example.com"
        assert result.subdomain == "www"
        assert result.path == "/path"
        assert result.query == {"q": "test"}

    def test_extract_platform(self):
        """Test extracting platform from URL."""
        assert extract_platform("https://twitter.com/user") == "twitter"
        assert extract_platform("https://github.com/user") == "github"
        assert extract_platform("https://example.com") is None

    def test_extract_username(self):
        """Test extracting username from URL."""
        assert extract_username("https://twitter.com/johndoe") == "johndoe"
        assert extract_username("https://github.com/users/octocat") == "octocat"


class TestHTMLParser:
    """Tests for HTML parser."""

    def test_extract_text(self):
        """Test extracting text from HTML."""
        html = "<p>Hello <b>World</b></p>"
        result = parse_html_text(html)
        assert "Hello" in result
        assert "World" in result
        assert "<" not in result

    def test_extract_links(self):
        """Test extracting links from HTML."""
        html = '<a href="https://example.com">Link</a>'
        links = parse_html_links(html)
        assert len(links) == 1
        assert links[0]["href"] == "https://example.com"
        assert links[0]["text"] == "Link"

    def test_extract_emails(self):
        """Test extracting emails from HTML."""
        html = "<p>Contact us at test@example.com</p>"
        emails = parse_html_emails(html)
        assert "test@example.com" in emails


class TestJSONParser:
    """Tests for JSON parser."""

    def test_parse_and_get(self):
        """Test parsing and getting value."""
        data = {"user": {"name": "John", "age": 30}}
        result = parse_json(data, "user.name")
        assert result == "John"

    def test_get_nested_array(self):
        """Test getting from nested array."""
        data = {"users": [{"name": "John"}, {"name": "Jane"}]}
        parser = JSONParser(data)
        assert parser.get("users.0.name") == "John"
        assert parser.get("users.1.name") == "Jane"

    def test_find_all(self):
        """Test finding all values for a key."""
        data = {
            "users": [
                {"name": "John"},
                {"name": "Jane"},
            ]
        }
        parser = JSONParser(data)
        names = parser.find_all("name")
        assert "John" in names
        assert "Jane" in names


class TestReportGenerator:
    """Tests for report generator."""

    def test_generate_json_report(self):
        """Test generating JSON report."""
        data = {"status": "success"}
        report = ReportGenerator()
        result = report.generate(data, OutputFormat.JSON)
        assert '"status": "success"' in result

    def test_generate_report_with_title(self):
        """Test generating report with title."""
        data = {"status": "ok"}
        report = ReportGenerator()
        result = report.generate(data, OutputFormat.TEXT, title="Test Report")
        assert "Test Report" in result


class TestProfileParser:
    """Tests for profile parser."""

    def test_parse_github_profile(self):
        """Test parsing GitHub profile."""
        data = {
            "login": "octocat",
            "name": "The Octocat",
            "bio": "GitHub mascot",
            "followers": 1000,
            "following": 10,
            "html_url": "https://github.com/octocat",
        }

        parser = ProfileParser()
        profile = parser.parse_github(data)

        assert profile.platform == "github"
        assert profile.username == "octocat"
        assert profile.name == "The Octocat"
        assert profile.followers == 1000

    def test_parse_generic_profile(self):
        """Test parsing generic profile."""
        data = {
            "username": "testuser",
            "full_name": "Test User",
            "description": "Just testing",
        }

        parser = ProfileParser()
        profile = parser.parse_generic(data, "unknown")

        assert profile.username == "testuser"
        assert profile.name == "Test User"
        assert profile.bio == "Just testing"

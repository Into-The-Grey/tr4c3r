"""Utility modules for TR4C3R.

This package provides common utilities for:
- Input validation
- Output formatting
- Content parsing
"""

from src.utils.formatters import (
    CSVFormatter,
    DataFormatter,
    JSONFormatter,
    MarkdownFormatter,
    OutputFormat,
    ReportGenerator,
    TableFormatter,
    generate_report,
    to_csv,
    to_json,
    to_markdown,
    to_table,
)
from src.utils.parsers import (
    HTMLParser,
    JSONParser,
    ParsedProfile,
    ParsedURL,
    ProfileParser,
    URLParser,
    extract_platform,
    extract_username,
    parse_html_emails,
    parse_html_links,
    parse_html_text,
    parse_json,
    parse_profile,
    parse_url,
)
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

__all__ = [
    # Validators
    "InputValidator",
    "ValidationResult",
    "validate_email",
    "validate_phone",
    "validate_username",
    "validate_url",
    "validate_ip",
    "validate_domain",
    "validate_hash",
    "detect_input_type",
    # Formatters
    "DataFormatter",
    "JSONFormatter",
    "TableFormatter",
    "CSVFormatter",
    "MarkdownFormatter",
    "ReportGenerator",
    "OutputFormat",
    "to_json",
    "to_table",
    "to_csv",
    "to_markdown",
    "generate_report",
    # Parsers
    "URLParser",
    "HTMLParser",
    "JSONParser",
    "ProfileParser",
    "ParsedURL",
    "ParsedProfile",
    "parse_url",
    "extract_platform",
    "extract_username",
    "parse_html_text",
    "parse_html_links",
    "parse_html_emails",
    "parse_json",
    "parse_profile",
]

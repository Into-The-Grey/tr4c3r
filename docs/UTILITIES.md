# TR4C3R Utility Modules

Comprehensive utility modules for input validation, output formatting, and content parsing.

## Overview

The utility modules provide:

- **Input Validation**: Validate OSINT data types (emails, phones, URLs, IPs, etc.)
- **Output Formatting**: Format results as JSON, tables, CSV, or reports
- **Content Parsing**: Parse HTML, JSON, and API responses

## Input Validation

### InputValidator

Validates various OSINT-relevant data types with detailed error reporting.

```python
from src.utils import InputValidator, ValidationResult

# Create validator
validator = InputValidator()

# Validate email
result = validator.validate_email("user@example.com")
if result.is_valid:
    print(f"Valid email: {result.normalized_value}")
else:
    print(f"Invalid: {result.errors}")

# Validate phone number
result = validator.validate_phone("+1-555-123-4567")
# result.normalized_value = "+15551234567"

# Validate URL
result = validator.validate_url("https://example.com/path")
# result.metadata = {"scheme": "https", "domain": "example.com", ...}

# Validate IP address
result = validator.validate_ip("192.168.1.1")
# result.metadata = {"version": 4, "is_private": True, ...}

# Validate username
result = validator.validate_username("john_doe123")
# Checks length, allowed characters, reserved words
```

### Supported Validation Types

| Type | Method | Features |
|------|--------|----------|
| Email | `validate_email()` | Format check, disposable detection |
| Phone | `validate_phone()` | International format, normalization |
| Username | `validate_username()` | Length, characters, reserved words |
| URL | `validate_url()` | Scheme validation, domain extraction |
| IP Address | `validate_ip()` | IPv4/IPv6, private/public detection |
| Domain | `validate_domain()` | Format, TLD validation |
| Hash | `validate_hash()` | MD5, SHA1, SHA256, SHA512 detection |
| Crypto Wallet | `validate_crypto_wallet()` | Bitcoin, Ethereum, Litecoin |
| MAC Address | `validate_mac_address()` | Format normalization |
| Credit Card | `validate_credit_card()` | Luhn algorithm, card type |
| SSN | `validate_ssn()` | Format validation |
| Date | `validate_date()` | Multiple format support |

### ValidationResult

```python
@dataclass
class ValidationResult:
    is_valid: bool           # Whether validation passed
    errors: List[str]        # List of error messages
    warnings: List[str]      # Non-fatal warnings
    normalized_value: Any    # Cleaned/normalized value
    metadata: Dict[str, Any] # Additional extracted info
```

### Batch Validation

```python
# Validate multiple inputs
inputs = [
    ("email", "user@example.com"),
    ("phone", "+1-555-1234"),
    ("url", "https://example.com")
]

results = validator.validate_batch(inputs)
for (input_type, value), result in zip(inputs, results):
    print(f"{input_type}: {result.is_valid}")
```

## Output Formatting

### JSONFormatter

Pretty-print JSON with customization options.

```python
from src.utils import JSONFormatter

formatter = JSONFormatter(indent=2, sort_keys=True)

# Format dictionary
data = {"name": "John", "results": [1, 2, 3]}
json_str = formatter.format(data)

# Format with custom options
json_str = formatter.format(data, compact=True)

# Safe format (handles non-serializable types)
data_with_datetime = {"timestamp": datetime.now()}
json_str = formatter.safe_format(data_with_datetime)
```

### TableFormatter

Create ASCII tables for terminal output.

```python
from src.utils import TableFormatter

formatter = TableFormatter()

# Create table from data
headers = ["Name", "Email", "Status"]
rows = [
    ["John Doe", "john@example.com", "Active"],
    ["Jane Smith", "jane@example.com", "Inactive"]
]

table = formatter.format(headers, rows)
print(table)
# +------------+------------------+----------+
# | Name       | Email            | Status   |
# +------------+------------------+----------+
# | John Doe   | john@example.com | Active   |
# | Jane Smith | jane@example.com | Inactive |
# +------------+------------------+----------+

# With alignment
table = formatter.format(
    headers, rows,
    alignments=["left", "left", "center"]
)

# Maximum column width
table = formatter.format(headers, rows, max_width=20)
```

### CSVFormatter

Export data to CSV format.

```python
from src.utils import CSVFormatter

formatter = CSVFormatter()

# Format to CSV string
headers = ["name", "email", "phone"]
rows = [
    ["John Doe", "john@example.com", "+1-555-1234"],
    ["Jane Smith", "jane@example.com", "+1-555-5678"]
]

csv_str = formatter.format(headers, rows)

# Write to file
formatter.to_file(headers, rows, "output.csv")

# From dictionaries
data = [
    {"name": "John", "email": "john@example.com"},
    {"name": "Jane", "email": "jane@example.com"}
]
csv_str = formatter.from_dicts(data)
```

### ReportGenerator

Generate formatted investigation reports.

```python
from src.utils import ReportGenerator

generator = ReportGenerator()

# Build report
report = generator.generate(
    title="Investigation Report: john_doe",
    sections=[
        {
            "title": "Summary",
            "content": "Target identified across 5 platforms..."
        },
        {
            "title": "Social Media Profiles",
            "content": "| Platform | Username | URL |\n|---|---|---|"
        },
        {
            "title": "Timeline",
            "content": "- 2020-01-15: Account created on Twitter..."
        }
    ],
    metadata={
        "investigator": "analyst@example.com",
        "date": "2024-01-15",
        "classification": "CONFIDENTIAL"
    }
)

# Save to file
generator.save(report, "report.md")
```

## Content Parsing

### HTMLParser

Extract information from HTML content.

```python
from src.utils import HTMLParser

parser = HTMLParser()

# Extract all links
html = '<a href="https://example.com">Link</a>'
links = parser.extract_links(html)
# [{"url": "https://example.com", "text": "Link"}]

# Extract text content
html = "<p>Hello <b>World</b></p>"
text = parser.extract_text(html)
# "Hello World"

# Extract by CSS selector
html = '<div class="profile"><span class="name">John</span></div>'
elements = parser.select(html, ".profile .name")
# ["John"]

# Extract metadata
html = '<meta name="description" content="Page description">'
meta = parser.extract_metadata(html)
# {"description": "Page description"}

# Extract structured data
html = '<script type="application/ld+json">{"@type": "Person"}</script>'
data = parser.extract_structured_data(html)
```

### JSONParser

Parse and normalize JSON with error handling.

```python
from src.utils import JSONParser

parser = JSONParser()

# Safe parse (never throws)
result = parser.safe_parse('{"key": "value"}')
if result.success:
    data = result.data
else:
    print(f"Error: {result.error}")

# Normalize nested structures
data = {"user": {"name": "John", "profile": {"age": 30}}}
flat = parser.flatten(data)
# {"user.name": "John", "user.profile.age": 30}

# Extract by path
value = parser.get_path(data, "user.profile.age")
# 30

# Merge multiple JSON objects
merged = parser.merge(
    {"a": 1, "b": 2},
    {"b": 3, "c": 4}
)
# {"a": 1, "b": 3, "c": 4}
```

### APIResponseParser

Parse and normalize API responses from various sources.

```python
from src.utils import APIResponseParser

parser = APIResponseParser()

# Parse generic API response
response = {
    "status": "success",
    "data": {"users": [...]},
    "meta": {"total": 100}
}
parsed = parser.parse(response)
# Normalized structure with data, errors, metadata

# Extract pagination info
pagination = parser.extract_pagination(response)
# {"total": 100, "page": 1, "per_page": 20, "has_more": True}

# Handle error responses
error_response = {
    "error": {"code": 404, "message": "Not found"}
}
parsed = parser.parse(error_response)
# parsed.is_error = True, parsed.error_message = "Not found"
```

### SocialProfileParser

Parse social media profile data.

```python
from src.utils import SocialProfileParser

parser = SocialProfileParser()

# Parse Twitter profile
twitter_data = {
    "screen_name": "johndoe",
    "name": "John Doe",
    "followers_count": 1000,
    ...
}
profile = parser.parse_twitter(twitter_data)

# Parse Instagram profile
instagram_data = {...}
profile = parser.parse_instagram(instagram_data)

# Generic profile parsing
profile = parser.parse_generic(data, platform="unknown")
```

## Best Practices

### Best Practices: Input Validation

```python
# Always validate user input before processing
def search_username(username: str):
    validator = InputValidator()
    result = validator.validate_username(username)
    
    if not result.is_valid:
        raise ValueError(f"Invalid username: {result.errors}")
    
    # Use normalized value for consistency
    normalized = result.normalized_value
    return perform_search(normalized)
```

### Error Handling

```python
# Use safe methods for untrusted data
parser = JSONParser()

# This won't throw even with invalid JSON
result = parser.safe_parse(untrusted_data)
if not result.success:
    log.warning(f"Failed to parse JSON: {result.error}")
    return default_value
```

### Report Generation

```python
# Generate investigation reports
def generate_report(investigation_results: dict):
    generator = ReportGenerator()
    
    sections = []
    
    # Add summary
    sections.append({
        "title": "Executive Summary",
        "content": summarize(investigation_results)
    })
    
    # Add findings as table
    table_formatter = TableFormatter()
    findings_table = table_formatter.format(
        ["Source", "Finding", "Confidence"],
        investigation_results["findings"]
    )
    sections.append({
        "title": "Detailed Findings",
        "content": findings_table
    })
    
    return generator.generate(
        title=f"Investigation: {investigation_results['target']}",
        sections=sections
    )
```

## Module Exports

```python
from src.utils import (
    # Validation
    InputValidator,
    ValidationResult,
    
    # Formatting
    JSONFormatter,
    TableFormatter,
    CSVFormatter,
    ReportGenerator,
    
    # Parsing
    HTMLParser,
    JSONParser,
    APIResponseParser,
    SocialProfileParser,
)
```

## Testing

```bash
# Run utility tests
pipenv run pytest tests/test_utils.py -v

# Run with coverage
pipenv run pytest tests/test_utils.py --cov=src/utils
```

## See Also

- [API Documentation](API.md)
- [Data Models](../src/core/data_models.py)
- [Security Guidelines](SECURITY_GUIDELINES_SUMMARY.md)

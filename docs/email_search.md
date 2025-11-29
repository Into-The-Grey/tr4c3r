# Email Search Module

## Overview

The Email Search module provides comprehensive OSINT capabilities for email addresses, including validation, breach detection, domain verification, and reputation analysis.

## Features

### ✅ Email Validation

- **Format Validation**: RFC-compliant email format checking using regex
- **Domain Extraction**: Separates username and domain components
- **Disposable Email Detection**: Identifies temporary/throwaway email services
- **Role-Based Email Detection**: Flags common role accounts (admin, support, noreply, etc.)
- **Case Normalization**: Converts emails to lowercase for consistent processing

### ✅ HaveIBeenPwned Integration

- **Privacy-First**: Uses k-anonymity API (range queries) to protect email addresses
- **Breach Detection**: Checks if email appears in known data breaches
- **SHA-1 Hashing**: Securely hashes emails before querying
- **Breach Count**: Reports number of breaches found

### ✅ Hunter.io Integration

- **Email Verification**: Verifies if email addresses are valid and deliverable
- **MX Record Checks**: Validates mail server configuration
- **SMTP Verification**: Tests if email server accepts mail
- **Deliverability Score**: Provides confidence score for email validity
- **Metadata Extraction**: Includes free/disposable/accept-all flags

### ✅ Email Reputation Checks

- **Provider Detection**: Identifies major email providers (Gmail, Yahoo, Outlook, etc.)
- **Reputation Scoring**: Calculates trust score based on multiple factors
- **Risk Assessment**: Flags disposable and role-based emails
- **Domain Analysis**: Evaluates email domain characteristics

## Configuration

### API Keys

Add the following to your `.env` file:

```bash
# HaveIBeenPwned API Key
# Get your key at: https://haveibeenpwned.com/API/Key
HIBP_API_KEY=your_hibp_key_here

# Hunter.io API Key
# Get your key at: https://hunter.io/api
HUNTER_API_KEY=your_hunter_key_here
```

**Note**: The module works without API keys but provides limited functionality:

- Without HIBP key: No breach detection
- Without Hunter.io key: No email verification or deliverability checks

## Usage

### Command Line

```bash
# Basic email search
python -m src.cli email john.doe@example.com

# Search multiple emails
python -m src.cli email admin@example.com
python -m src.cli email test@gmail.com
```

### Python API

```python
from src.search.email import EmailSearch

# Create search instance
search = EmailSearch()

# Search for an email
results = await search.search("john.doe@example.com")

# Process results
for result in results:
    print(f"Source: {result.source}")
    print(f"Confidence: {result.confidence}")
    print(f"Metadata: {result.metadata}")
```

### Email Validation Only

```python
from src.search.email import EmailValidator

validator = EmailValidator()
result = validator.validate("test@example.com")

print(f"Valid: {result.is_valid}")
print(f"Domain: {result.domain}")
print(f"Disposable: {result.is_disposable}")
print(f"Role-based: {result.is_role_based}")
```

## Result Types

### 1. Validation Result

```python
{
    "source": "email:validation",
    "identifier": "test@example.com",
    "confidence": 1.0,
    "metadata": {
        "is_valid": True,
        "domain": "example.com",
        "username": "test",
        "is_disposable": False,
        "is_role_based": False
    }
}
```

### 2. HaveIBeenPwned Result

```python
{
    "source": "email:haveibeenpwned",
    "identifier": "test@example.com",
    "url": "https://haveibeenpwned.com/",
    "confidence": 0.9,
    "metadata": {
        "service": "HaveIBeenPwned",
        "breached": True,
        "breach_count": 3,
        "note": "Email found in breach databases"
    }
}
```

### 3. Hunter.io Result

```python
{
    "source": "email:hunter_io",
    "identifier": "test@example.com",
    "url": "https://hunter.io/verify/test@example.com",
    "confidence": 0.8,
    "metadata": {
        "service": "Hunter.io",
        "status": "valid",
        "score": 85,
        "result": "deliverable",
        "accept_all": False,
        "disposable": False,
        "free": False,
        "mx_records": True,
        "smtp_server": True,
        "smtp_check": True
    }
}
```

### 4. Reputation Result

```python
{
    "source": "email:reputation",
    "identifier": "test@gmail.com",
    "confidence": 0.7,
    "metadata": {
        "reputation_score": 0.7,
        "is_major_provider": True,
        "is_disposable": False,
        "is_role_based": False,
        "domain": "gmail.com"
    }
}
```

## Reputation Scoring

The reputation score (0.0 - 1.0) is calculated based on:

- **Base Score**: 0.5 (neutral)
- **Major Provider Bonus**: +0.2 (Gmail, Yahoo, Outlook, etc.)
- **Disposable Penalty**: -0.3 (temporary email services)
- **Role-Based Penalty**: -0.1 (admin, support, noreply, etc.)

### Examples

| Email Type | Score | Reasoning |
|------------|-------|-----------|
| `john@gmail.com` | 0.7 | Major provider (+0.2) |
| `test@mailinator.com` | 0.2 | Disposable (-0.3) |
| `admin@company.com` | 0.4 | Role-based (-0.1) |
| `user@example.com` | 0.5 | Neutral (unknown domain) |

## Privacy & Security

### K-Anonymity

The module uses HaveIBeenPwned's k-anonymity API, which means:

1. Emails are hashed with SHA-1
2. Only the first 5 characters of the hash are sent
3. The API returns all hashes matching that prefix
4. The full hash is compared locally

This ensures your email addresses are never sent to the API.

### Rate Limiting

- HaveIBeenPwned: No rate limit on range API
- Hunter.io: Respects API rate limits (typically 50-100 requests/month on free tier)

### Error Handling

The module gracefully handles:

- Missing API keys (skips that check)
- Network failures (logs error, continues)
- Rate limit exceeded (logs warning)
- Invalid responses (logs error, continues)

## Testing

Run the email search tests:

```bash
# All email tests
pipenv run pytest tests/test_email_search.py -v

# Specific test
pipenv run pytest tests/test_email_search.py::TestEmailValidator::test_valid_email -v

# With coverage
pipenv run pytest tests/test_email_search.py --cov=src.search.email
```

## Limitations

1. **API Dependencies**: Full functionality requires API keys
2. **Rate Limits**: Hunter.io free tier has monthly limits
3. **Disposable Domain List**: Not exhaustive (can be extended)
4. **MX Record Checks**: Not implemented without Hunter.io
5. **SMTP Verification**: Not implemented without Hunter.io

## Future Enhancements

- [ ] Direct MX record lookup (without Hunter.io)
- [ ] SMTP server testing (with user permission)
- [ ] Expanded disposable domain database
- [ ] Email pattern analysis (corporate vs personal)
- [ ] Social media profile linking
- [ ] GitHub commit history search
- [ ] Gravatar profile lookup
- [ ] Google dorking for email mentions

## Related Modules

- **Username Search**: Can cross-reference emails with usernames
- **Social Search**: May find social profiles linked to emails
- **Correlation Engine**: Links email addresses to other identifiers

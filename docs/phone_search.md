# Phone Search Module

## Overview

The Phone Search module provides comprehensive OSINT capabilities for phone numbers, including validation, carrier identification, geographic location, international format support, and reputation analysis.

## Features

### ✅ Phone Number Validation

- **Format Validation**: Uses Google's libphonenumber library for accurate validation
- **International Support**: Handles phone numbers from any country
- **Number Parsing**: Extracts country code, national number, and area code
- **Type Detection**: Identifies mobile, fixed-line, toll-free, VOIP, etc.
- **Possibility Check**: Validates if number is possible for the region

### ✅ Carrier Lookup

- **Carrier Identification**: Extracts carrier/operator name when available
- **Network Type**: Identifies mobile vs. fixed-line networks
- **Coverage Area**: Geographic service area information

### ✅ International Format Support

- **E.164 Format**: Standard international format (+16502530000)
- **International Format**: Human-readable (+1 650-253-0000)
- **National Format**: Local format ((650) 253-0000)
- **Flexible Input**: Accepts various formats and normalizes them

### ✅ Geographic Information

- **Location Extraction**: City, state/province identification
- **Country Detection**: Automatic country code recognition
- **Timezone Information**: All timezones where number could be valid
- **Region Mapping**: Maps numbers to geographic regions

### ✅ Reverse Lookup APIs

- **Numverify Integration**: Validates and verifies phone numbers
- **Public Records**: Searches available public directories
- **Spam Detection**: Basic reputation and spam scoring

## Configuration

### API Keys

Add the following to your `.env` file:

```bash
# Numverify API Key (optional but recommended)
# Get your key at: https://numverify.com/
NUMVERIFY_API_KEY=your_numverify_key_here

# Twilio credentials for advanced lookups (optional)
# Get from: https://www.twilio.com/console
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
```

**Note**: The module works without API keys using the phonenumbers library:

- Without Numverify: No additional verification data
- Without Twilio: No advanced carrier lookups

## Usage

### Command Line

```bash
# Basic phone search (US number)
python -m src.cli phone "+1 650-253-0000"

# UK number
python -m src.cli phone "+44 20 7946 0958"

# Toll-free number
python -m src.cli phone "+1 800-555-0100"

# Number without country code (uses default region)
python -m src.cli phone "(650) 253-0000"
```

### Python API

```python
from src.search.phone import PhoneSearch

# Create search instance
search = PhoneSearch()

# Search for a phone number
results = await search.search("+1 650-253-0000")

# With default region for numbers without country code
results = await search.search("(650) 253-0000", default_region="US")

# Process results
for result in results:
    print(f"Source: {result.source}")
    print(f"Confidence: {result.confidence}")
    print(f"Metadata: {result.metadata}")
```

### Phone Validation Only

```python
from src.search.phone import PhoneValidator

validator = PhoneValidator()
result = validator.validate("+1 650-253-0000", "US")

print(f"Valid: {result.is_valid}")
print(f"Country: {result.country}")
print(f"Region: {result.region}")
print(f"Carrier: {result.carrier_name}")
print(f"Type: {result.number_type}")
print(f"E164: {result.e164_format}")
```

## Result Types

### 1. Validation Result

```python
{
    "source": "phone:validation",
    "identifier": "+16502530000",
    "confidence": 1.0,
    "metadata": {
        "is_valid": True,
        "original_input": "+1 650-253-0000",
        "country_code": 1,
        "national_number": "6502530000",
        "country": "US",
        "region": "Mountain View, CA",
        "number_type": "fixed_or_mobile",
        "carrier": "Unknown",
        "timezones": ["America/Los_Angeles"],
        "formats": {
            "international": "+1 650-253-0000",
            "national": "(650) 253-0000",
            "e164": "+16502530000"
        }
    }
}
```

### 2. Carrier Lookup Result

```python
{
    "source": "phone:carrier_lookup",
    "identifier": "+16502530000",
    "confidence": 0.9,
    "metadata": {
        "carrier": "AT&T",
        "region": "Mountain View, CA",
        "country": "US",
        "number_type": "mobile",
        "timezones": ["America/Los_Angeles"],
        "note": "Carrier and location information"
    }
}
```

### 3. Numverify Result (with API key)

```python
{
    "source": "phone:numverify",
    "identifier": "+16502530000",
    "confidence": 0.8,
    "metadata": {
        "service": "Numverify",
        "valid": True,
        "number": "6502530000",
        "local_format": "6502530000",
        "international_format": "+16502530000",
        "country_code": "US",
        "country_name": "United States",
        "location": "California",
        "carrier": "AT&T Mobility",
        "line_type": "mobile"
    }
}
```

### 4. Reputation Result

```python
{
    "source": "phone:reputation",
    "identifier": "+18005550100",
    "confidence": 0.6,
    "metadata": {
        "spam_score": 0.2,
        "flags": ["toll_free_number"],
        "note": "Basic spam detection heuristics"
    }
}
```

## Number Type Detection

The module identifies various phone number types:

| Type | Description | Example |
|------|-------------|---------|
| `mobile` | Mobile/cellular number | +1 415-555-0100 |
| `fixed_line` | Landline number | +44 20 7946 0958 |
| `fixed_or_mobile` | Could be either | +1 650-253-0000 |
| `toll_free` | Toll-free number | +1 800-555-0100 |
| `premium_rate` | Premium service | +1 900-555-0100 |
| `voip` | VoIP service | Various |
| `personal` | Personal number service | Various |
| `pager` | Pager service | Rare |
| `uan` | Universal access number | Various |
| `voicemail` | Voicemail access | Various |
| `unknown` | Cannot determine | - |

## International Format Examples

### North America (NANP)

```python
# United States
"+1 650-253-0000"  # California
"+1 212-555-0100"  # New York

# Canada
"+1 416-555-0100"  # Ontario
"+1 604-555-0100"  # British Columbia
```

### Europe

```python
# United Kingdom
"+44 20 7946 0958"  # London
"+44 161 555 0100"  # Manchester

# Germany
"+49 30 12345678"  # Berlin
"+49 89 12345678"  # Munich

# France
"+33 1 42 86 82 00"  # Paris
```

### Asia

```python
# Japan
"+81 3-1234-5678"  # Tokyo

# China
"+86 10 1234 5678"  # Beijing

# India
"+91 11 2345 6789"  # New Delhi
```

## Spam Detection

### Spam Score Calculation

The reputation score (0.0 = clean, 1.0 = spam) is based on:

- **Toll-Free Numbers**: +0.2 (often used for telemarketing)
- **Premium Rate**: +0.5 (high-cost numbers)
- **Known Spam Patterns**: +0.3 (flagged prefixes)

### Flags

| Flag | Description |
|------|-------------|
| `toll_free_number` | 800/888/877 numbers |
| `premium_rate` | 900 numbers |
| `voip_service` | Internet-based numbers |

## Privacy & Security

### Data Protection

- No phone numbers are stored or logged
- API calls use HTTPS encryption
- Minimal data sent to external services

### Rate Limiting

- Numverify: Free tier typically 100-250 requests/month
- Twilio: Pay-per-use pricing
- phonenumbers library: No limits (local processing)

### Error Handling

The module gracefully handles:

- Missing API keys (skips that check)
- Network failures (logs error, continues)
- Invalid number formats (returns validation error)
- Rate limit exceeded (logs warning)

## Testing

Run the phone search tests:

```bash
# All phone tests
pipenv run pytest tests/test_phone_search.py -v

# Specific test
pipenv run pytest tests/test_phone_search.py::TestPhoneValidator::test_valid_us_number -v

# With coverage
pipenv run pytest tests/test_phone_search.py --cov=src.search.phone
```

## Limitations

1. **Carrier Data**: May be "Unknown" for some numbers
2. **Geographic Precision**: Region data varies by country
3. **Real-Time Validation**: Cannot verify if number is currently active
4. **Porting**: Cannot detect number portability across carriers
5. **Private Numbers**: Cannot identify unlisted/private numbers
6. **API Dependencies**: Full features require API keys

## Future Enhancements

- [ ] Twilio Lookup API integration
- [ ] Advanced spam database integration
- [ ] Call history tracking (if legally obtained)
- [ ] Number portability database
- [ ] Caller ID spoofing detection
- [ ] SMS verification capabilities
- [ ] Social media profile linking
- [ ] Reverse address lookup
- [ ] Business registration matching
- [ ] Telemarketer database checks

## Related Modules

- **Email Search**: Can correlate emails with phone numbers
- **Name Search**: May find people associated with numbers
- **Social Search**: May link phones to social profiles
- **Correlation Engine**: Links phone numbers to other identifiers

## Legal & Ethical Notes

⚠️ **Important**: Phone number lookups must comply with:

- Telephone Consumer Protection Act (TCPA)
- General Data Protection Regulation (GDPR)
- Local privacy laws and regulations
- Terms of Service of lookup APIs

Only use this module for:

- Legitimate OSINT investigations
- Security research
- Fraud prevention
- With proper authorization

Do NOT use for:

- Harassment or stalking
- Unsolicited marketing
- Privacy violations
- Illegal activities

## Supported Countries

The phonenumbers library supports 250+ countries and territories. Some examples:

- 🇺🇸 United States & Canada (NANP: +1)
- 🇬🇧 United Kingdom (+44)
- 🇩🇪 Germany (+49)
- 🇫🇷 France (+33)
- 🇯🇵 Japan (+81)
- 🇨🇳 China (+86)
- 🇮🇳 India (+91)
- 🇧🇷 Brazil (+55)
- 🇦🇺 Australia (+61)
- And 240+ more...

For a complete list, see: <https://github.com/google/libphonenumber>

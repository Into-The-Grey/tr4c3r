# Name Search Module

The name search module provides comprehensive OSINT capabilities for researching individuals by their full name. It includes intelligent name parsing, disambiguation analysis, location filtering, and integration with people search services.

## Features

### 1. Name Parsing

- **Component Extraction**: Automatically parses first, middle, and last names
- **Title Recognition**: Identifies and extracts prefixes (Dr., Mr., Mrs., Prof., etc.)
- **Suffix Detection**: Recognizes suffixes (Jr., Sr., II, III, PhD, MD, etc.)
- **Name Variations**: Generates common variations and formats
- **Compound Names**: Handles multi-part middle and last names
- **Normalization**: Cleans whitespace and standardizes formatting

### 2. Disambiguation Analysis

The module calculates a disambiguation score (0.0 to 1.0) based on multiple factors:

| Factor | Impact | Description |
|--------|--------|-------------|
| Common Last Name | -0.2 | Penalties for Smith, Johnson, Garcia, etc. |
| Unique First Name | +0.1 | Longer/unique first names improve score |
| Middle Name Present | +0.15 | Middle names aid disambiguation |
| Suffix Present | +0.1 | Jr., Sr., III help identify specific person |
| Location Provided | +0.2 | Geographic context improves precision |
| Age Range Provided | +0.15 | Narrows search to specific generation |
| Occupation Provided | +0.1 | Professional context aids identification |
| Known Usernames | +0.15 | Cross-reference with digital identities |
| Known Emails | +0.15 | Email addresses aid verification |

**Disambiguation Recommendations:**

- **High (>0.7)**: Name is relatively unique, results likely accurate
- **Medium (0.4-0.7)**: Moderate ambiguity, use location or context
- **Low (<0.4)**: High ambiguity, strongly recommend additional identifiers

### 3. Social Media Patterns

Automatically generates likely username patterns from names:

- `firstnamelastname` (e.g., "johnsmith")
- `firstname.lastname` (e.g., "john.smith")
- `firstname_lastname` (e.g., "john_smith")
- `firstinitiallastname` (e.g., "jsmith")

These patterns can be verified using the username search module.

### 4. People Search APIs

Integration with people finder services:

- **Pipl API**: Comprehensive people search (requires `PIPL_API_KEY`)
- **Clearbit**: Professional contact information (requires `CLEARBIT_API_KEY`)

### 5. Location Filtering

Apply geographic filters to narrow results:

- City, state, or country-level filtering
- Improves precision for common names
- Adds location context to disambiguation

## Usage

### Command Line Interface

```bash
# Basic name search
pipenv run python -m src.cli name "John Smith"

# Name with title and suffix
pipenv run python -m src.cli name "Dr. Jane Doe PhD"

# Name with middle name
pipenv run python -m src.cli name "John Robert Smith"
```

### Python API

```python
from src.search.name import NameSearch, DisambiguationContext

# Basic search
search = NameSearch()
results = await search.search("John Smith")

# With location context
context = DisambiguationContext(location="San Francisco, CA")
results = await search.search("John Smith", context=context)

# With comprehensive context
context = DisambiguationContext(
    location="Boston, MA",
    age_range=(30, 40),
    occupation="Software Engineer",
    known_usernames=["jsmith123"],
    known_emails=["john.smith@company.com"]
)
results = await search.search("John Smith", context=context)
```

### Name Parser

```python
from src.search.name import NameParser

parser = NameParser()
parsed = parser.parse("Dr. Christopher Alexander Pemberton III")

print(parsed.first_name)    # "Christopher"
print(parsed.middle_name)   # "Alexander"
print(parsed.last_name)     # "Pemberton"
print(parsed.prefixes)      # ["Dr."]
print(parsed.suffixes)      # ["III"]
print(parsed.variations)    # ["Christopher Pemberton", "C. Pemberton", ...]
```

## Result Types

### 1. Name Parsing (`name:parsing`)

Complete name parsing results with variations:

```json
{
  "source": "name:parsing",
  "confidence": 1.0,
  "metadata": {
    "original_input": "Dr. John R. Smith Jr.",
    "first_name": "John",
    "middle_name": "R",
    "last_name": "Smith",
    "prefixes": ["Dr."],
    "suffixes": ["Jr."],
    "variations": [
      "John R. Smith",
      "John Smith",
      "J. R. Smith",
      "Smith, John R.",
      "J. Smith"
    ]
  }
}
```

### 2. Disambiguation Analysis (`name:disambiguation`)

Uniqueness scoring and recommendations:

```json
{
  "source": "name:disambiguation",
  "confidence": 0.7,
  "metadata": {
    "disambiguation_score": 0.85,
    "factors": ["unique_first_name", "has_middle_name", "has_suffix"],
    "uniqueness": "high",
    "recommendation": "Name is relatively unique. Results likely accurate.",
    "has_context": false
  }
}
```

### 3. Social Media Patterns (`name:social_media_patterns`)

Likely username patterns:

```json
{
  "source": "name:social_media_patterns",
  "confidence": 0.5,
  "metadata": {
    "potential_usernames": [
      "johnsmith",
      "john.smith",
      "john_smith",
      "jsmith"
    ],
    "note": "Common username patterns derived from name",
    "recommendation": "Use username search module to verify these"
  }
}
```

### 4. Public Records (`name:public_records`)

Recommended manual search sources:

```json
{
  "source": "name:public_records",
  "confidence": 0.6,
  "metadata": {
    "recommended_sources": [
      "LinkedIn (professional profiles)",
      "Facebook (social profiles)",
      "Twitter/X (social profiles)",
      "WhitePages (phone directory)",
      "Spokeo (people search)",
      "BeenVerified (public records)",
      "ZoomInfo (business directory)",
      "Company websites (about pages)"
    ],
    "name_variations": ["John Smith", "J. Smith", "Smith, John"]
  }
}
```

### 5. Location Filter (`name:location_filter`)

Applied when location context is provided:

```json
{
  "source": "name:location_filter",
  "confidence": 1.0,
  "metadata": {
    "filter_applied": "location",
    "location": "San Francisco, CA",
    "note": "Results filtered for location: San Francisco, CA"
  }
}
```

### 6. People APIs (`name:pipl`)

Results from people search services (when API keys configured):

```json
{
  "source": "name:pipl",
  "confidence": 0.8,
  "metadata": {
    "service": "Pipl",
    "match_count": 15,
    "possible_persons": 3,
    "note": "People search API results"
  }
}
```

## Configuration

Add API keys to `.env` file:

```bash
# People Search APIs (Optional - enhances results)
PIPL_API_KEY=your_pipl_api_key_here
CLEARBIT_API_KEY=your_clearbit_api_key_here
```

**Note**: API keys are optional. The module provides useful results without them through parsing, disambiguation, and pattern generation.

## Examples

### Example 1: Common Name (High Ambiguity)

```bash
pipenv run python -m src.cli name "John Smith"
```

**Results**:

- Disambiguation score: 0.3 (low)
- Recommendation: "High ambiguity. Strongly recommend providing location, age, or other identifiers."
- Username patterns: johnsmith, john.smith, jsmith
- Status: Needs additional context

### Example 2: Unique Name (Low Ambiguity)

```bash
pipenv run python -m src.cli name "Xenophilius Lovegood"
```

**Results**:

- Disambiguation score: 0.7+ (high)
- Recommendation: "Name is relatively unique. Results likely accurate."
- Username patterns: xenophiliuslovegood, xenophilius.lovegood
- Status: High confidence in uniqueness

### Example 3: Name with Context

```python
context = DisambiguationContext(
    location="Seattle, WA",
    age_range=(25, 35),
    occupation="Data Scientist"
)
results = await search.search("Emily Chen", context=context)
```

**Results**:

- Disambiguation score: 0.75+ (high)
- Location filter applied
- Factors: location_provided, age_range_provided, occupation_provided
- Status: Context significantly improves precision

## Name Parsing Capabilities

### Supported Formats

| Format | Example | Parsed As |
|--------|---------|-----------|
| First Last | John Smith | first: John, last: Smith |
| First Middle Last | John Robert Smith | first: John, middle: Robert, last: Smith |
| Title First Last | Dr. Jane Doe | prefix: Dr., first: Jane, last: Doe |
| First Last Suffix | Robert Johnson Jr. | first: Robert, last: Johnson, suffix: Jr. |
| Complex | Dr. John R. Smith Jr. PhD | All components extracted |
| Hyphenated | Jane Smith-Jones | first: Jane, last: Smith-Jones |
| Compound Middle | Maria Elena Garcia | first: Maria, middle: Elena, last: Garcia |

### Name Variations Generated

For "John Robert Smith", the parser generates:

- John Robert Smith
- John Smith
- John R. Smith
- J. Robert Smith
- J. R. Smith
- Smith, John
- Smith, John R.
- J.R. Smith
- J. Smith

## Testing

The module includes 24 comprehensive tests:

```bash
# Run name search tests
pipenv run pytest tests/test_name_search.py -v

# Run all tests
pipenv run pytest -v
```

**Test Coverage**:

- Name parsing (11 tests): simple names, titles, suffixes, compound names, edge cases
- Name search (13 tests): disambiguation, context, filtering, API integration

## Privacy & Ethics

### Best Practices

1. **Consent**: Obtain proper authorization before researching individuals
2. **Purpose**: Use only for legitimate OSINT, security, or research purposes
3. **Context**: Provide disambiguation context to avoid false positives
4. **Verification**: Cross-reference multiple sources before drawing conclusions
5. **Data Protection**: Handle personal information according to privacy regulations

### Legal Considerations

- Comply with GDPR, CCPA, and other privacy regulations
- Respect data subject rights (access, deletion, correction)
- Document legitimate interests for data processing
- Use public sources only
- Avoid harassment or stalking behaviors

## Limitations

1. **Name Ambiguity**: Common names may return many false positives without context
2. **Cultural Variations**: Name parsing optimized for Western name conventions
3. **API Dependency**: Full functionality requires paid API subscriptions
4. **Manual Verification**: Automated results should be manually verified
5. **Privacy Restrictions**: Some jurisdictions restrict people search capabilities
6. **Data Freshness**: Public records may be outdated or incomplete

## Future Enhancements

- [ ] Cultural name parsing (Asian, Arabic, Hispanic conventions)
- [ ] Phonetic matching (Soundex, Metaphone) for misspellings
- [ ] Nickname/diminutive expansion (Bob → Robert, etc.)
- [ ] Integration with more people search APIs
- [ ] Age estimation from birth year/graduation dates
- [ ] Relationship graph construction (family, colleagues)
- [ ] Historical name changes (marriage, legal name changes)
- [ ] Academic credential verification
- [ ] Professional license lookups
- [ ] Court records integration

## Related Modules

- **Username Search**: Verify generated username patterns
- **Email Search**: Validate known email addresses
- **Phone Search**: Cross-reference phone numbers
- **Social Media**: Deep dive into social profiles

## Support

For issues, questions, or contributions, please refer to the main project documentation.

# TR4C3R API Integrations

Additional API integrations for enriched OSINT data collection.

## Overview

The integrations module provides collectors for external data sources:

| Collector | Data Source | API Required |
|-----------|-------------|--------------|
| DNSCollector | DNS-over-HTTPS | No |
| WHOISCollector | WHOIS lookups | No |
| BreachCollector | HaveIBeenPwned | Yes (HIBP) |
| PasteCollector | Paste sites | Yes (HIBP) |
| DomainReputationCollector | VirusTotal | Yes (VT) |

## DNS Collector

Perform DNS lookups using public DNS-over-HTTPS APIs.

```python
from src.integrations import DNSCollector, RecordType

collector = DNSCollector()

# Single record lookup
records = await collector.lookup("example.com", RecordType.A)
for record in records:
    print(f"{record.record_type}: {record.value} (TTL: {record.ttl})")

# Lookup all common record types
all_records = await collector.lookup_all("example.com")
print(f"A records: {all_records[RecordType.A]}")
print(f"MX records: {all_records[RecordType.MX]}")
print(f"TXT records: {all_records[RecordType.TXT]}")

# Reverse DNS lookup
ptr_records = await collector.reverse_lookup("93.184.216.34")
```

### Record Types

- `A` - IPv4 address
- `AAAA` - IPv6 address
- `MX` - Mail exchange (includes priority)
- `TXT` - Text records
- `NS` - Name servers
- `CNAME` - Canonical name
- `SOA` - Start of authority
- `PTR` - Pointer (reverse DNS)
- `SRV` - Service records
- `CAA` - Certificate authority authorization

## WHOIS Collector

Retrieve domain registration information.

```python
from src.integrations import WHOISCollector

collector = WHOISCollector()

# Lookup domain registration
info = await collector.lookup("example.com")

print(f"Domain: {info.domain}")
print(f"Registrar: {info.registrar}")
print(f"Created: {info.creation_date}")
print(f"Expires: {info.expiration_date}")
print(f"Registrant: {info.registrant_name}")
print(f"Name Servers: {info.name_servers}")
print(f"DNSSEC: {info.dnssec}")
```

### WHOISInfo Fields

```python
@dataclass
class WHOISInfo:
    domain: str
    registrar: Optional[str]
    creation_date: Optional[datetime]
    expiration_date: Optional[datetime]
    updated_date: Optional[datetime]
    registrant_name: Optional[str]
    registrant_org: Optional[str]
    registrant_email: Optional[str]
    registrant_country: Optional[str]
    name_servers: List[str]
    status: List[str]
    dnssec: bool
    raw_text: str
```

## Breach Collector

Check if emails appear in known data breaches using HaveIBeenPwned API.

```python
from src.integrations import BreachCollector

collector = BreachCollector(hibp_api_key="your-api-key")

# Check email for breaches
breaches = await collector.check_email("test@example.com")

for breach in breaches:
    print(f"Breach: {breach.breach_name}")
    print(f"Date: {breach.breach_date}")
    print(f"Data exposed: {breach.data_classes}")
    print(f"Verified: {breach.is_verified}")
    print(f"Records: {breach.pwn_count:,}")

# Check password (uses k-anonymity - safe)
pwn_count = await collector.check_password("password123")
if pwn_count > 0:
    print(f"Password found in {pwn_count:,} breaches!")

# Get breach details
breach_info = await collector.get_breach_info("Adobe")
```

### Getting an HIBP API Key

1. Visit [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
2. Purchase an API key (supports the service)
3. Add to your configuration:

```yaml
# config/tr4c3r.yaml
integrations:
  hibp_api_key: "your-key-here"
```

## Paste Collector

Check if emails appear in paste sites.

```python
from src.integrations import PasteCollector

collector = PasteCollector(hibp_api_key="your-api-key")

# Check email for paste appearances
pastes = await collector.check_email("test@example.com")

for paste in pastes:
    print(f"Paste ID: {paste.paste_id}")
    print(f"Source: {paste.source}")
    print(f"Date: {paste.date}")
    print(f"Email count: {paste.email_count}")
```

## Domain Reputation Collector

Check domain/IP reputation using VirusTotal.

```python
from src.integrations import DomainReputationCollector

collector = DomainReputationCollector(virustotal_api_key="your-api-key")

# Check domain reputation
reputation = await collector.check_domain("suspicious-site.com")

print(f"Malicious: {reputation.is_malicious}")
print(f"Risk Score: {reputation.risk_score}%")
print(f"Categories: {reputation.categories}")
print(f"Blacklists: {reputation.blacklists}")
print(f"IP Addresses: {reputation.ip_addresses}")

# Check IP reputation
ip_reputation = await collector.check_ip("93.184.216.34")
```

### Getting a VirusTotal API Key

1. Sign up at [virustotal.com](https://www.virustotal.com)
2. Go to your profile → API key
3. Add to your configuration:

```yaml
# config/tr4c3r.yaml
integrations:
  virustotal_api_key: "your-key-here"
```

## Integration Manager

Unified interface for all collectors.

```python
from src.integrations import IntegrationManager

manager = IntegrationManager(
    hibp_api_key="hibp-key",
    virustotal_api_key="vt-key"
)

# Comprehensive domain investigation
domain_info = await manager.investigate_domain("example.com")
# Returns: DNS, WHOIS, and reputation data

# Comprehensive email investigation
email_info = await manager.investigate_email("user@example.com")
# Returns: Breaches, pastes, and domain info

# Quick IP check
ip_reputation = await manager.check_ip_reputation("93.184.216.34")
```

### Investigation Results

```python
# Domain investigation returns:
{
    "dns": {
        "A": [{"value": "93.184.216.34", "ttl": 300}],
        "MX": [{"value": "mail.example.com", "ttl": 3600}],
        ...
    },
    "whois": {
        "registrar": "Example Registrar",
        "creation_date": "2020-01-01",
        "name_servers": ["ns1.example.com", "ns2.example.com"]
    },
    "reputation": {
        "is_malicious": False,
        "risk_score": 0.0,
        "categories": [],
        "blacklists": []
    }
}

# Email investigation returns:
{
    "breaches": [
        {"name": "Adobe", "date": "2013-10-04", "data_types": [...]}
    ],
    "pastes": [
        {"id": "abc123", "source": "Pastebin", "date": "2023-01-15"}
    ],
    "domain": {
        # Same as domain investigation
    }
}
```

## Converting to Results

Each collector provides a `to_result()` method to convert findings to the standard `Result` format:

```python
from src.integrations import DNSCollector

collector = DNSCollector()
records = await collector.lookup("example.com")

# Convert to standard Result format
result = collector.to_result(records, "example.com")
print(result.source)     # "dns"
print(result.identifier) # "example.com"
print(result.metadata)   # Contains all DNS records
```

## Configuration

### Environment Variables

```bash
export HIBP_API_KEY="your-hibp-key"
export VIRUSTOTAL_API_KEY="your-vt-key"
```

### Config File

```yaml
# config/tr4c3r.yaml
integrations:
  hibp_api_key: ${HIBP_API_KEY}
  virustotal_api_key: ${VIRUSTOTAL_API_KEY}
  dns_servers:
    - "https://dns.google/resolve"
    - "https://cloudflare-dns.com/dns-query"
```

## Rate Limiting

Be mindful of API rate limits:

| Service | Rate Limit |
|---------|------------|
| HaveIBeenPwned | 1 request/1.5 seconds |
| VirusTotal (free) | 4 requests/minute |
| DNS-over-HTTPS | Generally unlimited |

Use the rate limiting middleware for API endpoints:

```python
from src.api.rate_limit import rate_limit

@app.get("/api/v1/investigate/domain/{domain}")
@rate_limit(requests_per_minute=10)
async def investigate_domain(domain: str):
    manager = IntegrationManager(...)
    return await manager.investigate_domain(domain)
```

## Error Handling

All collectors handle errors gracefully and return empty results:

```python
# Network error - returns empty list
records = await collector.lookup("example.com")
# records = []

# API error - returns default reputation
reputation = await collector.check_domain("example.com")
# reputation.is_malicious = False (safe default)
```

## Module Exports

```python
from src.integrations import (
    # Enums
    RecordType,
    
    # Data Classes
    DNSRecord,
    WHOISInfo,
    BreachRecord,
    PasteRecord,
    DomainReputation,
    
    # Collectors
    DNSCollector,
    WHOISCollector,
    BreachCollector,
    PasteCollector,
    DomainReputationCollector,
    
    # Manager
    IntegrationManager,
)
```

## Testing

```bash
# Run integration tests
pipenv run pytest tests/test_integrations.py -v

# Run with coverage
pipenv run pytest tests/test_integrations.py --cov=src/integrations
```

## See Also

- [API Documentation](API.md)
- [Rate Limiting](../src/api/rate_limit.py)
- [Data Models](../src/core/data_models.py)
- [Threat Intelligence](../src/integrations/threat_intel.py)

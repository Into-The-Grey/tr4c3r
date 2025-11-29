"""Integration modules for TR4C3R.

This package contains connectors to external services:
- DNS lookups and records
- WHOIS domain registration
- Breach database checks (HaveIBeenPwned)
- Paste site monitoring
- Domain reputation (VirusTotal)
- Tor proxy for dark web access
- API clients for third-party OSINT services
- Social media platform integrations

API Integrations:
- Free: GitHub, Gravatar, EmailRep.io, IPInfo
- Paid (disabled by default): Hunter.io, HIBP, Numverify, Clearbit
"""

from src.integrations.collectors import (
    RecordType,
    DNSRecord,
    WHOISInfo,
    BreachRecord,
    PasteRecord,
    DomainReputation,
    DNSCollector,
    WHOISCollector,
    BreachCollector,
    PasteCollector,
    DomainReputationCollector,
    IntegrationManager,
)

from src.integrations.api_clients import (
    APIConfig,
    API_REGISTRY,
    BaseAPIClient,
    GitHubAPI,
    GravatarAPI,
    EmailRepAPI,
    IPInfoAPI,
    HunterAPI,
    HIBPApi,
    APIIntegrationManager,
    search_with_apis,
)

__all__ = [
    # Collectors
    "RecordType",
    "DNSRecord",
    "WHOISInfo",
    "BreachRecord",
    "PasteRecord",
    "DomainReputation",
    "DNSCollector",
    "WHOISCollector",
    "BreachCollector",
    "PasteCollector",
    "DomainReputationCollector",
    "IntegrationManager",
    # API Clients
    "APIConfig",
    "API_REGISTRY",
    "BaseAPIClient",
    "GitHubAPI",
    "GravatarAPI",
    "EmailRepAPI",
    "IPInfoAPI",
    "HunterAPI",
    "HIBPApi",
    "APIIntegrationManager",
    "search_with_apis",
]

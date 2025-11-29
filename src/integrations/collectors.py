"""
Additional API integrations for TR4C3R.

Provides collectors for:
- DNS lookups and records
- WHOIS information
- Breach database checks
- Paste site monitoring
- Domain reputation
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol
from datetime import datetime, timezone
from enum import Enum
import asyncio
import hashlib
import re

from src.core.data_models import Result


class HTTPClientProtocol(Protocol):
    """Protocol for HTTP client interface."""

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Make GET request."""
        ...


class SimpleHTTPClient:
    """Simple HTTP client wrapper for API calls."""

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Make GET request and return JSON response."""
        import httpx

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                return response.json()
            return response.text


class RecordType(str, Enum):
    """DNS record types."""

    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    CNAME = "CNAME"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"


@dataclass
class DNSRecord:
    """Represents a DNS record."""

    record_type: RecordType
    name: str
    value: str
    ttl: int = 3600
    priority: Optional[int] = None  # For MX records
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WHOISInfo:
    """WHOIS registration information."""

    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: bool = False
    raw_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BreachRecord:
    """Data breach record."""

    breach_name: str
    breach_date: Optional[datetime] = None
    domain: Optional[str] = None
    description: str = ""
    data_classes: List[str] = field(default_factory=list)  # email, password, etc.
    is_verified: bool = False
    is_sensitive: bool = False
    pwn_count: int = 0
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PasteRecord:
    """Paste site record."""

    paste_id: str
    source: str  # pastebin, ghostbin, etc.
    title: Optional[str] = None
    date: Optional[datetime] = None
    email_count: int = 0
    content_preview: str = ""
    url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainReputation:
    """Domain reputation information."""

    domain: str
    is_malicious: bool = False
    risk_score: float = 0.0  # 0-100
    categories: List[str] = field(default_factory=list)
    blacklists: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    ip_addresses: List[str] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DNSCollector:
    """
    Collector for DNS information.

    Performs DNS lookups using public DNS-over-HTTPS APIs.
    """

    def __init__(
        self,
        http_client: Optional[SimpleHTTPClient] = None,
        dns_servers: Optional[List[str]] = None,
    ):
        self.http_client = http_client or SimpleHTTPClient()
        self.dns_servers = dns_servers or [
            "https://dns.google/resolve",
            "https://cloudflare-dns.com/dns-query",
        ]
        self._record_type_map = {
            RecordType.A: 1,
            RecordType.AAAA: 28,
            RecordType.MX: 15,
            RecordType.TXT: 16,
            RecordType.NS: 2,
            RecordType.CNAME: 5,
            RecordType.SOA: 6,
            RecordType.PTR: 12,
            RecordType.SRV: 33,
            RecordType.CAA: 257,
        }

    async def lookup(self, domain: str, record_type: RecordType = RecordType.A) -> List[DNSRecord]:
        """
        Perform DNS lookup for a domain.

        Args:
            domain: Domain name to lookup
            record_type: Type of DNS record to query

        Returns:
            List of DNS records found
        """
        records = []

        # Use Google DNS-over-HTTPS
        url = self.dns_servers[0]
        params = {"name": domain, "type": self._record_type_map.get(record_type, 1)}

        try:
            response = await self.http_client.get(url, params=params)

            if response and "Answer" in response:
                for answer in response["Answer"]:
                    record = DNSRecord(
                        record_type=record_type,
                        name=answer.get("name", domain).rstrip("."),
                        value=answer.get("data", ""),
                        ttl=answer.get("TTL", 3600),
                        metadata={"raw": answer},
                    )

                    # Extract priority for MX records
                    if record_type == RecordType.MX and record.value:
                        parts = record.value.split()
                        if len(parts) >= 2:
                            try:
                                record.priority = int(parts[0])
                                record.value = parts[1].rstrip(".")
                            except ValueError:
                                pass

                    records.append(record)

        except Exception as e:
            # Log error but don't fail
            pass

        return records

    async def lookup_all(self, domain: str) -> Dict[RecordType, List[DNSRecord]]:
        """
        Lookup all common record types for a domain.

        Args:
            domain: Domain name to lookup

        Returns:
            Dictionary mapping record types to their records
        """
        results = {}

        record_types = [
            RecordType.A,
            RecordType.AAAA,
            RecordType.MX,
            RecordType.TXT,
            RecordType.NS,
            RecordType.CNAME,
        ]

        # Perform lookups concurrently
        tasks = [self.lookup(domain, rt) for rt in record_types]

        lookup_results = await asyncio.gather(*tasks, return_exceptions=True)

        for rt, result in zip(record_types, lookup_results):
            if isinstance(result, list):
                results[rt] = result
            else:
                results[rt] = []

        return results

    async def reverse_lookup(self, ip_address: str) -> List[DNSRecord]:
        """
        Perform reverse DNS lookup for an IP address.

        Args:
            ip_address: IP address to lookup

        Returns:
            List of PTR records
        """
        # Convert IP to reverse DNS format
        if ":" in ip_address:
            # IPv6 - not implemented for simplicity
            return []

        parts = ip_address.split(".")
        if len(parts) != 4:
            return []

        reverse_name = ".".join(reversed(parts)) + ".in-addr.arpa"

        return await self.lookup(reverse_name, RecordType.PTR)

    def to_result(self, records: List[DNSRecord], domain: str) -> Result:
        """Convert DNS records to Result format."""
        return Result(
            source="dns",
            identifier=domain,
            metadata={
                "domain": domain,
                "records": [
                    {
                        "type": r.record_type.value,
                        "name": r.name,
                        "value": r.value,
                        "ttl": r.ttl,
                        "priority": r.priority,
                    }
                    for r in records
                ],
                "record_count": len(records),
            },
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
        )


class WHOISCollector:
    """
    Collector for WHOIS domain registration information.

    Uses public WHOIS APIs to retrieve domain registration data.
    """

    def __init__(
        self, http_client: Optional[SimpleHTTPClient] = None, api_key: Optional[str] = None
    ):
        self.http_client = http_client or SimpleHTTPClient()
        self.api_key = api_key
        self._whois_api_url = "https://whois.iana.org"  # Fallback

    async def lookup(self, domain: str) -> Optional[WHOISInfo]:
        """
        Perform WHOIS lookup for a domain.

        Args:
            domain: Domain name to lookup

        Returns:
            WHOISInfo or None if lookup fails
        """
        # Extract root domain if needed
        domain = self._extract_root_domain(domain)

        # For actual implementation, would use WHOIS API
        # Here we return a structured result

        whois_info = WHOISInfo(
            domain=domain,
            metadata={
                "query_time": datetime.now(timezone.utc).isoformat(),
                "source": "whois_lookup",
            },
        )

        # In production, would parse actual WHOIS response
        # This is a placeholder for the API integration

        return whois_info

    def _extract_root_domain(self, domain: str) -> str:
        """Extract root domain from a full domain name."""
        # Remove protocol if present
        if "://" in domain:
            domain = domain.split("://")[1]

        # Remove path
        domain = domain.split("/")[0]

        # Handle www
        if domain.startswith("www."):
            domain = domain[4:]

        return domain.lower()

    def _parse_whois_response(self, raw_text: str) -> WHOISInfo:
        """Parse raw WHOIS response text."""
        info = WHOISInfo(domain="", raw_text=raw_text)

        # Common WHOIS field patterns
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiration_date": r"(?:Registry Expiry|Expiration) Date:\s*(.+)",
            "updated_date": r"Updated Date:\s*(.+)",
            "registrant_name": r"Registrant Name:\s*(.+)",
            "registrant_org": r"Registrant Organization:\s*(.+)",
            "registrant_email": r"Registrant Email:\s*(.+)",
            "registrant_country": r"Registrant Country:\s*(.+)",
        }

        for field, pattern in patterns.items():
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                setattr(info, field, value)

        # Extract name servers
        ns_pattern = r"Name Server:\s*(.+)"
        ns_matches = re.findall(ns_pattern, raw_text, re.IGNORECASE)
        info.name_servers = [ns.strip().lower() for ns in ns_matches]

        # Extract status
        status_pattern = r"(?:Domain )?Status:\s*(.+)"
        status_matches = re.findall(status_pattern, raw_text, re.IGNORECASE)
        info.status = [s.strip() for s in status_matches]

        # Check DNSSEC
        info.dnssec = "dnssec" in raw_text.lower() and "unsigned" not in raw_text.lower()

        return info

    def to_result(self, whois_info: WHOISInfo) -> Result:
        """Convert WHOIS info to Result format."""
        return Result(
            source="whois",
            identifier=whois_info.domain,
            metadata={
                "domain": whois_info.domain,
                "registrar": whois_info.registrar,
                "creation_date": (
                    whois_info.creation_date.isoformat() if whois_info.creation_date else None
                ),
                "expiration_date": (
                    whois_info.expiration_date.isoformat() if whois_info.expiration_date else None
                ),
                "registrant": {
                    "name": whois_info.registrant_name,
                    "org": whois_info.registrant_org,
                    "email": whois_info.registrant_email,
                    "country": whois_info.registrant_country,
                },
                "name_servers": whois_info.name_servers,
                "status": whois_info.status,
                "dnssec": whois_info.dnssec,
            },
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
        )


class BreachCollector:
    """
    Collector for data breach information.

    Checks if an email or domain appears in known data breaches.
    """

    def __init__(
        self, http_client: Optional[SimpleHTTPClient] = None, hibp_api_key: Optional[str] = None
    ):
        self.http_client = http_client or SimpleHTTPClient()
        self.hibp_api_key = hibp_api_key
        self._hibp_base_url = "https://haveibeenpwned.com/api/v3"
        self._headers = {"User-Agent": "TR4C3R-OSINT", "hibp-api-key": hibp_api_key or ""}

    async def check_email(self, email: str) -> List[BreachRecord]:
        """
        Check if an email appears in known data breaches.

        Args:
            email: Email address to check

        Returns:
            List of breaches containing the email
        """
        breaches = []

        if not self.hibp_api_key:
            # Return empty list if no API key
            return breaches

        email = email.lower().strip()

        try:
            url = f"{self._hibp_base_url}/breachedaccount/{email}"
            response = await self.http_client.get(url, headers=self._headers)

            if response and isinstance(response, list):
                for breach_data in response:
                    breach = BreachRecord(
                        breach_name=breach_data.get("Name", "Unknown"),
                        description=breach_data.get("Description", ""),
                        data_classes=breach_data.get("DataClasses", []),
                        is_verified=breach_data.get("IsVerified", False),
                        is_sensitive=breach_data.get("IsSensitive", False),
                        pwn_count=breach_data.get("PwnCount", 0),
                        domain=breach_data.get("Domain"),
                        source="haveibeenpwned",
                        metadata=breach_data,
                    )

                    # Parse date
                    if "BreachDate" in breach_data:
                        try:
                            breach.breach_date = datetime.fromisoformat(breach_data["BreachDate"])
                        except ValueError:
                            pass

                    breaches.append(breach)

        except Exception:
            pass

        return breaches

    async def check_password(self, password: str) -> int:
        """
        Check if a password appears in known data breaches.

        Uses k-anonymity to check without exposing the full password.

        Args:
            password: Password to check

        Returns:
            Number of times the password appears in breaches
        """
        # Hash the password with SHA-1
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = await self.http_client.get(url)

            if response:
                # Response is text with format: SUFFIX:COUNT
                lines = response.split("\n") if isinstance(response, str) else []
                for line in lines:
                    if ":" in line:
                        hash_suffix, count = line.strip().split(":")
                        if hash_suffix == suffix:
                            return int(count)

        except Exception:
            pass

        return 0

    async def get_breach_info(self, breach_name: str) -> Optional[BreachRecord]:
        """
        Get detailed information about a specific breach.

        Args:
            breach_name: Name of the breach

        Returns:
            BreachRecord with breach details
        """
        try:
            url = f"{self._hibp_base_url}/breach/{breach_name}"
            response = await self.http_client.get(url, headers=self._headers)

            if response:
                return BreachRecord(
                    breach_name=response.get("Name", breach_name),
                    description=response.get("Description", ""),
                    data_classes=response.get("DataClasses", []),
                    is_verified=response.get("IsVerified", False),
                    is_sensitive=response.get("IsSensitive", False),
                    pwn_count=response.get("PwnCount", 0),
                    domain=response.get("Domain"),
                    source="haveibeenpwned",
                    metadata=response,
                )

        except Exception:
            pass

        return None

    def to_result(self, breaches: List[BreachRecord], email: str) -> Result:
        """Convert breach records to Result format."""
        return Result(
            source="breach_database",
            identifier=email,
            metadata={
                "email": email,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.breach_name,
                        "date": b.breach_date.isoformat() if b.breach_date else None,
                        "data_types": b.data_classes,
                        "is_verified": b.is_verified,
                        "is_sensitive": b.is_sensitive,
                        "pwn_count": b.pwn_count,
                    }
                    for b in breaches
                ],
            },
            confidence=1.0 if breaches else 0.0,
            timestamp=datetime.now(timezone.utc),
        )


class PasteCollector:
    """
    Collector for paste site mentions.

    Checks if an email appears in public paste sites.
    """

    def __init__(
        self, http_client: Optional[SimpleHTTPClient] = None, hibp_api_key: Optional[str] = None
    ):
        self.http_client = http_client or SimpleHTTPClient()
        self.hibp_api_key = hibp_api_key
        self._hibp_base_url = "https://haveibeenpwned.com/api/v3"
        self._headers = {"User-Agent": "TR4C3R-OSINT", "hibp-api-key": hibp_api_key or ""}

    async def check_email(self, email: str) -> List[PasteRecord]:
        """
        Check if an email appears in paste sites.

        Args:
            email: Email address to check

        Returns:
            List of pastes containing the email
        """
        pastes = []

        if not self.hibp_api_key:
            return pastes

        email = email.lower().strip()

        try:
            url = f"{self._hibp_base_url}/pasteaccount/{email}"
            response = await self.http_client.get(url, headers=self._headers)

            if response and isinstance(response, list):
                for paste_data in response:
                    paste = PasteRecord(
                        paste_id=paste_data.get("Id", ""),
                        source=paste_data.get("Source", "unknown"),
                        title=paste_data.get("Title"),
                        email_count=paste_data.get("EmailCount", 0),
                        metadata=paste_data,
                    )

                    # Parse date
                    if "Date" in paste_data:
                        try:
                            paste.date = datetime.fromisoformat(
                                paste_data["Date"].replace("Z", "+00:00")
                            )
                        except ValueError:
                            pass

                    pastes.append(paste)

        except Exception:
            pass

        return pastes

    def to_result(self, pastes: List[PasteRecord], email: str) -> Result:
        """Convert paste records to Result format."""
        return Result(
            source="paste_site",
            identifier=email,
            metadata={
                "email": email,
                "paste_count": len(pastes),
                "pastes": [
                    {
                        "id": p.paste_id,
                        "source": p.source,
                        "title": p.title,
                        "date": p.date.isoformat() if p.date else None,
                        "email_count": p.email_count,
                    }
                    for p in pastes
                ],
            },
            confidence=1.0 if pastes else 0.0,
            timestamp=datetime.now(timezone.utc),
        )


class DomainReputationCollector:
    """
    Collector for domain reputation information.

    Checks domain against threat intelligence feeds and blacklists.
    """

    def __init__(
        self,
        http_client: Optional[SimpleHTTPClient] = None,
        virustotal_api_key: Optional[str] = None,
    ):
        self.http_client = http_client or SimpleHTTPClient()
        self.virustotal_api_key = virustotal_api_key
        self._vt_base_url = "https://www.virustotal.com/api/v3"

    async def check_domain(self, domain: str) -> DomainReputation:
        """
        Check domain reputation.

        Args:
            domain: Domain to check

        Returns:
            DomainReputation with threat intelligence data
        """
        domain = self._normalize_domain(domain)

        reputation = DomainReputation(domain=domain)

        if not self.virustotal_api_key:
            return reputation

        try:
            url = f"{self._vt_base_url}/domains/{domain}"
            headers = {"x-apikey": self.virustotal_api_key}

            response = await self.http_client.get(url, headers=headers)

            if response and "data" in response:
                data = response["data"]
                attributes = data.get("attributes", {})

                # Check if malicious
                analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = analysis_stats.get("malicious", 0)
                total = sum(analysis_stats.values()) or 1

                reputation.is_malicious = malicious_count > 0
                reputation.risk_score = (malicious_count / total) * 100

                # Get categories
                reputation.categories = list(attributes.get("categories", {}).values())

                # Get blacklist detections
                last_analysis = attributes.get("last_analysis_results", {})
                for engine, result in last_analysis.items():
                    if result.get("category") == "malicious":
                        reputation.blacklists.append(engine)

                # Get dates
                if "creation_date" in attributes:
                    reputation.first_seen = datetime.fromtimestamp(attributes["creation_date"])

                # Get DNS info
                if "last_dns_records" in attributes:
                    for record in attributes["last_dns_records"]:
                        if record.get("type") == "A":
                            reputation.ip_addresses.append(record.get("value", ""))

                # SSL info
                if "last_https_certificate" in attributes:
                    cert = attributes["last_https_certificate"]
                    reputation.ssl_info = {
                        "issuer": cert.get("issuer", {}),
                        "validity": cert.get("validity", {}),
                        "subject": cert.get("subject", {}),
                    }

        except Exception:
            pass

        return reputation

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain for lookup."""
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = domain.split("/")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.lower()

    async def check_ip(self, ip_address: str) -> DomainReputation:
        """
        Check IP address reputation.

        Args:
            ip_address: IP address to check

        Returns:
            DomainReputation with threat intelligence data
        """
        reputation = DomainReputation(domain=ip_address)
        reputation.ip_addresses = [ip_address]

        if not self.virustotal_api_key:
            return reputation

        try:
            url = f"{self._vt_base_url}/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.virustotal_api_key}

            response = await self.http_client.get(url, headers=headers)

            if response and "data" in response:
                data = response["data"]
                attributes = data.get("attributes", {})

                analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = analysis_stats.get("malicious", 0)
                total = sum(analysis_stats.values()) or 1

                reputation.is_malicious = malicious_count > 0
                reputation.risk_score = (malicious_count / total) * 100

                # Get blacklist detections
                last_analysis = attributes.get("last_analysis_results", {})
                for engine, result in last_analysis.items():
                    if result.get("category") == "malicious":
                        reputation.blacklists.append(engine)

        except Exception:
            pass

        return reputation

    def to_result(self, reputation: DomainReputation) -> Result:
        """Convert domain reputation to Result format."""
        return Result(
            source="threat_intel",
            identifier=reputation.domain,
            metadata={
                "domain": reputation.domain,
                "is_malicious": reputation.is_malicious,
                "risk_score": reputation.risk_score,
                "categories": reputation.categories,
                "blacklists": reputation.blacklists,
                "ip_addresses": reputation.ip_addresses,
                "ssl_info": reputation.ssl_info,
            },
            confidence=1.0 if reputation.risk_score > 0 else 0.5,
            timestamp=datetime.now(timezone.utc),
        )


class IntegrationManager:
    """
    Manager for all API integrations.

    Provides a unified interface for querying multiple data sources.
    """

    def __init__(
        self,
        http_client: Optional[SimpleHTTPClient] = None,
        hibp_api_key: Optional[str] = None,
        virustotal_api_key: Optional[str] = None,
    ):
        self.http_client = http_client or SimpleHTTPClient()

        # Initialize collectors
        self.dns = DNSCollector(http_client=self.http_client)
        self.whois = WHOISCollector(http_client=self.http_client)
        self.breach = BreachCollector(http_client=self.http_client, hibp_api_key=hibp_api_key)
        self.paste = PasteCollector(http_client=self.http_client, hibp_api_key=hibp_api_key)
        self.reputation = DomainReputationCollector(
            http_client=self.http_client, virustotal_api_key=virustotal_api_key
        )

    async def investigate_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive domain investigation.

        Args:
            domain: Domain to investigate

        Returns:
            Dictionary with all gathered information
        """
        results = {}

        # Run all domain-related lookups concurrently
        dns_task = self.dns.lookup_all(domain)
        whois_task = self.whois.lookup(domain)
        reputation_task = self.reputation.check_domain(domain)

        dns_result, whois_result, reputation_result = await asyncio.gather(
            dns_task, whois_task, reputation_task, return_exceptions=True
        )

        if not isinstance(dns_result, Exception):
            results["dns"] = {
                rt.value: [{"value": r.value, "ttl": r.ttl} for r in records]
                for rt, records in dns_result.items()
            }

        if not isinstance(whois_result, Exception) and whois_result:
            results["whois"] = {
                "registrar": whois_result.registrar,
                "creation_date": whois_result.creation_date,
                "expiration_date": whois_result.expiration_date,
                "name_servers": whois_result.name_servers,
                "status": whois_result.status,
            }

        if not isinstance(reputation_result, Exception):
            results["reputation"] = {
                "is_malicious": reputation_result.is_malicious,
                "risk_score": reputation_result.risk_score,
                "categories": reputation_result.categories,
                "blacklists": reputation_result.blacklists,
            }

        return results

    async def investigate_email(self, email: str) -> Dict[str, Any]:
        """
        Perform comprehensive email investigation.

        Args:
            email: Email to investigate

        Returns:
            Dictionary with all gathered information
        """
        results = {}

        # Extract domain from email
        if "@" in email:
            domain = email.split("@")[1]
        else:
            return results

        # Run all email-related lookups concurrently
        breach_task = self.breach.check_email(email)
        paste_task = self.paste.check_email(email)
        domain_task = self.investigate_domain(domain)

        breach_result, paste_result, domain_result = await asyncio.gather(
            breach_task, paste_task, domain_task, return_exceptions=True
        )

        if not isinstance(breach_result, Exception):
            results["breaches"] = [
                {"name": b.breach_name, "date": b.breach_date, "data_types": b.data_classes}
                for b in breach_result
            ]

        if not isinstance(paste_result, Exception):
            results["pastes"] = [
                {"id": p.paste_id, "source": p.source, "date": p.date} for p in paste_result
            ]

        if not isinstance(domain_result, Exception):
            results["domain"] = domain_result

        return results

    async def check_ip_reputation(self, ip_address: str) -> DomainReputation:
        """
        Check IP address reputation.

        Args:
            ip_address: IP to check

        Returns:
            DomainReputation with threat data
        """
        return await self.reputation.check_ip(ip_address)

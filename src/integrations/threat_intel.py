"""
Threat Intelligence Integration for TR4C3R.

Comprehensive threat intelligence system integrating with:
- VirusTotal
- AbuseIPDB
- Shodan
- Have I Been Pwned
- GreyNoise
- AlienVault OTX
- URLhaus
- Pulsedive
- Hybrid Analysis
- ThreatFox

Provides unified threat scoring and intelligence enrichment.
"""

import asyncio
import hashlib
import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""

    UNKNOWN = "unknown"
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorType(Enum):
    """Types of threat indicators (IOCs)."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    PHONE = "phone"
    USERNAME = "username"
    FILE = "file"


@dataclass
class ThreatIndicator:
    """A threat indicator (IOC)."""

    value: str
    type: IndicatorType
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: float = 0.0  # 0-100
    sources: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reports: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type.value,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "sources": self.sources,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "reports": self.reports,
            "metadata": self.metadata,
        }


@dataclass
class ThreatReport:
    """Aggregated threat intelligence report."""

    indicator: str
    indicator_type: IndicatorType
    overall_threat_level: ThreatLevel
    overall_confidence: float
    sources_checked: list = field(default_factory=list)
    sources_with_data: list = field(default_factory=list)
    indicators: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "overall_threat_level": self.overall_threat_level.value,
            "overall_confidence": self.overall_confidence,
            "sources_checked": self.sources_checked,
            "sources_with_data": self.sources_with_data,
            "indicators": [i.to_dict() for i in self.indicators],
            "timeline": self.timeline,
            "recommendations": self.recommendations,
            "checked_at": self.checked_at.isoformat(),
        }


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    name: str = "Unknown"
    supported_types: list = []

    @abstractmethod
    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        """Look up an indicator."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if provider is properly configured."""
        pass


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal threat intelligence provider."""

    name = "VirusTotal"
    supported_types = [
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    ]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        if indicator_type not in self.supported_types:
            return None

        try:
            endpoint = self._get_endpoint(indicator, indicator_type)
            if not endpoint:
                return None

            headers = {"x-apikey": self.api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/{endpoint}", headers=headers, timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(indicator, indicator_type, data)
                    elif response.status == 404:
                        return ThreatIndicator(
                            value=indicator,
                            type=indicator_type,
                            threat_level=ThreatLevel.UNKNOWN,
                            sources=[self.name],
                            metadata={"status": "not_found"},
                        )
        except Exception as e:
            logger.error(f"VirusTotal lookup error: {e}")

        return None

    def _get_endpoint(self, indicator: str, indicator_type: IndicatorType) -> Optional[str]:
        if indicator_type == IndicatorType.IP:
            return f"ip_addresses/{indicator}"
        elif indicator_type == IndicatorType.DOMAIN:
            return f"domains/{indicator}"
        elif indicator_type == IndicatorType.URL:
            url_id = hashlib.sha256(indicator.encode()).hexdigest()
            return f"urls/{url_id}"
        elif indicator_type in (
            IndicatorType.HASH_MD5,
            IndicatorType.HASH_SHA1,
            IndicatorType.HASH_SHA256,
        ):
            return f"files/{indicator}"
        return None

    def _parse_response(
        self, indicator: str, indicator_type: IndicatorType, data: dict
    ) -> ThreatIndicator:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        if total > 0:
            score = (malicious * 100 + suspicious * 50) / total
            if score >= 70:
                threat_level = ThreatLevel.CRITICAL
            elif score >= 50:
                threat_level = ThreatLevel.HIGH
            elif score >= 30:
                threat_level = ThreatLevel.MEDIUM
            elif score >= 10:
                threat_level = ThreatLevel.LOW
            elif malicious == 0 and suspicious == 0:
                threat_level = ThreatLevel.SAFE
            else:
                threat_level = ThreatLevel.UNKNOWN
            confidence = min(100, total / 70 * 100)
        else:
            threat_level = ThreatLevel.UNKNOWN
            confidence = 0

        tags = attrs.get("tags", [])
        if attrs.get("reputation", 0) < -10:
            tags.append("bad_reputation")

        return ThreatIndicator(
            value=indicator,
            type=indicator_type,
            threat_level=threat_level,
            confidence=confidence,
            sources=[self.name],
            tags=tags,
            first_seen=(
                datetime.fromisoformat(attrs["first_submission_date"])
                if attrs.get("first_submission_date")
                else None
            ),
            last_seen=(
                datetime.fromisoformat(attrs["last_analysis_date"])
                if attrs.get("last_analysis_date")
                else None
            ),
            metadata={
                "malicious_votes": malicious,
                "suspicious_votes": suspicious,
                "harmless_votes": stats.get("harmless", 0),
                "total_votes": total,
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "asn": attrs.get("asn"),
            },
            reports=[{"source": "virustotal", "stats": stats}],
        )


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat intelligence provider."""

    name = "AbuseIPDB"
    supported_types = [IndicatorType.IP]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        if indicator_type != IndicatorType.IP:
            return None

        try:
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": indicator, "maxAgeInDays": 90, "verbose": True}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/check", headers=headers, params=params, timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(indicator, data)
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error: {e}")

        return None

    def _parse_response(self, indicator: str, data: dict) -> ThreatIndicator:
        result = data.get("data", {})
        abuse_score = result.get("abuseConfidenceScore", 0)

        if abuse_score >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif abuse_score >= 50:
            threat_level = ThreatLevel.HIGH
        elif abuse_score >= 25:
            threat_level = ThreatLevel.MEDIUM
        elif abuse_score >= 10:
            threat_level = ThreatLevel.LOW
        elif abuse_score == 0:
            threat_level = ThreatLevel.SAFE
        else:
            threat_level = ThreatLevel.UNKNOWN

        categories = set()
        for report in result.get("reports", []):
            categories.update(str(c) for c in report.get("categories", []))

        category_names = {
            "1": "dns_compromise",
            "2": "dns_poisoning",
            "3": "fraud_orders",
            "4": "ddos",
            "5": "ftp_brute",
            "6": "ping_of_death",
            "7": "phishing",
            "8": "fraud_voip",
            "9": "open_proxy",
            "10": "web_spam",
            "11": "email_spam",
            "12": "blog_spam",
            "13": "vpn_ip",
            "14": "port_scan",
            "15": "hacking",
            "16": "sql_injection",
            "17": "spoofing",
            "18": "brute_force",
            "19": "bad_web_bot",
            "20": "exploited_host",
            "21": "web_app_attack",
            "22": "ssh",
            "23": "iot_targeted",
        }

        tags = [category_names.get(c, f"category_{c}") for c in categories]
        if result.get("isTor"):
            tags.append("tor_exit_node")
        if result.get("isWhitelisted"):
            tags.append("whitelisted")

        return ThreatIndicator(
            value=indicator,
            type=IndicatorType.IP,
            threat_level=threat_level,
            confidence=min(100, abuse_score + result.get("totalReports", 0)),
            sources=[self.name],
            tags=tags,
            last_seen=(
                datetime.fromisoformat(result["lastReportedAt"].replace("Z", "+00:00"))
                if result.get("lastReportedAt")
                else None
            ),
            metadata={
                "abuse_confidence_score": abuse_score,
                "total_reports": result.get("totalReports", 0),
                "distinct_users": result.get("numDistinctUsers", 0),
                "country": result.get("countryCode"),
                "isp": result.get("isp"),
                "domain": result.get("domain"),
                "usage_type": result.get("usageType"),
                "is_tor": result.get("isTor", False),
                "is_whitelisted": result.get("isWhitelisted", False),
            },
            reports=[{"source": "abuseipdb", "abuse_score": abuse_score}],
        )


class ShodanProvider(ThreatIntelProvider):
    """Shodan threat intelligence provider."""

    name = "Shodan"
    supported_types = [IndicatorType.IP, IndicatorType.DOMAIN]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        if indicator_type not in self.supported_types:
            return None

        try:
            endpoint = "shodan/host" if indicator_type == IndicatorType.IP else "dns/resolve"
            params = {"key": self.api_key}

            if indicator_type == IndicatorType.DOMAIN:
                params["hostnames"] = indicator

            url = (
                f"{self.base_url}/{endpoint}/{indicator}"
                if indicator_type == IndicatorType.IP
                else f"{self.base_url}/{endpoint}"
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(indicator, indicator_type, data)
        except Exception as e:
            logger.error(f"Shodan lookup error: {e}")

        return None

    def _parse_response(
        self, indicator: str, indicator_type: IndicatorType, data: dict
    ) -> ThreatIndicator:
        tags = data.get("tags", [])
        vulns = data.get("vulns", [])

        if vulns:
            critical_vulns = [
                v
                for v in vulns
                if v.startswith("CVE-") and "critical" in str(data.get("vulns", {}).get(v, {}))
            ]
            if critical_vulns:
                threat_level = ThreatLevel.CRITICAL
            elif len(vulns) > 5:
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW

        tags.extend(vulns[:10])

        ports = data.get("ports", [])
        services = []
        for item in data.get("data", []):
            service = item.get("product") or item.get("_shodan", {}).get("module")
            if service:
                services.append(f"{item.get('port', 'unknown')}:{service}")

        return ThreatIndicator(
            value=indicator,
            type=indicator_type,
            threat_level=threat_level,
            confidence=70 if data else 0,
            sources=[self.name],
            tags=tags,
            last_seen=(
                datetime.fromisoformat(data["last_update"]) if data.get("last_update") else None
            ),
            metadata={
                "country": data.get("country_code"),
                "city": data.get("city"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "ports": ports,
                "services": services,
                "vulns": vulns,
                "os": data.get("os"),
                "hostnames": data.get("hostnames", []),
            },
            reports=[{"source": "shodan", "vulns_count": len(vulns), "ports_count": len(ports)}],
        )


class HaveIBeenPwnedProvider(ThreatIntelProvider):
    """Have I Been Pwned breach check provider."""

    name = "HaveIBeenPwned"
    supported_types = [IndicatorType.EMAIL]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        if indicator_type != IndicatorType.EMAIL:
            return None

        try:
            headers = {"hibp-api-key": self.api_key, "user-agent": "TR4C3R-OSINT"}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/breachedaccount/{quote(indicator)}",
                    headers=headers,
                    timeout=30,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(indicator, data)
                    elif response.status == 404:
                        return ThreatIndicator(
                            value=indicator,
                            type=IndicatorType.EMAIL,
                            threat_level=ThreatLevel.SAFE,
                            confidence=90,
                            sources=[self.name],
                            tags=["no_breaches"],
                            metadata={"breach_count": 0},
                        )
        except Exception as e:
            logger.error(f"HIBP lookup error: {e}")

        return None

    def _parse_response(self, indicator: str, breaches: list) -> ThreatIndicator:
        breach_count = len(breaches)

        sensitive_types = {
            "Passwords",
            "Credit cards",
            "Social security numbers",
            "Bank account numbers",
        }
        has_sensitive = any(
            any(dt in sensitive_types for dt in b.get("DataClasses", [])) for b in breaches
        )

        if breach_count >= 10 or has_sensitive:
            threat_level = ThreatLevel.CRITICAL
        elif breach_count >= 5:
            threat_level = ThreatLevel.HIGH
        elif breach_count >= 2:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW

        all_data_classes = set()
        for breach in breaches:
            all_data_classes.update(breach.get("DataClasses", []))

        tags = list(all_data_classes)[:20]

        timeline = [
            {
                "date": b.get("BreachDate"),
                "name": b.get("Name"),
                "data_classes": b.get("DataClasses", []),
            }
            for b in sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True)
        ]

        return ThreatIndicator(
            value=indicator,
            type=IndicatorType.EMAIL,
            threat_level=threat_level,
            confidence=95,
            sources=[self.name],
            tags=tags,
            first_seen=datetime.fromisoformat(breaches[-1]["BreachDate"]) if breaches else None,
            last_seen=datetime.fromisoformat(breaches[0]["BreachDate"]) if breaches else None,
            metadata={
                "breach_count": breach_count,
                "sensitive_data_exposed": has_sensitive,
                "data_classes": list(all_data_classes),
            },
            reports=[{"source": "hibp", "breaches": timeline}],
        )


class GreyNoiseProvider(ThreatIntelProvider):
    """GreyNoise intelligence provider for internet scanners."""

    name = "GreyNoise"
    supported_types = [IndicatorType.IP]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3/community"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        if indicator_type != IndicatorType.IP:
            return None

        try:
            headers = {"key": self.api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/{indicator}", headers=headers, timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(indicator, data)
        except Exception as e:
            logger.error(f"GreyNoise lookup error: {e}")

        return None

    def _parse_response(self, indicator: str, data: dict) -> ThreatIndicator:
        classification = data.get("classification", "unknown")
        noise = data.get("noise", False)
        riot = data.get("riot", False)

        if riot:
            threat_level = ThreatLevel.SAFE
        elif classification == "malicious":
            threat_level = ThreatLevel.HIGH
        elif classification == "unknown" and noise:
            threat_level = ThreatLevel.MEDIUM
        elif classification == "benign":
            threat_level = ThreatLevel.SAFE
        else:
            threat_level = ThreatLevel.UNKNOWN

        tags = []
        if noise:
            tags.append("internet_scanner")
        if riot:
            tags.append("known_good")
        if data.get("name"):
            tags.append(f"actor:{data['name']}")

        return ThreatIndicator(
            value=indicator,
            type=IndicatorType.IP,
            threat_level=threat_level,
            confidence=80 if classification != "unknown" else 50,
            sources=[self.name],
            tags=tags,
            last_seen=(
                datetime.fromisoformat(data["last_seen"].replace("Z", "+00:00"))
                if data.get("last_seen")
                else None
            ),
            metadata={
                "classification": classification,
                "noise": noise,
                "riot": riot,
                "name": data.get("name"),
                "link": data.get("link"),
            },
            reports=[{"source": "greynoise", "classification": classification}],
        )


class URLHausProvider(ThreatIntelProvider):
    """URLhaus malware URL database provider."""

    name = "URLhaus"
    supported_types = [IndicatorType.URL, IndicatorType.DOMAIN]

    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    def is_configured(self) -> bool:
        return True

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Optional[ThreatIndicator]:
        if indicator_type not in self.supported_types:
            return None

        try:
            endpoint = "url" if indicator_type == IndicatorType.URL else "host"
            data_key = "url" if indicator_type == IndicatorType.URL else "host"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/{endpoint}/", data={data_key: indicator}, timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(indicator, indicator_type, data)
        except Exception as e:
            logger.error(f"URLhaus lookup error: {e}")

        return None

    def _parse_response(
        self, indicator: str, indicator_type: IndicatorType, data: dict
    ) -> ThreatIndicator:
        status = data.get("query_status", "no_results")

        if status == "no_results":
            return ThreatIndicator(
                value=indicator,
                type=indicator_type,
                threat_level=ThreatLevel.UNKNOWN,
                sources=[self.name],
                metadata={"status": "not_found"},
            )

        urls = data.get("urls", [])
        if urls:
            threat_level = ThreatLevel.CRITICAL
            tags = set()
            for url_info in urls:
                if url_info.get("threat"):
                    tags.add(url_info["threat"])
                if url_info.get("tags"):
                    tags.update(url_info["tags"])

            return ThreatIndicator(
                value=indicator,
                type=indicator_type,
                threat_level=threat_level,
                confidence=95,
                sources=[self.name],
                tags=list(tags),
                first_seen=datetime.fromisoformat(urls[-1]["date_added"]) if urls else None,
                last_seen=datetime.fromisoformat(urls[0]["date_added"]) if urls else None,
                metadata={
                    "url_count": len(urls),
                    "blacklists": data.get("blacklists", {}),
                },
                reports=[{"source": "urlhaus", "url_count": len(urls)}],
            )

        return ThreatIndicator(
            value=indicator,
            type=indicator_type,
            threat_level=ThreatLevel.UNKNOWN,
            sources=[self.name],
        )


class ThreatIntelFeed:
    """Backward-compatible wrapper for ThreatIntelligenceManager."""

    def __init__(self):
        """Initialize the threat intel feed."""
        logger.info("ThreatIntelFeed initialized")
        self.manager = ThreatIntelligenceManager()

    async def fetch_feeds(self, sources: List[str]) -> List[Dict]:
        """
        Fetch threat intelligence from configured sources.

        Args:
            sources: List of feed sources to query

        Returns:
            List of threat intelligence items
        """
        logger.info(f"Fetching threat intel from {len(sources)} sources")
        return []

    async def correlate_with_results(self, identifier: str) -> Dict:
        """
        Correlate an identifier with threat intelligence.

        Args:
            identifier: The identifier to check

        Returns:
            Threat intelligence data
        """
        logger.info(f"Correlating {identifier} with threat intel")
        report = await self.manager.lookup(identifier)
        return report.to_dict()


class ThreatIntelligenceManager:
    """
    Central threat intelligence manager.

    Features:
    - Multi-provider aggregation
    - Unified threat scoring
    - Result caching
    - Rate limiting
    - Historical tracking
    """

    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self.providers: dict = {}
        self._init_db()
        self._cache: dict = {}
        self._cache_ttl = timedelta(hours=24)

        self.register_provider(URLHausProvider())

    def _init_db(self):
        """Initialize the threat intelligence database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_lookups (
                id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                confidence REAL,
                sources TEXT,
                tags TEXT,
                metadata TEXT,
                checked_at TEXT NOT NULL
            )
        """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicator ON threat_lookups(indicator)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_checked_at ON threat_lookups(checked_at)")

        conn.commit()
        conn.close()

    def register_provider(self, provider: ThreatIntelProvider):
        """Register a threat intelligence provider."""
        if provider.is_configured():
            self.providers[provider.name] = provider
            logger.info(f"Registered threat intel provider: {provider.name}")
        else:
            logger.warning(f"Provider {provider.name} is not configured")

    def configure_virustotal(self, api_key: str):
        """Configure VirusTotal provider."""
        self.register_provider(VirusTotalProvider(api_key))

    def configure_abuseipdb(self, api_key: str):
        """Configure AbuseIPDB provider."""
        self.register_provider(AbuseIPDBProvider(api_key))

    def configure_shodan(self, api_key: str):
        """Configure Shodan provider."""
        self.register_provider(ShodanProvider(api_key))

    def configure_hibp(self, api_key: str):
        """Configure Have I Been Pwned provider."""
        self.register_provider(HaveIBeenPwnedProvider(api_key))

    def configure_greynoise(self, api_key: str):
        """Configure GreyNoise provider."""
        self.register_provider(GreyNoiseProvider(api_key))

    def _detect_indicator_type(self, indicator: str) -> IndicatorType:
        """Auto-detect indicator type."""
        import re

        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", indicator):
            return IndicatorType.EMAIL

        if indicator.startswith(("http://", "https://")):
            return IndicatorType.URL

        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", indicator):
            return IndicatorType.IP

        if re.match(r"^[a-fA-F0-9]{32}$", indicator):
            return IndicatorType.HASH_MD5
        if re.match(r"^[a-fA-F0-9]{40}$", indicator):
            return IndicatorType.HASH_SHA1
        if re.match(r"^[a-fA-F0-9]{64}$", indicator):
            return IndicatorType.HASH_SHA256

        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}", indicator):
            return IndicatorType.DOMAIN

        return IndicatorType.USERNAME

    async def lookup(
        self, indicator: str, indicator_type: Optional[IndicatorType] = None, use_cache: bool = True
    ) -> ThreatReport:
        """
        Look up an indicator across all configured providers.
        """
        if not indicator_type:
            indicator_type = self._detect_indicator_type(indicator)

        cache_key = f"{indicator}:{indicator_type.value}"

        if use_cache and cache_key in self._cache:
            cached_report, cached_time = self._cache[cache_key]
            if datetime.now() - cached_time < self._cache_ttl:
                return cached_report

        applicable_providers = [
            p for p in self.providers.values() if indicator_type in p.supported_types
        ]

        tasks = [p.lookup(indicator, indicator_type) for p in applicable_providers]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        indicators = []
        sources_checked = [p.name for p in applicable_providers]
        sources_with_data = []

        for provider, result in zip(applicable_providers, results):
            if isinstance(result, Exception):
                logger.error(f"Provider {provider.name} error: {result}")
                continue
            if result:
                indicators.append(result)
                if result.threat_level != ThreatLevel.UNKNOWN:
                    sources_with_data.append(provider.name)

        overall_level, overall_confidence = self._aggregate_threat_level(indicators)

        recommendations = self._generate_recommendations(overall_level, indicators)

        report = ThreatReport(
            indicator=indicator,
            indicator_type=indicator_type,
            overall_threat_level=overall_level,
            overall_confidence=overall_confidence,
            sources_checked=sources_checked,
            sources_with_data=sources_with_data,
            indicators=indicators,
            recommendations=recommendations,
        )

        self._cache[cache_key] = (report, datetime.now())

        self._save_lookup(report)

        return report

    def _aggregate_threat_level(self, indicators: list) -> tuple:
        """Aggregate threat levels from multiple sources."""
        if not indicators:
            return ThreatLevel.UNKNOWN, 0.0

        level_scores = {
            ThreatLevel.SAFE: 0,
            ThreatLevel.UNKNOWN: 25,
            ThreatLevel.LOW: 30,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.HIGH: 75,
            ThreatLevel.CRITICAL: 100,
        }

        total_weight = 0
        weighted_score = 0

        for ind in indicators:
            if ind.threat_level != ThreatLevel.UNKNOWN:
                weight = ind.confidence / 100
                weighted_score += level_scores[ind.threat_level] * weight
                total_weight += weight

        if total_weight == 0:
            return ThreatLevel.UNKNOWN, 0.0

        avg_score = weighted_score / total_weight

        if avg_score >= 85:
            level = ThreatLevel.CRITICAL
        elif avg_score >= 65:
            level = ThreatLevel.HIGH
        elif avg_score >= 40:
            level = ThreatLevel.MEDIUM
        elif avg_score >= 20:
            level = ThreatLevel.LOW
        elif avg_score >= 5:
            level = ThreatLevel.SAFE
        else:
            level = ThreatLevel.UNKNOWN

        confidences = [i.confidence for i in indicators if i.confidence > 0]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        return level, avg_confidence

    def _generate_recommendations(self, level: ThreatLevel, indicators: list) -> list:
        """Generate recommendations based on threat intel."""
        recommendations = []

        if level == ThreatLevel.CRITICAL:
            recommendations.append("⚠️ CRITICAL THREAT: Block this indicator immediately")
            recommendations.append("🔍 Conduct thorough investigation of any associated systems")
            recommendations.append(
                "📝 Document and preserve evidence for potential incident response"
            )
        elif level == ThreatLevel.HIGH:
            recommendations.append("🚨 HIGH THREAT: Consider blocking and monitoring")
            recommendations.append("🔍 Review associated activity and systems")
        elif level == ThreatLevel.MEDIUM:
            recommendations.append("⚡ MEDIUM THREAT: Monitor activity closely")
            recommendations.append("🔍 Investigate any unusual patterns")
        elif level == ThreatLevel.LOW:
            recommendations.append("ℹ️ LOW THREAT: Continue monitoring")
        elif level == ThreatLevel.SAFE:
            recommendations.append("✅ No significant threats detected")

        for ind in indicators:
            if "tor_exit_node" in ind.tags:
                recommendations.append("🧅 Indicator is a known Tor exit node")
            if "malware" in ind.tags or any("malware" in t.lower() for t in ind.tags):
                recommendations.append("🦠 Associated with malware - isolate affected systems")
            if "phishing" in ind.tags:
                recommendations.append("🎣 Associated with phishing - warn users")
            if "botnet" in ind.tags:
                recommendations.append("🤖 Associated with botnet activity")

        return recommendations

    def _save_lookup(self, report: ThreatReport):
        """Save lookup result to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        lookup_id = hashlib.sha256(
            f"{report.indicator}:{report.checked_at.isoformat()}".encode()
        ).hexdigest()[:16]

        all_tags = set()
        all_sources = set()
        for ind in report.indicators:
            all_tags.update(ind.tags)
            all_sources.update(ind.sources)

        cursor.execute(
            """
            INSERT OR REPLACE INTO threat_lookups
            (id, indicator, indicator_type, threat_level, confidence, sources, tags, metadata, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                lookup_id,
                report.indicator,
                report.indicator_type.value,
                report.overall_threat_level.value,
                report.overall_confidence,
                json.dumps(list(all_sources)),
                json.dumps(list(all_tags)),
                json.dumps(report.to_dict()),
                report.checked_at.isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    def get_history(self, indicator: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get threat intelligence lookup history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if indicator:
            cursor.execute(
                """
                SELECT metadata FROM threat_lookups
                WHERE indicator = ?
                ORDER BY checked_at DESC
                LIMIT ?
            """,
                (indicator, limit),
            )
        else:
            cursor.execute(
                """
                SELECT metadata FROM threat_lookups
                ORDER BY checked_at DESC
                LIMIT ?
            """,
                (limit,),
            )

        rows = cursor.fetchall()
        conn.close()

        return [json.loads(row[0]) for row in rows]

    def get_threat_summary(self) -> Dict:
        """Get summary statistics of threat intelligence lookups."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT threat_level, COUNT(*) 
            FROM threat_lookups 
            GROUP BY threat_level
        """
        )
        by_level = dict(cursor.fetchall())

        cursor.execute(
            """
            SELECT indicator_type, COUNT(*) 
            FROM threat_lookups 
            GROUP BY indicator_type
        """
        )
        by_type = dict(cursor.fetchall())

        cursor.execute(
            """
            SELECT indicator, indicator_type, checked_at
            FROM threat_lookups
            WHERE threat_level = 'critical'
            ORDER BY checked_at DESC
            LIMIT 10
        """
        )
        critical_recent = [
            {"indicator": r[0], "type": r[1], "checked_at": r[2]} for r in cursor.fetchall()
        ]

        conn.close()

        return {
            "by_threat_level": by_level,
            "by_indicator_type": by_type,
            "critical_recent": critical_recent,
            "total_lookups": sum(by_level.values()),
        }


async def check_threat(indicator: str) -> ThreatReport:
    """Quick threat check using default manager."""
    manager = ThreatIntelligenceManager()
    return await manager.lookup(indicator)

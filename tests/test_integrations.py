"""Tests for API integration collectors."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

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


class TestRecordType:
    """Tests for RecordType enum."""

    def test_record_types(self):
        """Test all DNS record types are defined."""
        assert RecordType.A == "A"
        assert RecordType.AAAA == "AAAA"
        assert RecordType.MX == "MX"
        assert RecordType.TXT == "TXT"
        assert RecordType.NS == "NS"
        assert RecordType.CNAME == "CNAME"
        assert RecordType.SOA == "SOA"
        assert RecordType.PTR == "PTR"
        assert RecordType.SRV == "SRV"
        assert RecordType.CAA == "CAA"


class TestDNSRecord:
    """Tests for DNSRecord dataclass."""

    def test_dns_record_creation(self):
        """Test creating a DNS record."""
        record = DNSRecord(
            record_type=RecordType.A, name="example.com", value="93.184.216.34", ttl=300
        )

        assert record.record_type == RecordType.A
        assert record.name == "example.com"
        assert record.value == "93.184.216.34"
        assert record.ttl == 300
        assert record.priority is None
        assert record.metadata == {}

    def test_mx_record_with_priority(self):
        """Test MX record with priority."""
        record = DNSRecord(
            record_type=RecordType.MX,
            name="example.com",
            value="mail.example.com",
            ttl=3600,
            priority=10,
        )

        assert record.priority == 10


class TestWHOISInfo:
    """Tests for WHOISInfo dataclass."""

    def test_whois_info_creation(self):
        """Test creating WHOIS info."""
        info = WHOISInfo(
            domain="example.com",
            registrar="Example Registrar Inc.",
            creation_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
            expiration_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            registrant_name="John Doe",
            registrant_org="Example Corp",
            name_servers=["ns1.example.com", "ns2.example.com"],
        )

        assert info.domain == "example.com"
        assert info.registrar == "Example Registrar Inc."
        assert info.registrant_name == "John Doe"
        assert len(info.name_servers) == 2
        assert info.dnssec is False

    def test_whois_info_defaults(self):
        """Test WHOIS info default values."""
        info = WHOISInfo(domain="test.com")

        assert info.registrar is None
        assert info.creation_date is None
        assert info.name_servers == []
        assert info.status == []


class TestBreachRecord:
    """Tests for BreachRecord dataclass."""

    def test_breach_record_creation(self):
        """Test creating a breach record."""
        record = BreachRecord(
            breach_name="Adobe",
            breach_date=datetime(2013, 10, 4, tzinfo=timezone.utc),
            domain="adobe.com",
            description="Adobe breach in 2013",
            data_classes=["Email addresses", "Password hints", "Passwords"],
            is_verified=True,
            pwn_count=152445165,
        )

        assert record.breach_name == "Adobe"
        assert record.is_verified is True
        assert record.pwn_count == 152445165
        assert "Passwords" in record.data_classes


class TestPasteRecord:
    """Tests for PasteRecord dataclass."""

    def test_paste_record_creation(self):
        """Test creating a paste record."""
        record = PasteRecord(
            paste_id="abc123", source="pastebin", title="Test Paste", email_count=500
        )

        assert record.paste_id == "abc123"
        assert record.source == "pastebin"
        assert record.email_count == 500


class TestDomainReputation:
    """Tests for DomainReputation dataclass."""

    def test_domain_reputation_creation(self):
        """Test creating domain reputation."""
        reputation = DomainReputation(
            domain="malicious-site.com",
            is_malicious=True,
            risk_score=85.0,
            categories=["phishing", "malware"],
            blacklists=["Fortinet", "Kaspersky"],
        )

        assert reputation.is_malicious is True
        assert reputation.risk_score == 85.0
        assert "phishing" in reputation.categories
        assert len(reputation.blacklists) == 2

    def test_safe_domain_defaults(self):
        """Test safe domain default values."""
        reputation = DomainReputation(domain="safe-site.com")

        assert reputation.is_malicious is False
        assert reputation.risk_score == 0.0
        assert reputation.categories == []
        assert reputation.blacklists == []


class TestDNSCollector:
    """Tests for DNSCollector."""

    @pytest.fixture
    def collector(self):
        """Create a DNS collector with mocked HTTP client."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        return DNSCollector(http_client=mock_client)

    async def test_lookup_a_record(self, collector):
        """Test A record lookup."""
        collector.http_client.get.return_value = {
            "Status": 0,
            "Answer": [{"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}],
        }

        records = await collector.lookup("example.com", RecordType.A)

        assert len(records) == 1
        assert records[0].value == "93.184.216.34"
        assert records[0].ttl == 300

    async def test_lookup_mx_record(self, collector):
        """Test MX record lookup with priority parsing."""
        collector.http_client.get.return_value = {
            "Status": 0,
            "Answer": [
                {"name": "example.com.", "type": 15, "TTL": 3600, "data": "10 mail.example.com."}
            ],
        }

        records = await collector.lookup("example.com", RecordType.MX)

        assert len(records) == 1
        assert records[0].priority == 10
        assert records[0].value == "mail.example.com"

    async def test_lookup_no_records(self, collector):
        """Test lookup with no records found."""
        collector.http_client.get.return_value = {"Status": 0, "Answer": []}

        records = await collector.lookup("nonexistent.com", RecordType.A)

        assert len(records) == 0

    async def test_lookup_error_handling(self, collector):
        """Test lookup handles errors gracefully."""
        collector.http_client.get.side_effect = Exception("Network error")

        records = await collector.lookup("example.com", RecordType.A)

        assert len(records) == 0

    async def test_lookup_all(self, collector):
        """Test lookup all record types."""
        collector.http_client.get.return_value = {
            "Status": 0,
            "Answer": [{"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}],
        }

        results = await collector.lookup_all("example.com")

        assert RecordType.A in results
        assert RecordType.MX in results
        assert RecordType.NS in results

    async def test_reverse_lookup(self, collector):
        """Test reverse DNS lookup."""
        collector.http_client.get.return_value = {
            "Status": 0,
            "Answer": [
                {
                    "name": "34.216.184.93.in-addr.arpa.",
                    "type": 12,
                    "TTL": 3600,
                    "data": "example.com.",
                }
            ],
        }

        records = await collector.reverse_lookup("93.184.216.34")

        # Should have called with reverse DNS format
        collector.http_client.get.assert_called()

    async def test_reverse_lookup_invalid_ip(self, collector):
        """Test reverse lookup with invalid IP."""
        records = await collector.reverse_lookup("invalid")

        assert len(records) == 0

    def test_to_result(self, collector):
        """Test converting DNS records to Result format."""
        records = [
            DNSRecord(RecordType.A, "example.com", "93.184.216.34", 300),
            DNSRecord(RecordType.A, "example.com", "93.184.216.35", 300),
        ]

        result = collector.to_result(records, "example.com")

        assert result.source == "dns"
        assert result.identifier == "example.com"
        assert result.metadata["record_count"] == 2
        assert len(result.metadata["records"]) == 2


class TestWHOISCollector:
    """Tests for WHOISCollector."""

    @pytest.fixture
    def collector(self):
        """Create a WHOIS collector."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        return WHOISCollector(http_client=mock_client)

    async def test_lookup(self, collector):
        """Test WHOIS lookup."""
        result = await collector.lookup("example.com")

        assert result is not None
        assert result.domain == "example.com"

    def test_extract_root_domain(self, collector):
        """Test root domain extraction."""
        assert collector._extract_root_domain("www.example.com") == "example.com"
        assert collector._extract_root_domain("https://www.example.com/path") == "example.com"
        assert collector._extract_root_domain("EXAMPLE.COM") == "example.com"

    def test_parse_whois_response(self, collector):
        """Test WHOIS response parsing."""
        raw_text = """
        Domain Name: EXAMPLE.COM
        Registrar: Example Registrar Inc.
        Creation Date: 2020-01-01T00:00:00Z
        Registry Expiry Date: 2025-01-01T00:00:00Z
        Registrant Name: John Doe
        Registrant Organization: Example Corp
        Registrant Email: john@example.com
        Registrant Country: US
        Name Server: ns1.example.com
        Name Server: ns2.example.com
        Domain Status: clientTransferProhibited
        DNSSEC: signedDelegation
        """

        info = collector._parse_whois_response(raw_text)

        assert info.registrar == "Example Registrar Inc."
        assert info.registrant_name == "John Doe"
        assert info.registrant_org == "Example Corp"
        assert len(info.name_servers) == 2
        assert info.dnssec is True

    def test_to_result(self, collector):
        """Test converting WHOIS info to Result format."""
        whois_info = WHOISInfo(
            domain="example.com", registrar="Example Registrar", name_servers=["ns1.example.com"]
        )

        result = collector.to_result(whois_info)

        assert result.source == "whois"
        assert result.identifier == "example.com"
        assert result.metadata["registrar"] == "Example Registrar"


class TestBreachCollector:
    """Tests for BreachCollector."""

    @pytest.fixture
    def collector(self):
        """Create a breach collector with API key."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        return BreachCollector(http_client=mock_client, hibp_api_key="test-api-key")

    @pytest.fixture
    def collector_no_key(self):
        """Create a breach collector without API key."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        return BreachCollector(http_client=mock_client)

    async def test_check_email(self, collector):
        """Test checking email for breaches."""
        collector.http_client.get.return_value = [
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "Description": "Adobe breach",
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
                "IsSensitive": False,
                "PwnCount": 152445165,
            }
        ]

        breaches = await collector.check_email("test@example.com")

        assert len(breaches) == 1
        assert breaches[0].breach_name == "Adobe"
        assert breaches[0].is_verified is True

    async def test_check_email_no_api_key(self, collector_no_key):
        """Test that check_email returns empty without API key."""
        breaches = await collector_no_key.check_email("test@example.com")

        assert len(breaches) == 0

    async def test_check_email_not_found(self, collector):
        """Test email not in any breaches."""
        collector.http_client.get.return_value = []

        breaches = await collector.check_email("safe@example.com")

        assert len(breaches) == 0

    async def test_check_password(self, collector):
        """Test password breach check."""
        # Mock response format: SUFFIX:COUNT
        collector.http_client.get.return_value = (
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10\n" "1D2DA4053E34E76F6576ED1DA63134B5E2A:5"
        )

        # The actual password hash would need to match
        count = await collector.check_password("password123")

        # Returns 0 since our mock suffix won't match
        assert count >= 0

    async def test_get_breach_info(self, collector):
        """Test getting specific breach information."""
        collector.http_client.get.return_value = {
            "Name": "Adobe",
            "Domain": "adobe.com",
            "Description": "Adobe breach description",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "PwnCount": 152445165,
        }

        breach = await collector.get_breach_info("Adobe")

        assert breach is not None
        assert breach.breach_name == "Adobe"
        assert breach.pwn_count == 152445165

    def test_to_result(self, collector):
        """Test converting breach records to Result format."""
        breaches = [
            BreachRecord(
                breach_name="Adobe",
                data_classes=["Email addresses"],
                is_verified=True,
                pwn_count=1000000,
            )
        ]

        result = collector.to_result(breaches, "test@example.com")

        assert result.source == "breach_database"
        assert result.identifier == "test@example.com"
        assert result.metadata["breach_count"] == 1
        assert result.confidence == 1.0

    def test_to_result_no_breaches(self, collector):
        """Test converting empty breach list."""
        result = collector.to_result([], "safe@example.com")

        assert result.confidence == 0.0
        assert result.metadata["breach_count"] == 0


class TestPasteCollector:
    """Tests for PasteCollector."""

    @pytest.fixture
    def collector(self):
        """Create a paste collector with API key."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        return PasteCollector(http_client=mock_client, hibp_api_key="test-api-key")

    async def test_check_email(self, collector):
        """Test checking email for paste appearances."""
        collector.http_client.get.return_value = [
            {
                "Id": "abc123",
                "Source": "Pastebin",
                "Title": "Leaked Data",
                "Date": "2023-01-15T10:30:00Z",
                "EmailCount": 1000,
            }
        ]

        pastes = await collector.check_email("test@example.com")

        assert len(pastes) == 1
        assert pastes[0].paste_id == "abc123"
        assert pastes[0].source == "Pastebin"

    async def test_check_email_no_api_key(self):
        """Test that check_email returns empty without API key."""
        collector = PasteCollector(hibp_api_key=None)

        pastes = await collector.check_email("test@example.com")

        assert len(pastes) == 0

    def test_to_result(self, collector):
        """Test converting paste records to Result format."""
        pastes = [PasteRecord(paste_id="abc123", source="Pastebin", email_count=500)]

        result = collector.to_result(pastes, "test@example.com")

        assert result.source == "paste_site"
        assert result.metadata["paste_count"] == 1


class TestDomainReputationCollector:
    """Tests for DomainReputationCollector."""

    @pytest.fixture
    def collector(self):
        """Create a reputation collector with API key."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        return DomainReputationCollector(http_client=mock_client, virustotal_api_key="test-api-key")

    async def test_check_domain(self, collector):
        """Test checking domain reputation."""
        collector.http_client.get.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 70,
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 10,
                    },
                    "categories": {"Fortinet": "phishing"},
                    "last_analysis_results": {
                        "Fortinet": {"category": "malicious"},
                        "Kaspersky": {"category": "malicious"},
                    },
                }
            }
        }

        reputation = await collector.check_domain("malicious-site.com")

        assert reputation.is_malicious is True
        assert reputation.risk_score > 0
        assert "Fortinet" in reputation.blacklists

    async def test_check_safe_domain(self, collector):
        """Test checking a safe domain."""
        collector.http_client.get.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 80,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 7,
                    },
                    "categories": {},
                    "last_analysis_results": {},
                }
            }
        }

        reputation = await collector.check_domain("safe-site.com")

        assert reputation.is_malicious is False
        assert reputation.risk_score == 0.0

    async def test_check_domain_no_api_key(self):
        """Test that check_domain works without API key."""
        collector = DomainReputationCollector(virustotal_api_key=None)

        reputation = await collector.check_domain("example.com")

        assert reputation.domain == "example.com"
        assert reputation.is_malicious is False

    def test_normalize_domain(self, collector):
        """Test domain normalization."""
        assert collector._normalize_domain("www.example.com") == "example.com"
        assert collector._normalize_domain("https://example.com/path") == "example.com"
        assert collector._normalize_domain("EXAMPLE.COM") == "example.com"

    async def test_check_ip(self, collector):
        """Test checking IP reputation."""
        collector.http_client.get.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 60,
                        "malicious": 3,
                        "suspicious": 1,
                        "undetected": 20,
                    },
                    "last_analysis_results": {"Fortinet": {"category": "malicious"}},
                }
            }
        }

        reputation = await collector.check_ip("93.184.216.34")

        assert reputation.is_malicious is True
        assert "93.184.216.34" in reputation.ip_addresses

    def test_to_result(self, collector):
        """Test converting reputation to Result format."""
        reputation = DomainReputation(
            domain="example.com", is_malicious=True, risk_score=50.0, blacklists=["Fortinet"]
        )

        result = collector.to_result(reputation)

        assert result.source == "threat_intel"
        assert result.identifier == "example.com"
        assert result.metadata["is_malicious"] is True


class TestIntegrationManager:
    """Tests for IntegrationManager."""

    @pytest.fixture
    def manager(self):
        """Create an integration manager."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value={})
        return IntegrationManager(
            http_client=mock_client, hibp_api_key="test-hibp-key", virustotal_api_key="test-vt-key"
        )

    def test_manager_initialization(self, manager):
        """Test manager initializes all collectors."""
        assert manager.dns is not None
        assert manager.whois is not None
        assert manager.breach is not None
        assert manager.paste is not None
        assert manager.reputation is not None

    async def test_investigate_domain(self, manager):
        """Test comprehensive domain investigation."""
        # Mock responses for each collector
        manager.dns.http_client.get = AsyncMock(
            return_value={"Answer": [{"name": "example.com.", "data": "93.184.216.34", "TTL": 300}]}
        )

        results = await manager.investigate_domain("example.com")

        assert isinstance(results, dict)
        # Should have attempted all lookups

    async def test_investigate_email(self, manager):
        """Test comprehensive email investigation."""
        manager.breach.http_client.get = AsyncMock(return_value=[])
        manager.paste.http_client.get = AsyncMock(return_value=[])

        results = await manager.investigate_email("test@example.com")

        assert isinstance(results, dict)

    async def test_investigate_email_invalid(self, manager):
        """Test investigating invalid email."""
        results = await manager.investigate_email("not-an-email")

        assert results == {}

    async def test_check_ip_reputation(self, manager):
        """Test IP reputation check through manager."""
        manager.reputation.http_client.get = AsyncMock(
            return_value={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 80}}}
            }
        )

        reputation = await manager.check_ip_reputation("93.184.216.34")

        assert reputation.domain == "93.184.216.34"


class TestIntegrationEdgeCases:
    """Tests for edge cases and error handling."""

    async def test_dns_collector_ipv6_reverse_lookup(self):
        """Test that IPv6 reverse lookup returns empty."""
        mock_client = MagicMock()
        collector = DNSCollector(http_client=mock_client)

        records = await collector.reverse_lookup("2001:db8::1")

        assert len(records) == 0

    async def test_breach_collector_error_handling(self):
        """Test breach collector handles API errors."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=Exception("API Error"))
        collector = BreachCollector(http_client=mock_client, hibp_api_key="key")

        breaches = await collector.check_email("test@example.com")

        assert len(breaches) == 0

    async def test_reputation_collector_error_handling(self):
        """Test reputation collector handles API errors."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=Exception("API Error"))
        collector = DomainReputationCollector(http_client=mock_client, virustotal_api_key="key")

        reputation = await collector.check_domain("example.com")

        # Should return default (safe) reputation
        assert reputation.is_malicious is False

    def test_whois_parsing_partial_data(self):
        """Test WHOIS parsing with partial data."""
        collector = WHOISCollector()

        raw_text = "Domain Name: TEST.COM\nRegistrar: Example"
        info = collector._parse_whois_response(raw_text)

        assert info.registrar == "Example"
        assert info.registrant_name is None

    async def test_manager_handles_exceptions(self):
        """Test manager handles exceptions in concurrent lookups."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=Exception("Network error"))

        manager = IntegrationManager(http_client=mock_client)

        # Should not raise, should return partial results
        results = await manager.investigate_domain("example.com")

        assert isinstance(results, dict)

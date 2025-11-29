"""Tests for security modules (OpSec, API security, compliance).

Tests cover:
- OpSec advisor with Tor/VPN detection
- API security validation and secret scanning
- Legal compliance checking and ethical guidelines
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import os
import tempfile
from pathlib import Path

from src.security.opsec import OpSecAdvisor, OPSEC_BEST_PRACTICES
from src.security.api_security import APISecurityValidator, API_SECURITY_BEST_PRACTICES
from src.security.compliance import (
    ComplianceChecker,
    ComplianceLevel,
    JurisdictionType,
    COMPLIANCE_GUIDELINES,
)


class TestOpSecAdvisor:
    """Test OpSec advisor functionality."""

    @pytest.fixture
    def opsec_advisor(self):
        """Create OpSec advisor instance."""
        return OpSecAdvisor()

    @pytest.mark.asyncio
    async def test_initialization(self, opsec_advisor):
        """Test OpSec advisor initialization."""
        assert opsec_advisor is not None
        assert opsec_advisor.timeout == 10.0
        assert hasattr(opsec_advisor, "TOR_CHECK_URLS")
        assert hasattr(opsec_advisor, "IP_CHECK_URLS")

    @pytest.mark.asyncio
    async def test_check_tor_connection_detected(self, opsec_advisor):
        """Test Tor connection detection when Tor is active."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"IsTor": True, "IP": "185.220.101.1"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result = await opsec_advisor.check_tor_connection()

            assert result["is_tor"] is True
            assert result["confidence"] == 1.0
            assert result["ip"] == "185.220.101.1"
            assert result["source"] == "torproject.org"
            assert "Tor Project API" in result["details"]

    @pytest.mark.asyncio
    async def test_check_tor_connection_not_detected(self, opsec_advisor):
        """Test Tor connection detection when Tor is not active."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"IsTor": False, "IP": "203.0.113.1"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result = await opsec_advisor.check_tor_connection()

            assert result["is_tor"] is False
            assert result["confidence"] >= 0.7
            assert result["ip"] == "203.0.113.1"

    @pytest.mark.asyncio
    async def test_check_tor_connection_api_failure(self, opsec_advisor):
        """Test Tor connection check when API fails."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("API unavailable")
            )

            result = await opsec_advisor.check_tor_connection()

            assert result["is_tor"] is False
            assert result["confidence"] <= 0.5
            assert "details" in result

    @pytest.mark.asyncio
    async def test_check_vpn_connection_detected(self, opsec_advisor):
        """Test VPN detection when VPN is active."""
        mock_ip_info = {
            "ip": "198.51.100.1",
            "org": "NordVPN",
            "isp": "NordVPN Services",
            "country": "NL",
        }

        opsec_advisor._get_public_ip_info = AsyncMock(return_value=mock_ip_info)

        result = await opsec_advisor.check_vpn_connection()

        assert result["is_vpn"] is True
        assert result["confidence"] >= 0.8
        assert result["provider"] == "NordVPN"
        assert result["ip"] == "198.51.100.1"

    @pytest.mark.asyncio
    async def test_check_vpn_connection_not_detected(self, opsec_advisor):
        """Test VPN detection when VPN is not active."""
        mock_ip_info = {
            "ip": "203.0.113.1",
            "org": "Comcast Cable",
            "isp": "Comcast",
            "country": "US",
        }

        opsec_advisor._get_public_ip_info = AsyncMock(return_value=mock_ip_info)

        result = await opsec_advisor.check_vpn_connection()

        assert result["is_vpn"] is False
        assert result["confidence"] >= 0.7
        assert result["provider"] is None

    @pytest.mark.asyncio
    async def test_check_vpn_connection_unknown_provider(self, opsec_advisor):
        """Test VPN detection with unknown provider."""
        mock_ip_info = {
            "ip": "198.51.100.1",
            "org": "Some VPN Hosting",
            "isp": "Datacenter VPN",
            "hostname": "vpn-server.example.com",
        }

        opsec_advisor._get_public_ip_info = AsyncMock(return_value=mock_ip_info)

        result = await opsec_advisor.check_vpn_connection()

        assert result["is_vpn"] is True
        assert result["provider"] == "Unknown"

    @pytest.mark.asyncio
    async def test_check_dns_leak(self, opsec_advisor):
        """Test DNS leak detection."""
        result = await opsec_advisor.check_dns_leak()

        assert "has_leak" in result
        assert "confidence" in result
        assert "details" in result
        assert "dns_servers" in result
        assert isinstance(result["dns_servers"], list)

    @pytest.mark.asyncio
    async def test_get_connection_fingerprint(self, opsec_advisor):
        """Test connection fingerprint gathering."""
        mock_ip_info = {
            "ip": "203.0.113.1",
            "hostname": "example.com",
            "org": "Example ISP",
            "country": "US",
            "city": "New York",
            "region": "NY",
            "timezone": "America/New_York",
        }

        opsec_advisor._get_public_ip_info = AsyncMock(return_value=mock_ip_info)

        result = await opsec_advisor.get_connection_fingerprint()

        assert result["ip"] == "203.0.113.1"
        assert result["hostname"] == "example.com"
        assert result["isp"] == "Example ISP"
        assert result["country"] == "US"
        assert result["city"] == "New York"
        assert "New York" in result["location"]

    def test_get_opsec_recommendations_no_status(self, opsec_advisor):
        """Test OpSec recommendations without connection status."""
        recommendations = opsec_advisor.get_opsec_recommendations()

        assert len(recommendations) > 0
        assert any("infrastructure" in r.lower() for r in recommendations)
        assert any("fingerprint" in r.lower() for r in recommendations)

    def test_get_opsec_recommendations_with_tor(self, opsec_advisor):
        """Test OpSec recommendations with Tor status."""
        tor_status = {"is_tor": True}
        recommendations = opsec_advisor.get_opsec_recommendations(tor_status=tor_status)

        assert any("tor" in r.lower() for r in recommendations)
        assert any("detected" in r.lower() for r in recommendations)

    def test_get_opsec_recommendations_with_vpn(self, opsec_advisor):
        """Test OpSec recommendations with VPN status."""
        vpn_status = {"is_vpn": True, "provider": "NordVPN"}
        recommendations = opsec_advisor.get_opsec_recommendations(vpn_status=vpn_status)

        assert any("vpn" in r.lower() for r in recommendations)
        assert any("nordvpn" in r.lower() for r in recommendations)

    def test_analyze_for_tor_indicators(self, opsec_advisor):
        """Test Tor indicator analysis."""
        # Positive case
        ip_info = {"hostname": "tor-exit-node.example.com", "org": "Tor Project"}
        assert opsec_advisor._analyze_for_tor_indicators(ip_info) is True

        # Negative case
        ip_info = {"hostname": "regular-host.example.com", "org": "Comcast"}
        assert opsec_advisor._analyze_for_tor_indicators(ip_info) is False

    def test_analyze_for_vpn_indicators(self, opsec_advisor):
        """Test VPN indicator analysis."""
        # Known provider
        ip_info = {"org": "NordVPN", "hostname": "nordvpn.com"}
        result = opsec_advisor._analyze_for_vpn_indicators(ip_info)
        assert result["is_vpn"] is True
        assert result["provider"] == "NordVPN"

        # Generic VPN indicators
        ip_info = {"org": "VPN Hosting", "isp": "Datacenter"}
        result = opsec_advisor._analyze_for_vpn_indicators(ip_info)
        assert result["is_vpn"] is True

        # No VPN indicators
        ip_info = {"org": "Comcast", "isp": "Residential ISP"}
        result = opsec_advisor._analyze_for_vpn_indicators(ip_info)
        assert result["is_vpn"] is False

    def test_opsec_best_practices_constant(self):
        """Test OpSec best practices constant exists and has content."""
        assert OPSEC_BEST_PRACTICES is not None
        assert len(OPSEC_BEST_PRACTICES) > 100
        assert "Network Security" in OPSEC_BEST_PRACTICES
        assert "Browser Security" in OPSEC_BEST_PRACTICES
        assert "Legal Compliance" in OPSEC_BEST_PRACTICES


class TestAPISecurityValidator:
    """Test API security validator functionality."""

    @pytest.fixture
    def api_validator(self):
        """Create API security validator instance."""
        return APISecurityValidator()

    def test_initialization(self, api_validator):
        """Test API security validator initialization."""
        assert api_validator is not None
        assert hasattr(api_validator, "API_KEY_PATTERNS")
        assert hasattr(api_validator, "DANGEROUS_FILES")

    def test_validate_environment_variables(self, api_validator):
        """Test environment variable validation."""
        # Set test environment variable
        os.environ["GOOGLE_API_KEY"] = "test_key_123"

        result = api_validator.validate_environment_variables()

        assert "is_valid" in result
        assert "issues" in result
        assert "recommendations" in result
        assert "keys_in_env" in result
        assert "GOOGLE_API_KEY" in result["keys_in_env"]

        # Cleanup
        del os.environ["GOOGLE_API_KEY"]

    def test_validate_environment_variables_no_keys(self, api_validator):
        """Test environment validation when no keys present."""
        # Ensure no test keys in environment
        test_keys = ["GOOGLE_API_KEY", "TWITTER_API_KEY"]
        for key in test_keys:
            os.environ.pop(key, None)

        result = api_validator.validate_environment_variables()

        assert isinstance(result["keys_in_env"], list)
        assert len(result["recommendations"]) > 0

    def test_scan_for_hardcoded_secrets(self, api_validator):
        """Test scanning for hardcoded secrets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file with hardcoded secret
            sample_file = Path(tmpdir) / "sample.py"
            sample_file.write_text('api_key = "sk_test_abc123"\npassword = "secret123"')

            result = api_validator.scan_for_hardcoded_secrets(tmpdir)

            assert result["files_scanned"] >= 1
            assert result["secrets_found"] >= 1
            assert len(result["vulnerable_files"]) >= 1
            assert result["severity"] in ["low", "medium", "high", "critical"]

    def test_scan_for_hardcoded_secrets_clean(self, api_validator):
        """Test scanning directory with no secrets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create clean test file
            test_file = Path(tmpdir) / "clean.py"
            test_file.write_text("def hello():\n    return 'Hello World'")

            result = api_validator.scan_for_hardcoded_secrets(tmpdir)

            assert result["secrets_found"] == 0
            assert result["severity"] == "low"

    def test_validate_api_key_format_strong(self, api_validator):
        """Test API key format validation for strong key."""
        strong_key = "Sk_TeSt_1234567890AbCdEfGhIjKlMnOpQrStUvWxYz!@#$"

        result = api_validator.validate_api_key_format(strong_key)

        assert result["strength"] == "strong"
        assert result["is_valid"] is True
        assert result["length"] > 32
        assert result["diversity_score"] >= 3

    def test_validate_api_key_format_weak(self, api_validator):
        """Test API key format validation for weak key."""
        weak_key = "test123"

        result = api_validator.validate_api_key_format(weak_key)

        assert result["strength"] == "weak"
        assert result["is_valid"] is False
        assert len(result["issues"]) > 0

    def test_validate_api_key_format_placeholder(self, api_validator):
        """Test detection of placeholder/test keys."""
        placeholder_key = "test"

        result = api_validator.validate_api_key_format(placeholder_key)

        assert result["is_valid"] is False
        assert any("placeholder" in issue.lower() for issue in result["issues"])

    def test_get_key_rotation_recommendations_new(self, api_validator):
        """Test rotation recommendations for new key."""
        recommendations = api_validator.get_key_rotation_recommendations(0)

        assert len(recommendations) > 0
        assert any("track" in r.lower() for r in recommendations)

    def test_get_key_rotation_recommendations_old(self, api_validator):
        """Test rotation recommendations for old key."""
        recommendations = api_validator.get_key_rotation_recommendations(400)

        assert len(recommendations) > 0
        assert any("year" in r.lower() or "rotate" in r.lower() for r in recommendations)

    def test_get_key_rotation_recommendations_very_old(self, api_validator):
        """Test rotation recommendations for very old key."""
        recommendations = api_validator.get_key_rotation_recommendations(800)

        assert len(recommendations) > 0
        assert any("2 years" in r.lower() or "old" in r.lower() for r in recommendations)

    def test_check_secure_storage(self, api_validator):
        """Test secure storage checking."""
        result = api_validator.check_secure_storage()

        assert "is_secure" in result
        assert "storage_method" in result
        assert "issues" in result
        assert "recommendations" in result

    def test_check_secure_storage_with_env_vars(self, api_validator):
        """Test secure storage check with environment variables."""
        os.environ["TEST_API_KEY"] = "test_value"

        result = api_validator.check_secure_storage()

        assert "environment_variables" in result["storage_method"]

        # Cleanup
        del os.environ["TEST_API_KEY"]

    def test_api_security_best_practices_constant(self):
        """Test API security best practices constant."""
        assert API_SECURITY_BEST_PRACTICES is not None
        assert len(API_SECURITY_BEST_PRACTICES) > 100
        assert "Key Storage" in API_SECURITY_BEST_PRACTICES
        assert "Key Rotation" in API_SECURITY_BEST_PRACTICES


class TestComplianceChecker:
    """Test compliance checker functionality."""

    @pytest.fixture
    def compliance_checker(self):
        """Create compliance checker instance."""
        return ComplianceChecker()

    def test_initialization(self, compliance_checker):
        """Test compliance checker initialization."""
        assert compliance_checker is not None
        assert compliance_checker.jurisdiction == JurisdictionType.INTERNATIONAL.value

    def test_initialization_with_jurisdiction(self):
        """Test compliance checker with specific jurisdiction."""
        checker = ComplianceChecker(config={"jurisdiction": JurisdictionType.US.value})
        assert checker.jurisdiction == JurisdictionType.US.value

    def test_check_data_collection_compliance_personal_data(self, compliance_checker):
        """Test data collection compliance for personal data."""
        result = compliance_checker.check_data_collection_compliance(
            data_type="personal", source="social_media", purpose="investigation"
        )

        assert "is_compliant" in result
        assert "risk_level" in result
        assert len(result["warnings"]) > 0
        assert len(result["requirements"]) > 0
        assert result["risk_level"] in ["low", "medium", "high", "critical"]

    def test_check_data_collection_compliance_darkweb(self, compliance_checker):
        """Test data collection compliance for dark web sources."""
        result = compliance_checker.check_data_collection_compliance(
            data_type="public", source="darkweb", purpose="investigation"
        )

        assert result["risk_level"] in ["high", "critical"]
        assert any("dark web" in w.lower() for w in result["warnings"])
        assert any("legal authorization" in r.lower() for r in result["requirements"])

    def test_check_data_collection_compliance_commercial(self, compliance_checker):
        """Test data collection compliance for commercial purposes."""
        result = compliance_checker.check_data_collection_compliance(
            data_type="public", source="social_media", purpose="commercial"
        )

        assert any("commercial" in w.lower() for w in result["warnings"])
        assert any("consent" in r.lower() for r in result["requirements"])

    def test_check_data_retention_compliance_recent(self, compliance_checker):
        """Test data retention compliance for recent data."""
        result = compliance_checker.check_data_retention_compliance(30)

        assert result["data_age_days"] == 30
        assert len(result["warnings"]) == 0 or result["warnings"][0].find("within") >= 0

    def test_check_data_retention_compliance_old(self, compliance_checker):
        """Test data retention compliance for old data."""
        result = compliance_checker.check_data_retention_compliance(400)

        assert result["data_age_days"] == 400
        assert len(result["warnings"]) > 0

    def test_check_data_retention_compliance_very_old(self, compliance_checker):
        """Test data retention compliance for very old data."""
        result = compliance_checker.check_data_retention_compliance(800)

        assert result["data_age_days"] == 800
        assert any("2 years" in w.lower() for w in result["warnings"])

    def test_get_jurisdiction_requirements_eu(self, compliance_checker):
        """Test jurisdiction requirements for EU."""
        result = compliance_checker.get_jurisdiction_requirements(JurisdictionType.EU.value)

        assert result["jurisdiction"] == JurisdictionType.EU.value
        assert "GDPR" in result["regulations"]
        assert len(result["requirements"]) > 0
        assert len(result["restrictions"]) > 0
        assert len(result["resources"]) > 0

    def test_get_jurisdiction_requirements_us(self, compliance_checker):
        """Test jurisdiction requirements for US."""
        result = compliance_checker.get_jurisdiction_requirements(JurisdictionType.US.value)

        assert result["jurisdiction"] == JurisdictionType.US.value
        assert "CFAA" in result["regulations"]
        assert len(result["requirements"]) > 0

    def test_get_jurisdiction_requirements_uk(self, compliance_checker):
        """Test jurisdiction requirements for UK."""
        result = compliance_checker.get_jurisdiction_requirements(JurisdictionType.UK.value)

        assert result["jurisdiction"] == JurisdictionType.UK.value
        assert "UK GDPR" in result["regulations"]

    def test_check_terms_of_service_compliance_twitter(self, compliance_checker):
        """Test ToS compliance checking for Twitter."""
        result = compliance_checker.check_terms_of_service_compliance("twitter")

        assert result["platform"] == "twitter"
        assert len(result["warnings"]) > 0
        assert len(result["restrictions"]) > 0
        assert len(result["recommendations"]) > 0

    def test_check_terms_of_service_compliance_linkedin(self, compliance_checker):
        """Test ToS compliance checking for LinkedIn."""
        result = compliance_checker.check_terms_of_service_compliance("linkedin")

        assert result["platform"] == "linkedin"
        assert any("linkedin" in w.lower() for w in result["warnings"])

    def test_check_terms_of_service_compliance_unknown(self, compliance_checker):
        """Test ToS compliance for unknown platform."""
        result = compliance_checker.check_terms_of_service_compliance("unknown_platform")

        assert result["platform"] == "unknown_platform"
        assert len(result["recommendations"]) > 0

    def test_get_ethical_guidelines(self, compliance_checker):
        """Test getting ethical guidelines."""
        guidelines = compliance_checker.get_ethical_guidelines()

        assert len(guidelines) > 0
        assert any("purpose" in g.lower() for g in guidelines)
        assert any("privacy" in g.lower() for g in guidelines)
        assert any("consent" in g.lower() for g in guidelines)

    def test_is_gdpr_jurisdiction(self, compliance_checker):
        """Test GDPR jurisdiction detection."""
        # EU jurisdiction
        eu_checker = ComplianceChecker(config={"jurisdiction": JurisdictionType.EU.value})
        assert eu_checker._is_gdpr_jurisdiction() is True

        # Non-EU jurisdiction
        us_checker = ComplianceChecker(config={"jurisdiction": JurisdictionType.US.value})
        assert us_checker._is_gdpr_jurisdiction() is False

    def test_calculate_risk_level(self, compliance_checker):
        """Test risk level calculation."""
        # Low risk
        risk = compliance_checker._calculate_risk_level("public", "public_records", 0)
        assert risk == ComplianceLevel.LOW.value

        # High risk
        risk = compliance_checker._calculate_risk_level("personal", "darkweb", 3)
        assert risk in [ComplianceLevel.HIGH.value, ComplianceLevel.CRITICAL.value]

    def test_compliance_guidelines_constant(self):
        """Test compliance guidelines constant."""
        assert COMPLIANCE_GUIDELINES is not None
        assert len(COMPLIANCE_GUIDELINES) > 100
        assert "Legal Framework" in COMPLIANCE_GUIDELINES
        assert "Data Protection" in COMPLIANCE_GUIDELINES
        assert "Ethical Principles" in COMPLIANCE_GUIDELINES

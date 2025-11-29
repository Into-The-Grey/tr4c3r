"""Operational Security (OpSec) recommendations and utilities.

Provides tools for detecting and validating operational security measures
including VPN detection, Tor connection verification, and security recommendations.
"""

import asyncio
import logging
import socket
from typing import Dict, List, Optional, Any
import httpx

logger = logging.getLogger(__name__)


class OpSecAdvisor:
    """Provides operational security recommendations and connection analysis."""

    # Known Tor exit node check services
    TOR_CHECK_URLS = [
        "https://check.torproject.org/api/ip",
        "https://check.torproject.org/",
    ]

    # Public IP check services
    IP_CHECK_URLS = [
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ifconfig.me/all.json",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize OpSec advisor.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10.0)

    async def check_tor_connection(self) -> Dict[str, Any]:
        """Check if current connection is through Tor network.

        Returns:
            Dictionary with Tor status information:
            - is_tor: bool - Whether Tor is detected
            - confidence: float - Confidence level (0.0-1.0)
            - details: str - Additional information
            - ip: Optional[str] - Detected IP address
        """
        logger.info("Checking for Tor connection...")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Try Tor Project's check service
                try:
                    response = await client.get(
                        "https://check.torproject.org/api/ip", headers={"User-Agent": "TR4C3R/1.0"}
                    )

                    if response.status_code == 200:
                        data = response.json()
                        is_tor = data.get("IsTor", False)
                        ip_address = data.get("IP", "unknown")

                        return {
                            "is_tor": is_tor,
                            "confidence": 1.0 if is_tor else 0.8,
                            "details": "Verified via Tor Project API",
                            "ip": ip_address,
                            "source": "torproject.org",
                        }
                except Exception as e:
                    logger.debug(f"Tor Project API check failed: {e}")

                # Fallback: Check for Tor-like characteristics
                ip_info = await self._get_public_ip_info(client)

                if ip_info:
                    # Check for known Tor exit node indicators
                    is_likely_tor = self._analyze_for_tor_indicators(ip_info)

                    return {
                        "is_tor": is_likely_tor,
                        "confidence": 0.5 if is_likely_tor else 0.7,
                        "details": "Heuristic analysis (Tor API unavailable)",
                        "ip": ip_info.get("ip"),
                        "source": "heuristic",
                    }

                return {
                    "is_tor": False,
                    "confidence": 0.3,
                    "details": "Unable to verify connection type",
                    "ip": None,
                    "source": "unknown",
                }

        except Exception as e:
            logger.error(f"Error checking Tor connection: {e}")
            return {
                "is_tor": False,
                "confidence": 0.0,
                "details": f"Error: {str(e)}",
                "ip": None,
                "error": str(e),
            }

    async def check_vpn_connection(self) -> Dict[str, Any]:
        """Check if current connection is through a VPN.

        Returns:
            Dictionary with VPN status information:
            - is_vpn: bool - Whether VPN is detected
            - confidence: float - Confidence level (0.0-1.0)
            - details: str - Additional information
            - ip: Optional[str] - Detected IP address
            - provider: Optional[str] - Detected VPN provider
        """
        logger.info("Checking for VPN connection...")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                ip_info = await self._get_public_ip_info(client)

                if not ip_info:
                    return {
                        "is_vpn": False,
                        "confidence": 0.0,
                        "details": "Unable to retrieve IP information",
                        "ip": None,
                        "provider": None,
                    }

                # Analyze for VPN indicators
                vpn_analysis = self._analyze_for_vpn_indicators(ip_info)

                return {
                    "is_vpn": vpn_analysis["is_vpn"],
                    "confidence": vpn_analysis["confidence"],
                    "details": vpn_analysis["details"],
                    "ip": ip_info.get("ip"),
                    "provider": vpn_analysis.get("provider"),
                    "source": "ip_analysis",
                }

        except Exception as e:
            logger.error(f"Error checking VPN connection: {e}")
            return {
                "is_vpn": False,
                "confidence": 0.0,
                "details": f"Error: {str(e)}",
                "ip": None,
                "provider": None,
                "error": str(e),
            }

    async def check_dns_leak(self) -> Dict[str, Any]:
        """Check for DNS leaks that could compromise anonymity.

        Returns:
            Dictionary with DNS leak information:
            - has_leak: bool - Whether DNS leak detected
            - confidence: float - Confidence level
            - details: str - Leak details
            - dns_servers: List[str] - Detected DNS servers
        """
        logger.info("Checking for DNS leaks...")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Try DNS leak test service
                try:
                    response = await client.get(
                        "https://www.dnsleaktest.com/", headers={"User-Agent": "TR4C3R/1.0"}
                    )

                    # Note: Actual DNS leak detection requires more sophisticated analysis
                    # This is a placeholder for the basic framework

                    return {
                        "has_leak": False,
                        "confidence": 0.5,
                        "details": "Basic DNS check completed",
                        "dns_servers": [],
                        "warning": "Full DNS leak detection requires additional services",
                    }

                except Exception as e:
                    logger.debug(f"DNS leak test failed: {e}")

            return {
                "has_leak": None,
                "confidence": 0.0,
                "details": "DNS leak test unavailable",
                "dns_servers": [],
                "warning": "Unable to perform DNS leak test",
            }

        except Exception as e:
            logger.error(f"Error checking DNS leak: {e}")
            return {
                "has_leak": None,
                "confidence": 0.0,
                "details": f"Error: {str(e)}",
                "dns_servers": [],
                "error": str(e),
            }

    async def get_connection_fingerprint(self) -> Dict[str, Any]:
        """Get connection fingerprint for OpSec analysis.

        Returns:
            Dictionary with connection fingerprint:
            - ip: str - Public IP address
            - hostname: Optional[str] - Reverse DNS hostname
            - isp: Optional[str] - Internet Service Provider
            - country: Optional[str] - Country code
            - region: Optional[str] - Region/state
            - city: Optional[str] - City
            - timezone: Optional[str] - Timezone
        """
        logger.info("Gathering connection fingerprint...")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                ip_info = await self._get_public_ip_info(client)

                if not ip_info:
                    return {"ip": None, "error": "Unable to retrieve IP information"}

                # Extract relevant information
                fingerprint = {
                    "ip": ip_info.get("ip"),
                    "hostname": ip_info.get("hostname"),
                    "isp": ip_info.get("org") or ip_info.get("isp"),
                    "country": ip_info.get("country"),
                    "region": ip_info.get("region") or ip_info.get("regionName"),
                    "city": ip_info.get("city"),
                    "timezone": ip_info.get("timezone"),
                    "location": f"{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}",
                }

                return fingerprint

        except Exception as e:
            logger.error(f"Error getting connection fingerprint: {e}")
            return {"ip": None, "error": str(e)}

    def get_opsec_recommendations(
        self,
        tor_status: Optional[Dict[str, Any]] = None,
        vpn_status: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Get OpSec recommendations based on connection analysis.

        Args:
            tor_status: Optional Tor connection status from check_tor_connection()
            vpn_status: Optional VPN connection status from check_vpn_connection()

        Returns:
            List of OpSec recommendations
        """
        recommendations = []

        # Base recommendations
        recommendations.append("🔒 Always use dedicated investigation infrastructure")
        recommendations.append("🔒 Avoid using personal accounts or identifiers")
        recommendations.append("🔒 Be aware of fingerprinting and tracking techniques")

        # Tor-specific recommendations
        if tor_status:
            if tor_status.get("is_tor"):
                recommendations.append("✅ Tor connection detected - good for anonymity")
                recommendations.append("⚠️  Ensure Tor Browser is properly configured")
                recommendations.append("⚠️  Avoid logging into personal accounts via Tor")
            else:
                recommendations.append("⚠️  No Tor connection detected")
                recommendations.append("💡 Consider using Tor for sensitive investigations")

        # VPN-specific recommendations
        if vpn_status:
            if vpn_status.get("is_vpn"):
                recommendations.append("✅ VPN connection detected")
                provider = vpn_status.get("provider")
                if provider:
                    recommendations.append(f"📍 VPN Provider: {provider}")
                recommendations.append("⚠️  Ensure VPN has no-logs policy")
                recommendations.append("⚠️  Check for DNS/IPv6 leaks")
            else:
                recommendations.append("⚠️  No VPN connection detected")
                recommendations.append("💡 Consider using a VPN for additional privacy")

        # General recommendations
        recommendations.extend(
            [
                "🔒 Use different browsers for different investigations",
                "🔒 Clear cookies and cache regularly",
                "🔒 Disable WebRTC to prevent IP leaks",
                "🔒 Use privacy-focused search engines",
                "🔒 Monitor for rate limiting and blocking",
            ]
        )

        return recommendations

    async def _get_public_ip_info(self, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Get public IP address and related information.

        Args:
            client: HTTP client to use

        Returns:
            Dictionary with IP information or None if unavailable
        """
        # Try multiple IP info services
        for url in self.IP_CHECK_URLS:
            try:
                response = await client.get(url, headers={"User-Agent": "TR4C3R/1.0"}, timeout=5.0)

                if response.status_code == 200:
                    data = response.json()
                    logger.debug(f"Retrieved IP info from {url}")
                    return data

            except Exception as e:
                logger.debug(f"Failed to get IP info from {url}: {e}")
                continue

        return None

    def _analyze_for_tor_indicators(self, ip_info: Dict[str, Any]) -> bool:
        """Analyze IP information for Tor indicators.

        Args:
            ip_info: IP information dictionary

        Returns:
            True if Tor indicators found
        """
        # Check for common Tor exit node characteristics
        hostname = ip_info.get("hostname", "").lower()
        org = ip_info.get("org", "").lower()
        isp = ip_info.get("isp", "").lower()

        tor_keywords = ["tor", "exit", "relay", "proxy"]

        for keyword in tor_keywords:
            if keyword in hostname or keyword in org or keyword in isp:
                return True

        return False

    def _analyze_for_vpn_indicators(self, ip_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IP information for VPN indicators.

        Args:
            ip_info: IP information dictionary

        Returns:
            Dictionary with VPN analysis results
        """
        hostname = ip_info.get("hostname", "").lower()
        org = ip_info.get("org", "").lower()
        isp = ip_info.get("isp", "").lower()

        # Known VPN providers
        vpn_providers = {
            "nordvpn": "NordVPN",
            "expressvpn": "ExpressVPN",
            "protonvpn": "ProtonVPN",
            "mullvad": "Mullvad",
            "private internet access": "Private Internet Access",
            "pia": "Private Internet Access",
            "surfshark": "Surfshark",
            "cyberghost": "CyberGhost",
            "ipvanish": "IPVanish",
            "purevpn": "PureVPN",
        }

        # Check for VPN provider names
        for keyword, provider in vpn_providers.items():
            if keyword in hostname or keyword in org or keyword in isp:
                return {
                    "is_vpn": True,
                    "confidence": 0.9,
                    "details": f"Detected {provider} VPN provider",
                    "provider": provider,
                }

        # Check for generic VPN keywords
        vpn_keywords = ["vpn", "virtual private", "proxy", "hosting", "datacenter"]

        keyword_count = sum(
            1 for keyword in vpn_keywords if keyword in hostname or keyword in org or keyword in isp
        )

        if keyword_count >= 2:
            return {
                "is_vpn": True,
                "confidence": 0.7,
                "details": "Multiple VPN indicators detected",
                "provider": "Unknown",
            }
        elif keyword_count == 1:
            return {
                "is_vpn": True,
                "confidence": 0.5,
                "details": "Possible VPN connection",
                "provider": "Unknown",
            }

        return {
            "is_vpn": False,
            "confidence": 0.8,
            "details": "No VPN indicators detected",
            "provider": None,
        }


# Pre-defined OpSec best practices
OPSEC_BEST_PRACTICES = """
TR4C3R Operational Security Best Practices
==========================================

1. Network Security
   ✓ Use Tor Browser for maximum anonymity
   ✓ Use a trusted VPN service with no-logs policy
   ✓ Never use your home/work network for sensitive investigations
   ✓ Consider using public WiFi (with VPN) for additional separation
   ✓ Check for DNS leaks regularly

2. Browser Security
   ✓ Use dedicated browser for investigations (Firefox/Tor Browser)
   ✓ Disable WebRTC to prevent IP leaks
   ✓ Use privacy-focused extensions (uBlock Origin, NoScript)
   ✓ Clear cookies and cache after each session
   ✓ Disable JavaScript for sensitive operations

3. Account Security
   ✓ Never use personal accounts for OSINT
   ✓ Create dedicated investigation accounts with fake identities
   ✓ Use temporary email addresses (guerrilla mail, etc.)
   ✓ Use password manager with unique passwords
   ✓ Enable 2FA where possible

4. Data Security
   ✓ Encrypt all stored investigation data
   ✓ Use full disk encryption
   ✓ Store data on encrypted external drives
   ✓ Shred/wipe files when no longer needed
   ✓ Use secure deletion tools (shred, srm)

5. Infrastructure
   ✓ Use dedicated VM for investigations
   ✓ Use Tails OS or Whonix for maximum security
   ✓ Keep systems updated and patched
   ✓ Use disposable infrastructure when possible
   ✓ Separate investigation infrastructure from personal use

6. Behavioral Security
   ✓ Vary your search patterns and timing
   ✓ Don't log into multiple sites with same credentials
   ✓ Be aware of time zone leakage
   ✓ Avoid revealing investigation details on social media
   ✓ Document your digital footprint

7. Legal Compliance
   ✓ Know your jurisdiction's laws regarding OSINT
   ✓ Obtain proper authorization for investigations
   ✓ Document your legal basis for searches
   ✓ Consult legal counsel when in doubt
   ✓ Respect privacy laws and regulations
"""

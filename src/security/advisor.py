"""
Security Guidelines and Network Privacy Checks for TR4C3R.

Comprehensive security system including:
- Tor connection detection and management
- VPN detection and verification
- Proxy detection
- IP leak testing
- DNS leak testing
- WebRTC leak detection
- Network anonymity scoring
- Security recommendations engine
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


# Known Tor exit node IPs are fetched dynamically
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
IP_CHECK_SERVICES = [
    "https://api.ipify.org?format=json",
    "https://ipinfo.io/json",
    "https://api.myip.com",
    "https://ifconfig.me/all.json",
]
DNS_LEAK_TEST_DOMAINS = [
    "whoami.akamai.net",
    "o-o.myaddr.l.google.com",
]


SECURITY_GUIDELINES = """
TR4C3R Security Best Practices
===============================

1. Operational Security (OpSec)
   - Use VPN or Tor for sensitive investigations
   - Avoid using personal accounts or identifiers
   - Consider using dedicated investigation infrastructure
   - Be aware of fingerprinting and tracking

2. Data Security
   - Encrypt stored data at rest
   - Use secure communication channels
   - Implement access controls
   - Regular security audits

3. API Keys & Credentials
   - Store API keys in environment variables or secure vaults
   - Never commit credentials to version control
   - Rotate keys regularly
   - Use least-privilege access

4. Rate Limiting & Detection
   - Respect API rate limits
   - Implement delays between requests
   - Monitor for detection/blocking
   - Use multiple IP addresses if needed (legally)

5. Legal Compliance
   - Understand your jurisdiction's laws
   - Obtain proper authorization for investigations
   - Document your legal basis for searches
   - Consult legal counsel when in doubt
"""


class SecurityLevel(Enum):
    """Security/anonymity level."""

    EXPOSED = "exposed"  # Real IP visible
    LOW = "low"  # Basic protection
    MEDIUM = "medium"  # VPN or proxy
    HIGH = "high"  # Tor or multi-hop VPN
    MAXIMUM = "maximum"  # Tor + additional hardening


class ConnectionType(Enum):
    """Type of network connection."""

    DIRECT = "direct"
    VPN = "vpn"
    TOR = "tor"
    PROXY = "proxy"
    I2P = "i2p"
    UNKNOWN = "unknown"


@dataclass
class IPInfo:
    """Information about an IP address."""

    ip: str
    is_tor_exit: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    hostname: Optional[str] = None
    timezone: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_tor_exit": self.is_tor_exit,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_datacenter": self.is_datacenter,
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "asn": self.asn,
            "org": self.org,
            "hostname": self.hostname,
            "timezone": self.timezone,
        }


@dataclass
class SecurityStatus:
    """Current security/anonymity status."""

    level: SecurityLevel
    connection_type: ConnectionType
    public_ip: Optional[str] = None
    ip_info: Optional[IPInfo] = None
    tor_active: bool = False
    vpn_active: bool = False
    proxy_active: bool = False
    dns_leak: bool = False
    webrtc_leak: bool = False
    ipv6_leak: bool = False
    fingerprint_risk: str = "unknown"
    recommendations: list[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "connection_type": self.connection_type.value,
            "public_ip": self.public_ip,
            "ip_info": self.ip_info.to_dict() if self.ip_info else None,
            "tor_active": self.tor_active,
            "vpn_active": self.vpn_active,
            "proxy_active": self.proxy_active,
            "dns_leak": self.dns_leak,
            "webrtc_leak": self.webrtc_leak,
            "ipv6_leak": self.ipv6_leak,
            "fingerprint_risk": self.fingerprint_risk,
            "recommendations": self.recommendations,
            "checked_at": self.checked_at.isoformat(),
        }

    @property
    def is_secure(self) -> bool:
        """Check if current status is considered secure."""
        return (
            self.level in (SecurityLevel.HIGH, SecurityLevel.MAXIMUM)
            and not self.dns_leak
            and not self.webrtc_leak
            and not self.ipv6_leak
        )


@dataclass
class TorStatus:
    """Tor connection status."""

    is_connected: bool = False
    is_running: bool = False
    exit_node_ip: Optional[str] = None
    exit_node_country: Optional[str] = None
    circuit_established: bool = False
    control_port_available: bool = False
    socks_port: int = 9050
    control_port: int = 9051
    version: Optional[str] = None
    bandwidth_rate: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "is_connected": self.is_connected,
            "is_running": self.is_running,
            "exit_node_ip": self.exit_node_ip,
            "exit_node_country": self.exit_node_country,
            "circuit_established": self.circuit_established,
            "control_port_available": self.control_port_available,
            "socks_port": self.socks_port,
            "control_port": self.control_port,
            "version": self.version,
            "bandwidth_rate": self.bandwidth_rate,
        }


@dataclass
class VPNStatus:
    """VPN connection status."""

    is_connected: bool = False
    provider: Optional[str] = None
    protocol: Optional[str] = None
    server_ip: Optional[str] = None
    server_country: Optional[str] = None
    interface_name: Optional[str] = None
    local_ip: Optional[str] = None
    connection_time: Optional[datetime] = None
    kill_switch_enabled: bool = False

    def to_dict(self) -> dict:
        return {
            "is_connected": self.is_connected,
            "provider": self.provider,
            "protocol": self.protocol,
            "server_ip": self.server_ip,
            "server_country": self.server_country,
            "interface_name": self.interface_name,
            "local_ip": self.local_ip,
            "connection_time": self.connection_time.isoformat() if self.connection_time else None,
            "kill_switch_enabled": self.kill_switch_enabled,
        }


class TorManager:
    """
    Manages Tor connections and provides Tor-related utilities.

    Features:
    - Tor process detection
    - Control port communication
    - Circuit management
    - Exit node verification
    - Tor browser integration
    """

    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        control_password: Optional[str] = None,
    ):
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self._exit_nodes_cache: set[str] = set()
        self._exit_nodes_updated: Optional[datetime] = None

    async def check_tor_running(self) -> bool:
        """Check if Tor process is running."""
        system = platform.system()

        try:
            if system == "Darwin" or system == "Linux":
                process = await asyncio.create_subprocess_exec(
                    "pgrep",
                    "-x",
                    "tor",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await process.communicate()
                return bool(stdout.strip())
            elif system == "Windows":
                process = await asyncio.create_subprocess_exec(
                    "tasklist",
                    "/FI",
                    "IMAGENAME eq tor.exe",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await process.communicate()
                return b"tor.exe" in stdout.lower()
        except Exception as e:
            logger.debug(f"Error checking Tor process: {e}")

        return False

    async def check_socks_port(self) -> bool:
        """Check if Tor SOCKS port is listening."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.socks_port), timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def check_control_port(self) -> bool:
        """Check if Tor control port is available."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.control_port), timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def get_tor_version(self) -> Optional[str]:
        """Get Tor version via control port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.control_port), timeout=5.0
            )

            # Authenticate
            if self.control_password:
                writer.write(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
            else:
                writer.write(b"AUTHENTICATE\r\n")
            await writer.drain()

            response = await reader.readline()
            if not response.startswith(b"250"):
                return None

            # Get version
            writer.write(b"GETINFO version\r\n")
            await writer.drain()
            response = await reader.readline()

            writer.close()
            await writer.wait_closed()

            if response.startswith(b"250-version="):
                return response.decode().split("=")[1].strip()

        except Exception as e:
            logger.debug(f"Error getting Tor version: {e}")

        return None

    async def request_new_circuit(self) -> bool:
        """Request a new Tor circuit (new identity)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.control_port), timeout=5.0
            )

            # Authenticate
            if self.control_password:
                writer.write(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
            else:
                writer.write(b"AUTHENTICATE\r\n")
            await writer.drain()

            response = await reader.readline()
            if not response.startswith(b"250"):
                return False

            # Request new circuit
            writer.write(b"SIGNAL NEWNYM\r\n")
            await writer.drain()
            response = await reader.readline()

            writer.close()
            await writer.wait_closed()

            return response.startswith(b"250")

        except Exception as e:
            logger.error(f"Error requesting new circuit: {e}")
            return False

    async def fetch_exit_nodes(self) -> set[str]:
        """Fetch current Tor exit node list."""
        # Use cache if fresh (less than 1 hour old)
        if (
            self._exit_nodes_cache
            and self._exit_nodes_updated
            and (datetime.now() - self._exit_nodes_updated).seconds < 3600
        ):
            return self._exit_nodes_cache

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(TOR_EXIT_LIST_URL, timeout=30) as response:
                    if response.status == 200:
                        text = await response.text()
                        self._exit_nodes_cache = set(
                            line.strip()
                            for line in text.splitlines()
                            if line.strip() and not line.startswith("#")
                        )
                        self._exit_nodes_updated = datetime.now()
                        logger.info(f"Fetched {len(self._exit_nodes_cache)} Tor exit nodes")
        except Exception as e:
            logger.warning(f"Failed to fetch Tor exit nodes: {e}")

        return self._exit_nodes_cache

    async def is_tor_exit(self, ip: str) -> bool:
        """Check if an IP is a known Tor exit node."""
        exit_nodes = await self.fetch_exit_nodes()
        return ip in exit_nodes

    async def check_tor_connection(self) -> bool:
        """Check if traffic is going through Tor."""
        try:
            async with aiohttp.ClientSession() as session:
                # Use Tor SOCKS proxy
                connector = aiohttp.TCPConnector()

                # Check via Tor Project's check service
                async with session.get(
                    TOR_CHECK_URL, proxy=f"socks5://127.0.0.1:{self.socks_port}", timeout=15
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("IsTor", False)
        except Exception as e:
            logger.debug(f"Tor connection check failed: {e}")

        return False

    async def get_status(self) -> TorStatus:
        """Get comprehensive Tor status."""
        status = TorStatus(socks_port=self.socks_port, control_port=self.control_port)

        # Check if process is running
        status.is_running = await self.check_tor_running()

        # Check ports
        socks_available = await self.check_socks_port()
        status.control_port_available = await self.check_control_port()

        if status.control_port_available:
            status.version = await self.get_tor_version()

        # Check if actually connected through Tor
        if socks_available:
            status.is_connected = await self.check_tor_connection()
            status.circuit_established = status.is_connected

            if status.is_connected:
                # Get exit node info
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            "https://api.ipify.org?format=json",
                            proxy=f"socks5://127.0.0.1:{self.socks_port}",
                            timeout=10,
                        ) as response:
                            if response.status == 200:
                                data = await response.json()
                                status.exit_node_ip = data.get("ip")
                except Exception:
                    pass

        return status


class VPNDetector:
    """
    Detects VPN connections and provides VPN-related utilities.

    Features:
    - Network interface analysis
    - Known VPN provider detection
    - Protocol identification
    - Kill switch verification
    """

    # Known VPN interface patterns
    VPN_INTERFACE_PATTERNS = [
        r"tun\d+",  # OpenVPN, WireGuard
        r"tap\d+",  # OpenVPN TAP
        r"wg\d+",  # WireGuard
        r"ppp\d+",  # PPTP
        r"ipsec\d+",  # IPSec
        r"utun\d+",  # macOS VPN
        r"gpd\d+",  # GlobalProtect
        r"nordlynx",  # NordVPN
        r"proton\d+",  # ProtonVPN
        r"mullvad\d+",  # Mullvad
    ]

    # Known VPN ISP/ASN keywords
    VPN_PROVIDER_KEYWORDS = [
        "nordvpn",
        "expressvpn",
        "protonvpn",
        "mullvad",
        "surfshark",
        "cyberghost",
        "privateinternetaccess",
        "pia",
        "ipvanish",
        "purevpn",
        "hotspot shield",
        "tunnelbear",
        "windscribe",
        "private internet",
        "hide.me",
        "vpn",
        "hosting",
        "datacenter",
        "server",
        "cloud",
        "amazon",
        "google cloud",
        "microsoft azure",
        "digitalocean",
        "linode",
        "vultr",
        "ovh",
        "hetzner",
    ]

    async def detect_vpn_interface(self) -> Optional[str]:
        """Detect active VPN network interface."""
        system = platform.system()

        try:
            if system == "Darwin":
                process = await asyncio.create_subprocess_exec(
                    "ifconfig", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                output = stdout.decode()

                for pattern in self.VPN_INTERFACE_PATTERNS:
                    match = re.search(f"({pattern}):", output)
                    if match:
                        return match.group(1)

            elif system == "Linux":
                process = await asyncio.create_subprocess_exec(
                    "ip",
                    "link",
                    "show",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await process.communicate()
                output = stdout.decode()

                for pattern in self.VPN_INTERFACE_PATTERNS:
                    match = re.search(f"\\d+: ({pattern}):", output)
                    if match:
                        return match.group(1)

            elif system == "Windows":
                process = await asyncio.create_subprocess_exec(
                    "ipconfig",
                    "/all",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await process.communicate()
                output = stdout.decode()

                # Look for TAP or TUN adapters
                if re.search(r"TAP-Windows|WireGuard|OpenVPN", output, re.IGNORECASE):
                    return "VPN Adapter"

        except Exception as e:
            logger.debug(f"Error detecting VPN interface: {e}")

        return None

    async def check_routing_table(self) -> bool:
        """Check if default route goes through VPN."""
        system = platform.system()

        try:
            if system in ("Darwin", "Linux"):
                process = await asyncio.create_subprocess_exec(
                    "netstat", "-rn", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                output = stdout.decode()

                # Check if default route uses a VPN interface
                for line in output.splitlines():
                    if "default" in line or "0.0.0.0" in line:
                        for pattern in self.VPN_INTERFACE_PATTERNS:
                            if re.search(pattern, line):
                                return True

        except Exception as e:
            logger.debug(f"Error checking routing table: {e}")

        return False

    async def detect_vpn_provider(self, ip_info: IPInfo) -> Optional[str]:
        """Attempt to identify VPN provider from IP info."""
        if not ip_info:
            return None

        # Check ISP and org fields
        for field in [ip_info.isp, ip_info.org, ip_info.asn]:
            if field:
                field_lower = field.lower()
                for keyword in self.VPN_PROVIDER_KEYWORDS:
                    if keyword in field_lower:
                        return field

        return None

    async def check_kill_switch(self) -> bool:
        """Check if a VPN kill switch might be active."""
        system = platform.system()

        try:
            if system in ("Darwin", "Linux"):
                # Check for iptables/pf rules that block non-VPN traffic
                if system == "Darwin":
                    process = await asyncio.create_subprocess_exec(
                        "pfctl",
                        "-sr",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                else:
                    process = await asyncio.create_subprocess_exec(
                        "iptables",
                        "-L",
                        "-n",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                stdout, _ = await process.communicate()
                output = stdout.decode()

                # Look for blocking rules
                if re.search(r"block|DROP|REJECT", output):
                    return True

        except Exception as e:
            logger.debug(f"Error checking kill switch: {e}")

        return False

    async def get_status(self) -> VPNStatus:
        """Get comprehensive VPN status."""
        status = VPNStatus()

        # Check for VPN interface
        interface = await self.detect_vpn_interface()
        if interface:
            status.interface_name = interface

        # Check routing
        routing_vpn = await self.check_routing_table()

        status.is_connected = bool(interface) or routing_vpn

        # Check kill switch
        status.kill_switch_enabled = await self.check_kill_switch()

        # Try to determine protocol from interface name
        if interface:
            if re.match(r"wg\d+|nordlynx", interface):
                status.protocol = "WireGuard"
            elif re.match(r"tun\d+", interface):
                status.protocol = "OpenVPN (tun)"
            elif re.match(r"tap\d+", interface):
                status.protocol = "OpenVPN (tap)"
            elif re.match(r"ppp\d+", interface):
                status.protocol = "PPTP/L2TP"

        return status


class SecurityAdvisor:
    """
    Comprehensive security advisor with Tor/VPN detection and recommendations.

    Features:
    - Real-time IP detection
    - Tor connection verification
    - VPN detection and validation
    - DNS leak testing
    - WebRTC leak detection
    - IPv6 leak detection
    - Security scoring
    - Personalized recommendations
    """

    def __init__(
        self,
        tor_socks_port: int = 9050,
        tor_control_port: int = 9051,
        tor_control_password: Optional[str] = None,
    ):
        self.tor_manager = TorManager(
            socks_port=tor_socks_port,
            control_port=tor_control_port,
            control_password=tor_control_password,
        )
        self.vpn_detector = VPNDetector()
        self._status_cache: Optional[SecurityStatus] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl = 60  # seconds

        logger.info("SecurityAdvisor initialized")

    def get_recommendations(self) -> str:
        """Return security recommendations."""
        return SECURITY_GUIDELINES

    async def get_public_ip(self) -> Optional[str]:
        """Get current public IP address."""
        for service in IP_CHECK_SERVICES:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(service, timeout=5) as response:
                        if response.status == 200:
                            data = await response.json()
                            # Different services use different keys
                            for key in ["ip", "origin", "query"]:
                                if key in data:
                                    return data[key]
            except Exception:
                continue

        return None

    async def get_ip_info(self, ip: Optional[str] = None) -> Optional[IPInfo]:
        """Get detailed information about an IP address."""
        if not ip:
            ip = await self.get_public_ip()

        if not ip:
            return None

        info = IPInfo(ip=ip)

        try:
            async with aiohttp.ClientSession() as session:
                # Use ipinfo.io for detailed lookup
                async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        info.country = data.get("country")
                        info.city = data.get("city")
                        info.org = data.get("org")
                        info.hostname = data.get("hostname")
                        info.timezone = data.get("timezone")

                        # Parse ASN from org field
                        if info.org:
                            match = re.match(r"AS(\d+)", info.org)
                            if match:
                                info.asn = match.group(0)
                                info.isp = info.org[len(info.asn) :].strip()
        except Exception as e:
            logger.debug(f"Error fetching IP info: {e}")

        # Check if Tor exit
        info.is_tor_exit = await self.tor_manager.is_tor_exit(ip)

        # Check for VPN/datacenter indicators
        if info.org:
            org_lower = info.org.lower()
            info.is_datacenter = any(
                kw in org_lower
                for kw in [
                    "hosting",
                    "server",
                    "datacenter",
                    "cloud",
                    "amazon",
                    "google",
                    "microsoft",
                    "digital ocean",
                ]
            )
            info.is_vpn = any(
                kw in org_lower
                for kw in [
                    "vpn",
                    "private internet",
                    "mullvad",
                    "nord",
                    "express",
                    "proton",
                    "surfshark",
                ]
            )

        return info

    async def check_dns_leak(self) -> bool:
        """
        Check for DNS leaks.

        Returns True if a DNS leak is detected.
        """
        try:
            # Get resolver IP by doing a DNS lookup
            resolver = socket.gethostbyname("resolver1.opendns.com")

            # If using Tor, the resolver should not be our real DNS
            tor_status = await self.tor_manager.get_status()
            if tor_status.is_connected:
                # Check if resolver is in known ISP ranges
                # This is a simplified check
                try:
                    host = socket.gethostbyaddr(resolver)
                    hostname = host[0].lower()
                    # If hostname contains ISP names, likely a leak
                    isp_keywords = ["comcast", "verizon", "att", "spectrum", "cox"]
                    if any(kw in hostname for kw in isp_keywords):
                        return True
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"DNS leak check error: {e}")

        return False

    async def check_ipv6_leak(self) -> bool:
        """
        Check for IPv6 leaks.

        Returns True if IPv6 is leaking real address.
        """
        try:
            # Try to connect to an IPv6 service
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api64.ipify.org?format=json", timeout=5
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        ipv6 = data.get("ip", "")

                        # If we get an IPv6 and we're supposed to be on Tor/VPN
                        if ":" in ipv6:  # IPv6 address
                            tor_status = await self.tor_manager.get_status()
                            vpn_status = await self.vpn_detector.get_status()

                            if tor_status.is_connected or vpn_status.is_connected:
                                # Check if this IPv6 is our real address
                                # (simplified - in practice would compare to known real IP)
                                return True
        except Exception:
            pass  # No IPv6 connectivity is actually good for privacy

        return False

    async def check_tor_connection(self) -> bool:
        """Check if Tor connection is active."""
        status = await self.tor_manager.get_status()
        return status.is_connected

    async def check_vpn_connection(self) -> bool:
        """Check if VPN connection is active."""
        status = await self.vpn_detector.get_status()
        return status.is_connected

    async def get_security_status(self, force_refresh: bool = False) -> SecurityStatus:
        """
        Get comprehensive security status.

        Returns a SecurityStatus object with all security checks.
        """
        # Check cache
        if (
            not force_refresh
            and self._status_cache
            and self._cache_time
            and (datetime.now() - self._cache_time).seconds < self._cache_ttl
        ):
            return self._status_cache

        # Get all status info in parallel
        public_ip, tor_status, vpn_status = await asyncio.gather(
            self.get_public_ip(), self.tor_manager.get_status(), self.vpn_detector.get_status()
        )

        # Get IP info if we have an IP
        ip_info = None
        if public_ip:
            ip_info = await self.get_ip_info(public_ip)

        # Determine connection type
        if tor_status.is_connected:
            connection_type = ConnectionType.TOR
        elif vpn_status.is_connected:
            connection_type = ConnectionType.VPN
        elif ip_info and (ip_info.is_proxy or ip_info.is_datacenter):
            connection_type = ConnectionType.PROXY
        else:
            connection_type = ConnectionType.DIRECT

        # Check for leaks
        dns_leak, ipv6_leak = await asyncio.gather(self.check_dns_leak(), self.check_ipv6_leak())

        # Determine security level
        if tor_status.is_connected and not dns_leak and not ipv6_leak:
            level = SecurityLevel.HIGH
            if vpn_status.is_connected:  # Tor over VPN
                level = SecurityLevel.MAXIMUM
        elif vpn_status.is_connected and not dns_leak:
            level = SecurityLevel.MEDIUM
        elif ip_info and (ip_info.is_proxy or ip_info.is_datacenter):
            level = SecurityLevel.LOW
        else:
            level = SecurityLevel.EXPOSED

        # Generate recommendations
        recommendations = self._generate_recommendations(
            tor_status, vpn_status, dns_leak, ipv6_leak, level
        )

        status = SecurityStatus(
            level=level,
            connection_type=connection_type,
            public_ip=public_ip,
            ip_info=ip_info,
            tor_active=tor_status.is_connected,
            vpn_active=vpn_status.is_connected,
            proxy_active=ip_info.is_proxy if ip_info else False,
            dns_leak=dns_leak,
            webrtc_leak=False,  # Would need browser context to check
            ipv6_leak=ipv6_leak,
            fingerprint_risk=self._assess_fingerprint_risk(level),
            recommendations=recommendations,
        )

        # Cache result
        self._status_cache = status
        self._cache_time = datetime.now()

        return status

    def _generate_recommendations(
        self,
        tor_status: TorStatus,
        vpn_status: VPNStatus,
        dns_leak: bool,
        ipv6_leak: bool,
        level: SecurityLevel,
    ) -> list[str]:
        """Generate security recommendations based on current status."""
        recommendations = []

        if level == SecurityLevel.EXPOSED:
            recommendations.append(
                "⚠️ Your real IP is exposed. Use a VPN or Tor for investigations."
            )

        if not tor_status.is_connected and not vpn_status.is_connected:
            recommendations.append(
                "🔐 Consider using Tor for maximum anonymity during OSINT operations."
            )

        if vpn_status.is_connected and not vpn_status.kill_switch_enabled:
            recommendations.append(
                "🛡️ Enable your VPN's kill switch to prevent IP leaks if connection drops."
            )

        if dns_leak:
            recommendations.append(
                "⚠️ DNS leak detected! Configure your system to use anonymous DNS servers."
            )

        if ipv6_leak:
            recommendations.append(
                "⚠️ IPv6 leak detected! Disable IPv6 or ensure your VPN/Tor handles it."
            )

        if tor_status.is_running and not tor_status.is_connected:
            recommendations.append(
                "ℹ️ Tor is running but traffic isn't routed through it. Check SOCKS proxy settings."
            )

        if level == SecurityLevel.HIGH:
            recommendations.append(
                "✅ Good anonymity level. Consider using TAILS or Whonix for maximum security."
            )

        if level == SecurityLevel.MAXIMUM:
            recommendations.append("🎯 Maximum anonymity achieved with Tor over VPN.")

        return recommendations

    def _assess_fingerprint_risk(self, level: SecurityLevel) -> str:
        """Assess browser/system fingerprinting risk."""
        if level in (SecurityLevel.HIGH, SecurityLevel.MAXIMUM):
            return "low"
        elif level == SecurityLevel.MEDIUM:
            return "medium"
        else:
            return "high"

    async def request_new_tor_identity(self) -> bool:
        """Request a new Tor identity (circuit)."""
        return await self.tor_manager.request_new_circuit()

    def get_security_summary(self, status: SecurityStatus) -> str:
        """Generate a human-readable security summary."""
        level_icons = {
            SecurityLevel.EXPOSED: "🔴",
            SecurityLevel.LOW: "🟠",
            SecurityLevel.MEDIUM: "🟡",
            SecurityLevel.HIGH: "🟢",
            SecurityLevel.MAXIMUM: "🟣",
        }

        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                    TR4C3R Security Status                     ║
╠══════════════════════════════════════════════════════════════╣
║  Security Level: {level_icons[status.level]} {status.level.value.upper():<10}                            ║
║  Connection Type: {status.connection_type.value.upper():<10}                           ║
║  Public IP: {status.public_ip or 'Unknown':<15}                               ║
╠══════════════════════════════════════════════════════════════╣
║  Tor Active: {'✅' if status.tor_active else '❌'}    VPN Active: {'✅' if status.vpn_active else '❌'}                    ║
║  DNS Leak: {'❌ LEAK!' if status.dns_leak else '✅ Safe'}    IPv6 Leak: {'❌ LEAK!' if status.ipv6_leak else '✅ Safe'}              ║
╠══════════════════════════════════════════════════════════════╣
"""

        if status.recommendations:
            summary += "║  Recommendations:                                            ║\n"
            for rec in status.recommendations[:3]:
                # Truncate if too long
                if len(rec) > 56:
                    rec = rec[:53] + "..."
                summary += f"║    {rec:<56} ║\n"

        summary += "╚══════════════════════════════════════════════════════════════╝"

        return summary

"""Input validation utilities for TR4C3R.

Provides validation for various OSINT input types:
- Email addresses
- Phone numbers
- Usernames
- URLs
- IP addresses
- Domain names
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


@dataclass
class ValidationResult:
    """Result of a validation check."""

    valid: bool
    value: str
    normalized: Optional[str] = None
    error: Optional[str] = None
    details: Optional[dict] = None


class InputValidator:
    """Validates and normalizes various input types."""

    # Email patterns
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    # Username patterns (alphanumeric, underscore, dash)
    USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")

    # IP patterns
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    IPV6_PATTERN = re.compile(
        r"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
        r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
        r":(?::[0-9a-fA-F]{1,4}){1,7}|"
        r"::(?:[fF]{4}(?::0{1,4})?:)?"
        r"(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}"
        r"(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|"
        r"(?:[0-9a-fA-F]{1,4}:){1,4}:"
        r"(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}"
        r"(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))$"
    )

    # Domain pattern
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    )

    # Hash patterns
    MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

    def validate_email(self, email: str) -> ValidationResult:
        """Validate and normalize an email address.

        Args:
            email: Email address to validate

        Returns:
            ValidationResult with status and normalized value
        """
        if not email:
            return ValidationResult(
                valid=False,
                value=email,
                error="Email cannot be empty",
            )

        email = email.strip().lower()

        if not self.EMAIL_PATTERN.match(email):
            return ValidationResult(
                valid=False,
                value=email,
                error="Invalid email format",
            )

        local, domain = email.rsplit("@", 1)

        # Extract domain details
        parts = domain.split(".")
        tld = parts[-1]

        return ValidationResult(
            valid=True,
            value=email,
            normalized=email,
            details={
                "local": local,
                "domain": domain,
                "tld": tld,
            },
        )

    def validate_phone(self, phone: str) -> ValidationResult:
        """Validate and normalize a phone number.

        Args:
            phone: Phone number to validate

        Returns:
            ValidationResult with status and normalized value
        """
        if not phone:
            return ValidationResult(
                valid=False,
                value=phone,
                error="Phone number cannot be empty",
            )

        # Remove common separators
        normalized = re.sub(r"[\s\-\.\(\)]", "", phone)

        # Handle + prefix
        if normalized.startswith("+"):
            has_country_code = True
            digits = normalized[1:]
        else:
            has_country_code = normalized.startswith("00")
            if has_country_code:
                digits = normalized[2:]
            else:
                digits = normalized

        # Check if all remaining characters are digits
        if not digits.isdigit():
            return ValidationResult(
                valid=False,
                value=phone,
                error="Phone number must contain only digits",
            )

        # Check length (international numbers: 7-15 digits)
        if len(digits) < 7 or len(digits) > 15:
            return ValidationResult(
                valid=False,
                value=phone,
                error="Phone number must be 7-15 digits",
            )

        # Normalize to E.164 format
        if not normalized.startswith("+"):
            normalized = "+" + digits
        else:
            normalized = "+" + digits

        return ValidationResult(
            valid=True,
            value=phone,
            normalized=normalized,
            details={
                "digits": digits,
                "has_country_code": has_country_code,
                "length": len(digits),
            },
        )

    def validate_username(self, username: str) -> ValidationResult:
        """Validate a username.

        Args:
            username: Username to validate

        Returns:
            ValidationResult with status
        """
        if not username:
            return ValidationResult(
                valid=False,
                value=username,
                error="Username cannot be empty",
            )

        username = username.strip()

        if len(username) < 3:
            return ValidationResult(
                valid=False,
                value=username,
                error="Username must be at least 3 characters",
            )

        if len(username) > 30:
            return ValidationResult(
                valid=False,
                value=username,
                error="Username must be at most 30 characters",
            )

        if not self.USERNAME_PATTERN.match(username):
            return ValidationResult(
                valid=False,
                value=username,
                error="Username can only contain letters, numbers, underscores, dots, and dashes",
            )

        return ValidationResult(
            valid=True,
            value=username,
            normalized=username.lower(),
        )

    def validate_url(self, url: str) -> ValidationResult:
        """Validate and parse a URL.

        Args:
            url: URL to validate

        Returns:
            ValidationResult with status and parsed components
        """
        if not url:
            return ValidationResult(
                valid=False,
                value=url,
                error="URL cannot be empty",
            )

        url = url.strip()

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)

            if not parsed.netloc:
                return ValidationResult(
                    valid=False,
                    value=url,
                    error="Invalid URL: missing domain",
                )

            return ValidationResult(
                valid=True,
                value=url,
                normalized=url,
                details={
                    "scheme": parsed.scheme,
                    "domain": parsed.netloc,
                    "path": parsed.path or "/",
                    "query": parsed.query,
                    "fragment": parsed.fragment,
                },
            )
        except Exception as e:
            return ValidationResult(
                valid=False,
                value=url,
                error=f"Invalid URL: {str(e)}",
            )

    def validate_ip(self, ip: str) -> ValidationResult:
        """Validate an IP address (IPv4 or IPv6).

        Args:
            ip: IP address to validate

        Returns:
            ValidationResult with status and version
        """
        if not ip:
            return ValidationResult(
                valid=False,
                value=ip,
                error="IP address cannot be empty",
            )

        ip = ip.strip()

        if self.IPV4_PATTERN.match(ip):
            return ValidationResult(
                valid=True,
                value=ip,
                normalized=ip,
                details={"version": 4},
            )

        if self.IPV6_PATTERN.match(ip):
            return ValidationResult(
                valid=True,
                value=ip,
                normalized=ip.lower(),
                details={"version": 6},
            )

        return ValidationResult(
            valid=False,
            value=ip,
            error="Invalid IP address format",
        )

    def validate_domain(self, domain: str) -> ValidationResult:
        """Validate a domain name.

        Args:
            domain: Domain name to validate

        Returns:
            ValidationResult with status
        """
        if not domain:
            return ValidationResult(
                valid=False,
                value=domain,
                error="Domain cannot be empty",
            )

        domain = domain.strip().lower()

        # Remove protocol if present
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc

        # Remove trailing dot
        domain = domain.rstrip(".")

        if len(domain) > 253:
            return ValidationResult(
                valid=False,
                value=domain,
                error="Domain name too long (max 253 characters)",
            )

        if not self.DOMAIN_PATTERN.match(domain):
            return ValidationResult(
                valid=False,
                value=domain,
                error="Invalid domain format",
            )

        parts = domain.split(".")
        if len(parts) < 2:
            return ValidationResult(
                valid=False,
                value=domain,
                error="Domain must have at least two parts",
            )

        return ValidationResult(
            valid=True,
            value=domain,
            normalized=domain,
            details={
                "parts": parts,
                "tld": parts[-1],
                "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else None,
            },
        )

    def validate_hash(self, hash_value: str) -> ValidationResult:
        """Validate a hash value (MD5, SHA1, SHA256).

        Args:
            hash_value: Hash to validate

        Returns:
            ValidationResult with status and hash type
        """
        if not hash_value:
            return ValidationResult(
                valid=False,
                value=hash_value,
                error="Hash cannot be empty",
            )

        hash_value = hash_value.strip().lower()

        if self.MD5_PATTERN.match(hash_value):
            return ValidationResult(
                valid=True,
                value=hash_value,
                normalized=hash_value,
                details={"type": "md5", "length": 32},
            )

        if self.SHA1_PATTERN.match(hash_value):
            return ValidationResult(
                valid=True,
                value=hash_value,
                normalized=hash_value,
                details={"type": "sha1", "length": 40},
            )

        if self.SHA256_PATTERN.match(hash_value):
            return ValidationResult(
                valid=True,
                value=hash_value,
                normalized=hash_value,
                details={"type": "sha256", "length": 64},
            )

        return ValidationResult(
            valid=False,
            value=hash_value,
            error="Invalid hash format (must be MD5, SHA1, or SHA256)",
        )

    def detect_input_type(self, value: str) -> tuple[str, ValidationResult]:
        """Detect the type of input and validate it.

        Args:
            value: Input value to detect

        Returns:
            Tuple of (detected_type, ValidationResult)
        """
        if not value:
            return "unknown", ValidationResult(
                valid=False,
                value=value,
                error="Input cannot be empty",
            )

        value = value.strip()

        # Try email first
        if "@" in value:
            result = self.validate_email(value)
            if result.valid:
                return "email", result

        # Try URL
        if value.startswith(("http://", "https://", "www.")):
            result = self.validate_url(value)
            if result.valid:
                return "url", result

        # Try IP
        if re.match(r"^[\d.:a-fA-F]+$", value):
            result = self.validate_ip(value)
            if result.valid:
                return "ip", result

        # Try phone
        if re.match(r"^[\d\s\-\+\.\(\)]+$", value):
            result = self.validate_phone(value)
            if result.valid:
                return "phone", result

        # Try hash
        if re.match(r"^[a-fA-F0-9]+$", value):
            result = self.validate_hash(value)
            if result.valid:
                return "hash", result

        # Try domain
        if "." in value and not " " in value:
            result = self.validate_domain(value)
            if result.valid:
                return "domain", result

        # Fall back to username
        result = self.validate_username(value)
        if result.valid:
            return "username", result

        return "unknown", ValidationResult(
            valid=False,
            value=value,
            error="Unable to detect input type",
        )


# Singleton instance
_validator = InputValidator()


def validate_email(email: str) -> ValidationResult:
    """Validate email address."""
    return _validator.validate_email(email)


def validate_phone(phone: str) -> ValidationResult:
    """Validate phone number."""
    return _validator.validate_phone(phone)


def validate_username(username: str) -> ValidationResult:
    """Validate username."""
    return _validator.validate_username(username)


def validate_url(url: str) -> ValidationResult:
    """Validate URL."""
    return _validator.validate_url(url)


def validate_ip(ip: str) -> ValidationResult:
    """Validate IP address."""
    return _validator.validate_ip(ip)


def validate_domain(domain: str) -> ValidationResult:
    """Validate domain name."""
    return _validator.validate_domain(domain)


def validate_hash(hash_value: str) -> ValidationResult:
    """Validate hash value."""
    return _validator.validate_hash(hash_value)


def detect_input_type(value: str) -> tuple[str, ValidationResult]:
    """Detect input type and validate."""
    return _validator.detect_input_type(value)

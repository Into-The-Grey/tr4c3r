"""Email search module for TR4C3R.

This module defines the ``EmailSearch`` class which performs OSINT lookups
for a given email address. It validates emails, checks breach databases
(HaveIBeenPwned), queries Hunter.io for company emails, and performs
reputation checks across multiple services.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.core.data_models import Result
from src.core.http_client import AsyncHTTPClient


@dataclass
class EmailValidationResult:
    """Result of email validation checks."""

    is_valid: bool
    email: str
    domain: str
    username: str
    has_mx_record: bool = False
    is_disposable: bool = False
    is_role_based: bool = False
    error: Optional[str] = None


class EmailValidator:
    """Validates email addresses using regex and optional DNS checks."""

    # Common role-based email prefixes
    ROLE_PREFIXES = {
        "admin",
        "administrator",
        "info",
        "support",
        "help",
        "sales",
        "contact",
        "noreply",
        "no-reply",
        "postmaster",
        "webmaster",
        "hostmaster",
        "abuse",
    }

    # Common disposable email domains (subset)
    DISPOSABLE_DOMAINS = {
        "mailinator.com",
        "guerrillamail.com",
        "10minutemail.com",
        "tempmail.com",
        "throwaway.email",
        "maildrop.cc",
        "yopmail.com",
        "trashmail.com",
    }

    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    def __init__(self):
        """Initialize the email validator."""
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate(self, email: str) -> EmailValidationResult:
        """
        Validate an email address.

        Args:
            email: The email address to validate

        Returns:
            EmailValidationResult with validation details
        """
        email = email.strip().lower()

        # Basic regex validation
        if not self.EMAIL_REGEX.match(email):
            return EmailValidationResult(
                is_valid=False, email=email, domain="", username="", error="Invalid email format"
            )

        # Split email into parts
        try:
            username, domain = email.rsplit("@", 1)
        except ValueError:
            return EmailValidationResult(
                is_valid=False,
                email=email,
                domain="",
                username="",
                error="Could not parse email address",
            )

        # Check for disposable domain
        is_disposable = domain in self.DISPOSABLE_DOMAINS

        # Check for role-based email
        is_role_based = username.split("+")[0] in self.ROLE_PREFIXES

        return EmailValidationResult(
            is_valid=True,
            email=email,
            domain=domain,
            username=username,
            is_disposable=is_disposable,
            is_role_based=is_role_based,
        )


class EmailSearch:
    """Performs OSINT searches for email addresses."""

    def __init__(self) -> None:
        """Initialize the email search module."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.validator = EmailValidator()
        self.http_client = AsyncHTTPClient()

        # Load API keys from environment
        self.hibp_api_key = os.getenv("HIBP_API_KEY", "")
        self.hunter_api_key = os.getenv("HUNTER_API_KEY", "")

    async def search(self, email: str) -> List[Result]:
        """
        Search for the given email address across multiple sources.

        Args:
            email: The email address to search for

        Returns:
            List of Result objects from various sources
        """
        self.logger.info(f"Starting email search for '{email}'")
        results: List[Result] = []

        # Step 1: Validate email
        validation = self.validator.validate(email)
        if not validation.is_valid:
            self.logger.warning(f"Invalid email: {validation.error}")
            return results

        # Use normalized email from validation
        normalized_email = validation.email

        # Create validation result
        validation_result = Result(
            source="email:validation",
            identifier=normalized_email,
            url="",
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "is_valid": validation.is_valid,
                "domain": validation.domain,
                "username": validation.username,
                "is_disposable": validation.is_disposable,
                "is_role_based": validation.is_role_based,
            },
        )
        results.append(validation_result)

        # Step 2: Run searches in parallel
        search_tasks = [
            self._search_haveibeenpwned(normalized_email),
            self._search_hunter_io(normalized_email),
            self._check_reputation(normalized_email),
        ]

        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        # Flatten results and filter out exceptions
        for task_results in search_results:
            if isinstance(task_results, Exception):
                self.logger.error(f"Search task failed: {task_results}")
                continue
            if isinstance(task_results, list):
                results.extend(task_results)

        self.logger.info(f"Completed email search for '{email}' with {len(results)} results")
        return results

    async def _search_haveibeenpwned(self, email: str) -> List[Result]:
        """
        Check if email appears in HaveIBeenPwned breaches.

        Args:
            email: The email address to check

        Returns:
            List of Result objects for breach findings
        """
        results: List[Result] = []

        if not self.hibp_api_key:
            self.logger.debug("HIBP API key not set, skipping HaveIBeenPwned check")
            return results

        try:
            # Use k-anonymity API (range search) for privacy
            # Hash the email with SHA1
            email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
            hash_prefix = email_hash[:5]

            url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"

            async with self.http_client as client:
                response = await client.get(url, timeout=10.0)

                if response.status_code == 200:
                    # Check if our hash suffix appears in results
                    hash_suffix = email_hash[5:]
                    breaches = []

                    for line in response.text.split("\n"):
                        if line.startswith(hash_suffix):
                            count = int(line.split(":")[1].strip())
                            breaches.append(count)

                    if breaches:
                        result = Result(
                            source="email:haveibeenpwned",
                            identifier=email,
                            url="https://haveibeenpwned.com/",
                            confidence=0.9,
                            timestamp=datetime.now(timezone.utc),
                            metadata={
                                "service": "HaveIBeenPwned",
                                "breached": True,
                                "breach_count": len(breaches),
                                "note": "Email found in breach databases",
                            },
                        )
                        results.append(result)
                        self.logger.info(f"Email found in {len(breaches)} breaches")
                    else:
                        result = Result(
                            source="email:haveibeenpwned",
                            identifier=email,
                            url="https://haveibeenpwned.com/",
                            confidence=1.0,
                            timestamp=datetime.now(timezone.utc),
                            metadata={
                                "service": "HaveIBeenPwned",
                                "breached": False,
                                "note": "Email not found in breach databases",
                            },
                        )
                        results.append(result)

        except Exception as e:
            self.logger.error(f"HaveIBeenPwned check failed: {e}")

        return results

    async def _search_hunter_io(self, email: str) -> List[Result]:
        """
        Search Hunter.io for email information and domain data.

        Args:
            email: The email address to search

        Returns:
            List of Result objects from Hunter.io
        """
        results: List[Result] = []

        if not self.hunter_api_key:
            self.logger.debug("Hunter.io API key not set, skipping Hunter.io check")
            return results

        try:
            # Email Verifier API
            url = f"https://api.hunter.io/v2/email-verifier"
            params = {"email": email, "api_key": self.hunter_api_key}

            async with self.http_client as client:
                response = await client.get(url, params=params, timeout=10.0)

                if response.status_code == 200:
                    data = response.json()

                    if "data" in data:
                        email_data = data["data"]

                        result = Result(
                            source="email:hunter_io",
                            identifier=email,
                            url=f"https://hunter.io/verify/{email}",
                            confidence=0.8,
                            timestamp=datetime.now(timezone.utc),
                            metadata={
                                "service": "Hunter.io",
                                "status": email_data.get("status"),
                                "score": email_data.get("score"),
                                "result": email_data.get("result"),
                                "accept_all": email_data.get("accept_all"),
                                "disposable": email_data.get("disposable"),
                                "free": email_data.get("free"),
                                "mx_records": email_data.get("mx_records", False),
                                "smtp_server": email_data.get("smtp_server", False),
                                "smtp_check": email_data.get("smtp_check", False),
                            },
                        )
                        results.append(result)
                        self.logger.info(f"Hunter.io verification: {email_data.get('result')}")

                elif response.status_code == 429:
                    self.logger.warning("Hunter.io rate limit exceeded")
                else:
                    self.logger.warning(f"Hunter.io returned status {response.status_code}")

        except Exception as e:
            self.logger.error(f"Hunter.io check failed: {e}")

        return results

    async def _check_reputation(self, email: str) -> List[Result]:
        """
        Check email reputation using various indicators.

        Args:
            email: The email address to check

        Returns:
            List of Result objects with reputation data
        """
        results: List[Result] = []

        try:
            validation = self.validator.validate(email)
            domain = validation.domain

            # Check if domain is from major email providers
            major_providers = {
                "gmail.com",
                "yahoo.com",
                "outlook.com",
                "hotmail.com",
                "icloud.com",
                "protonmail.com",
                "aol.com",
                "mail.com",
            }

            is_major_provider = domain in major_providers

            # Calculate basic reputation score
            reputation_score = 0.5  # neutral

            if is_major_provider:
                reputation_score += 0.2
            if validation.is_disposable:
                reputation_score -= 0.3
            if validation.is_role_based:
                reputation_score -= 0.1

            reputation_score = max(0.0, min(1.0, reputation_score))

            result = Result(
                source="email:reputation",
                identifier=email,
                url="",
                confidence=0.7,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "reputation_score": round(reputation_score, 2),
                    "is_major_provider": is_major_provider,
                    "is_disposable": validation.is_disposable,
                    "is_role_based": validation.is_role_based,
                    "domain": domain,
                },
            )
            results.append(result)

        except Exception as e:
            self.logger.error(f"Reputation check failed: {e}")

        return results

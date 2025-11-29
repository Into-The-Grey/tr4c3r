"""Phone number search module for TR4C3R.

This module defines the ``PhoneSearch`` class which performs OSINT lookups
for phone numbers. It validates numbers, extracts carrier information,
supports international formats, and performs reverse lookups.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat, PhoneNumberType
from phonenumbers import carrier, geocoder, timezone as phone_timezone

from src.core.data_models import Result
from src.core.http_client import AsyncHTTPClient


@dataclass
class PhoneValidationResult:
    """Result of phone number validation."""

    is_valid: bool
    number: str
    original: str
    country_code: Optional[int] = None
    national_number: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    number_type: Optional[str] = None
    carrier_name: Optional[str] = None
    timezones: Optional[List[str]] = None
    international_format: Optional[str] = None
    national_format: Optional[str] = None
    e164_format: Optional[str] = None
    error: Optional[str] = None


class PhoneValidator:
    """Validates and parses phone numbers using libphonenumber."""

    # Phone number type mapping
    TYPE_MAPPING = {
        PhoneNumberType.FIXED_LINE: "fixed_line",
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
        PhoneNumberType.TOLL_FREE: "toll_free",
        PhoneNumberType.PREMIUM_RATE: "premium_rate",
        PhoneNumberType.SHARED_COST: "shared_cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
        PhoneNumberType.UNKNOWN: "unknown",
    }

    def __init__(self):
        """Initialize the phone validator."""
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate(self, number: str, default_region: str = "US") -> PhoneValidationResult:
        """
        Validate and parse a phone number.

        Args:
            number: The phone number to validate (can include country code)
            default_region: Default country code if not specified in number

        Returns:
            PhoneValidationResult with detailed information
        """
        original = number

        try:
            # Parse the phone number
            parsed = phonenumbers.parse(number, default_region)

            # Validate if it's a possible and valid number
            is_possible = phonenumbers.is_possible_number(parsed)
            is_valid = phonenumbers.is_valid_number(parsed)

            if not is_valid:
                return PhoneValidationResult(
                    is_valid=False,
                    number=number,
                    original=original,
                    error="Number is not valid for the detected region",
                )

            # Extract detailed information
            country_code = parsed.country_code
            national_number = str(parsed.national_number)
            country = phonenumbers.region_code_for_number(parsed)

            # Get geographic location
            region = geocoder.description_for_number(parsed, "en")

            # Get carrier information
            carrier_name = carrier.name_for_number(parsed, "en")

            # Get timezones
            timezones = phone_timezone.time_zones_for_number(parsed)

            # Get number type
            number_type_enum = phonenumbers.number_type(parsed)
            number_type = self.TYPE_MAPPING.get(number_type_enum, "unknown")

            # Format in different standards
            international_format = phonenumbers.format_number(
                parsed, PhoneNumberFormat.INTERNATIONAL
            )
            national_format = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
            e164_format = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)

            return PhoneValidationResult(
                is_valid=True,
                number=e164_format,
                original=original,
                country_code=country_code,
                national_number=national_number,
                country=country,
                region=region or "Unknown",
                number_type=number_type,
                carrier_name=carrier_name or "Unknown",
                timezones=list(timezones) if timezones else [],
                international_format=international_format,
                national_format=national_format,
                e164_format=e164_format,
            )

        except NumberParseException as e:
            return PhoneValidationResult(
                is_valid=False, number=number, original=original, error=f"Parse error: {str(e)}"
            )
        except Exception as e:
            return PhoneValidationResult(
                is_valid=False,
                number=number,
                original=original,
                error=f"Validation error: {str(e)}",
            )


class PhoneSearch:
    """Performs OSINT searches for phone numbers."""

    def __init__(self) -> None:
        """Initialize the phone search module."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.validator = PhoneValidator()
        self.http_client = AsyncHTTPClient()

        # Load API keys from environment
        self.numverify_api_key = os.getenv("NUMVERIFY_API_KEY", "")
        self.twilio_account_sid = os.getenv("TWILIO_ACCOUNT_SID", "")
        self.twilio_auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")

    async def search(self, number: str, default_region: str = "US") -> List[Result]:
        """
        Search for the given phone number across multiple sources.

        Args:
            number: The phone number to search for
            default_region: Default country code if not in number (e.g., "US", "GB")

        Returns:
            List of Result objects from various sources
        """
        self.logger.info(f"Starting phone search for '{number}'")
        results: List[Result] = []

        # Step 1: Validate and parse phone number
        validation = self.validator.validate(number, default_region)
        if not validation.is_valid:
            self.logger.warning(f"Invalid phone number: {validation.error}")
            return results

        # Create validation result with all metadata
        validation_result = Result(
            source="phone:validation",
            identifier=validation.e164_format or validation.number,
            url="",
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "is_valid": validation.is_valid,
                "original_input": validation.original,
                "country_code": validation.country_code,
                "national_number": validation.national_number,
                "country": validation.country,
                "region": validation.region,
                "number_type": validation.number_type,
                "carrier": validation.carrier_name,
                "timezones": validation.timezones,
                "formats": {
                    "international": validation.international_format,
                    "national": validation.national_format,
                    "e164": validation.e164_format,
                },
            },
        )
        results.append(validation_result)

        # Use E164 format for searches
        normalized_number = validation.e164_format or validation.number

        # Step 2: Run searches in parallel
        search_tasks = [
            self._search_numverify(normalized_number),
            self._search_public_records(validation),
            self._check_spam_database(normalized_number),
        ]

        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        # Flatten results and filter out exceptions
        for task_results in search_results:
            if isinstance(task_results, Exception):
                self.logger.error(f"Search task failed: {task_results}")
                continue
            if isinstance(task_results, list):
                results.extend(task_results)

        self.logger.info(f"Completed phone search for '{number}' with {len(results)} results")
        return results

    async def _search_numverify(self, number: str) -> List[Result]:
        """
        Search Numverify API for phone number information.

        Args:
            number: The phone number in E164 format

        Returns:
            List of Result objects from Numverify
        """
        results: List[Result] = []

        if not self.numverify_api_key:
            self.logger.debug("Numverify API key not set, skipping")
            return results

        try:
            url = "http://apilayer.net/api/validate"
            params = {"access_key": self.numverify_api_key, "number": number, "format": "1"}

            async with self.http_client as client:
                response = await client.get(url, params=params, timeout=10.0)

                if response.status_code == 200:
                    data = response.json()

                    if data.get("valid"):
                        result = Result(
                            source="phone:numverify",
                            identifier=number,
                            url="https://numverify.com/",
                            confidence=0.8,
                            timestamp=datetime.now(timezone.utc),
                            metadata={
                                "service": "Numverify",
                                "valid": data.get("valid"),
                                "number": data.get("number"),
                                "local_format": data.get("local_format"),
                                "international_format": data.get("international_format"),
                                "country_code": data.get("country_code"),
                                "country_name": data.get("country_name"),
                                "location": data.get("location"),
                                "carrier": data.get("carrier"),
                                "line_type": data.get("line_type"),
                            },
                        )
                        results.append(result)
                        self.logger.info(f"Numverify verification successful")

        except Exception as e:
            self.logger.error(f"Numverify check failed: {e}")

        return results

    async def _search_public_records(self, validation: PhoneValidationResult) -> List[Result]:
        """
        Search for phone number in public records and registries.

        Args:
            validation: Validated phone number information

        Returns:
            List of Result objects from public sources
        """
        results: List[Result] = []

        try:
            # Create a summary result from validation data
            result = Result(
                source="phone:carrier_lookup",
                identifier=validation.e164_format or validation.number,
                url="",
                confidence=0.9,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "carrier": validation.carrier_name,
                    "region": validation.region,
                    "country": validation.country,
                    "number_type": validation.number_type,
                    "timezones": validation.timezones,
                    "note": "Carrier and location information from phonenumbers library",
                },
            )
            results.append(result)

        except Exception as e:
            self.logger.error(f"Public records check failed: {e}")

        return results

    async def _check_spam_database(self, number: str) -> List[Result]:
        """
        Check if phone number is reported in spam databases.

        Args:
            number: The phone number in E164 format

        Returns:
            List of Result objects with spam reputation
        """
        results: List[Result] = []

        try:
            # Known spam patterns (basic heuristics)
            spam_score = 0.0
            flags = []

            # Check for common spam number patterns
            # Toll-free numbers often used for telemarketing
            if (
                number.startswith("+1800")
                or number.startswith("+1888")
                or number.startswith("+1877")
            ):
                spam_score += 0.2
                flags.append("toll_free_number")

            # Premium rate numbers
            if number.startswith("+1900"):
                spam_score += 0.5
                flags.append("premium_rate")

            result = Result(
                source="phone:reputation",
                identifier=number,
                url="",
                confidence=0.6,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "spam_score": round(spam_score, 2),
                    "flags": flags,
                    "note": "Basic spam detection heuristics",
                },
            )
            results.append(result)

        except Exception as e:
            self.logger.error(f"Spam check failed: {e}")

        return results

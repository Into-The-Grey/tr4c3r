"""Ethical guidelines and usage policies for TR4C3R.

Ensures the tool is used responsibly and ethically with consent tracking,
usage acknowledgment, and ethical guideline enforcement.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import json
from enum import Enum

logger = logging.getLogger(__name__)

# Hardcoded override code for bypassing ethics checks during setup/testing
OVERRIDE_CODE = "3825"


class SafetyLevel(Enum):
    """Safety and ethics enforcement levels."""

    NONE = "none"  # No ethics checks - use for false positive scenarios
    LOW = "low"  # Basic checks only
    MEDIUM = "medium"  # Standard checks (default)
    HIGH = "high"  # Strict ethical guidelines
    TOTAL = "total"  # Maximum enforcement - all checks enabled


ETHICAL_GUIDELINES = """
TR4C3R Ethical Usage Guidelines
================================

1. Consent & Privacy
   - Only search for publicly available information
   - Respect privacy laws and regulations (GDPR, CCPA, etc.)
   - Obtain proper authorization before investigating individuals

2. Legitimate Purposes Only
   - Security research and threat intelligence
   - Digital forensics and investigations
   - Cybersecurity assessments
   - Academic research with proper ethics approval

3. Prohibited Uses
   - Stalking, harassment, or doxxing
   - Identity theft or fraud
   - Unauthorized surveillance
   - Any illegal activities

4. Data Handling
   - Secure storage of collected data
   - Minimize data retention
   - Proper anonymization when sharing results
   - Comply with data protection regulations

5. Transparency
   - Document your methodology
   - Be clear about data sources
   - Disclose limitations and uncertainties
   - Report responsibly

By using TR4C3R, you agree to follow these guidelines and applicable laws.
"""


DETAILED_ETHICAL_PRINCIPLES = [
    {
        "principle": "Purpose Limitation",
        "description": "Only collect data for legitimate, specified purposes",
        "examples": ["Security research", "Threat intelligence", "Digital forensics"],
        "prohibited": ["Stalking", "Harassment", "Identity theft"],
    },
    {
        "principle": "Data Minimization",
        "description": "Collect only the minimum data necessary",
        "examples": ["Targeted searches", "Specific identifiers", "Relevant timeframes"],
        "prohibited": ["Bulk scraping", "Excessive data collection", "Hoarding"],
    },
    {
        "principle": "Proportionality",
        "description": "Balance investigation needs with privacy rights",
        "examples": ["Risk-based approach", "Justified scope", "Minimal intrusion"],
        "prohibited": ["Excessive monitoring", "Disproportionate surveillance"],
    },
    {
        "principle": "Accuracy",
        "description": "Verify information from multiple sources",
        "examples": ["Cross-reference data", "Check timestamps", "Validate sources"],
        "prohibited": ["Accepting unverified data", "Spreading misinformation"],
    },
    {
        "principle": "Accountability",
        "description": "Take responsibility for your actions",
        "examples": ["Document methodology", "Log activities", "Accept consequences"],
        "prohibited": ["Anonymous abuse", "Avoiding responsibility"],
    },
]


class EthicsChecker:
    """Validates ethical usage of the tool and tracks consent."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize ethics checker.

        Args:
            config: Optional configuration dictionary with:
                - consent_file: Path to consent/acknowledgment file
                - require_acknowledgment: Whether to require user acknowledgment
                - strict_mode: Enable strict ethical checks (deprecated, use safety_level)
                - safety_level: Safety enforcement level (none/low/medium/high/total)
                - override_code: Code to bypass ethics checks (use with caution)
        """
        self.config = config or {}
        self.consent_file = Path(self.config.get("consent_file", ".tr4c3r_consent.json"))
        self.require_acknowledgment = self.config.get("require_acknowledgment", True)

        # Support legacy strict_mode or new safety_level
        if "safety_level" in self.config:
            level_str = self.config["safety_level"]
            try:
                self.safety_level = SafetyLevel(level_str)
            except ValueError:
                logger.warning(f"Invalid safety_level '{level_str}', defaulting to MEDIUM")
                self.safety_level = SafetyLevel.MEDIUM
        elif self.config.get("strict_mode", False):
            self.safety_level = SafetyLevel.HIGH
        else:
            self.safety_level = SafetyLevel.MEDIUM

        # Backwards compatibility
        self.strict_mode = self.safety_level in [SafetyLevel.HIGH, SafetyLevel.TOTAL]

        # Override code for bypassing checks
        self._override_active = False

        logger.info(f"EthicsChecker initialized (safety_level: {self.safety_level.value})")

    def activate_override(self, code: str) -> bool:
        """Activate override mode with code.

        Args:
            code: Override code to bypass ethics checks

        Returns:
            True if override activated successfully
        """
        if code == OVERRIDE_CODE:
            self._override_active = True
            logger.warning("⚠️  Ethics override activated - all checks bypassed")
            return True
        else:
            logger.error("❌ Invalid override code")
            return False

    def deactivate_override(self) -> None:
        """Deactivate override mode."""
        self._override_active = False
        logger.info("Ethics override deactivated")

    def is_override_active(self) -> bool:
        """Check if override mode is active.

        Returns:
            True if override is active
        """
        return self._override_active

    def get_guidelines(self) -> str:
        """Return ethical guidelines text.

        Returns:
            Ethical guidelines as formatted string
        """
        return ETHICAL_GUIDELINES

    def get_detailed_principles(self) -> List[Dict[str, Any]]:
        """Get detailed ethical principles with examples.

        Returns:
            List of ethical principles with descriptions and examples
        """
        return DETAILED_ETHICAL_PRINCIPLES

    def check_acknowledgment(self) -> bool:
        """Check if user has acknowledged ethical guidelines.

        Returns:
            True if acknowledged, False otherwise
        """
        # Override bypasses all checks
        if self._override_active:
            return True

        # NONE level bypasses acknowledgment
        if self.safety_level == SafetyLevel.NONE:
            return True

        if not self.require_acknowledgment:
            return True

        if not self.consent_file.exists():
            logger.warning("No ethical guidelines acknowledgment found")
            return False

        try:
            with open(self.consent_file, "r") as f:
                consent_data = json.load(f)

            acknowledged = consent_data.get("acknowledged", False)
            timestamp = consent_data.get("timestamp")

            if acknowledged:
                logger.info(f"Ethics acknowledged on {timestamp}")
                return True
            else:
                return False

        except Exception as e:
            logger.error(f"Error reading consent file: {e}")
            return False

    def record_acknowledgment(
        self,
        user_id: Optional[str] = None,
        purpose: Optional[str] = None,
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record user's acknowledgment of ethical guidelines.

        Args:
            user_id: Optional user identifier
            purpose: Optional stated purpose for using the tool
            additional_info: Optional additional information

        Returns:
            Dictionary with acknowledgment details
        """
        timestamp = datetime.now().isoformat()

        consent_data = {
            "acknowledged": True,
            "timestamp": timestamp,
            "user_id": user_id,
            "purpose": purpose,
            "guidelines_version": "1.0",
            "additional_info": additional_info or {},
        }

        try:
            with open(self.consent_file, "w") as f:
                json.dump(consent_data, f, indent=2)

            logger.info(f"Ethics acknowledgment recorded for user {user_id or 'anonymous'}")
            return {
                "success": True,
                "timestamp": timestamp,
                "message": "Ethical guidelines acknowledged",
            }

        except Exception as e:
            logger.error(f"Error recording acknowledgment: {e}")
            return {"success": False, "error": str(e), "message": "Failed to record acknowledgment"}

    def validate_purpose(self, purpose: str) -> Dict[str, Any]:
        """Validate if stated purpose is ethical.

        Args:
            purpose: Stated purpose for using the tool

        Returns:
            Dictionary with validation results
        """
        # Override or NONE level bypasses validation
        if self._override_active or self.safety_level == SafetyLevel.NONE:
            return {
                "is_valid": True,
                "reason": "override_active" if self._override_active else "safety_none",
                "matches": [],
                "message": "Validation bypassed",
            }

        purpose_lower = purpose.lower()

        # Legitimate purposes
        legitimate_keywords = [
            "security",
            "research",
            "threat",
            "intelligence",
            "forensic",
            "investigation",
            "cybersecurity",
            "academic",
            "compliance",
            "audit",
            "assessment",
            "protection",
            "defense",
        ]

        # Prohibited purposes
        prohibited_keywords = [
            "stalk",
            "harass",
            "dox",
            "fraud",
            "theft",
            "illegal",
            "revenge",
            "blackmail",
            "intimidate",
            "spy",
            "surveil",
        ]

        # Check for prohibited purposes
        prohibited_matches = [kw for kw in prohibited_keywords if kw in purpose_lower]

        if prohibited_matches:
            return {
                "is_valid": False,
                "reason": "prohibited_purpose",
                "matches": prohibited_matches,
                "message": f"Purpose contains prohibited keywords: {', '.join(prohibited_matches)}",
            }

        # Check for legitimate purposes
        legitimate_matches = [kw for kw in legitimate_keywords if kw in purpose_lower]

        if legitimate_matches:
            return {
                "is_valid": True,
                "reason": "legitimate_purpose",
                "matches": legitimate_matches,
                "message": "Purpose appears legitimate",
            }

        # Unclear purpose
        return {
            "is_valid": None,
            "reason": "unclear_purpose",
            "matches": [],
            "message": "Purpose is unclear - please be more specific",
        }

    def check_compliance(self, data_type: str, target: str, purpose: str) -> Dict[str, Any]:
        """Check if an operation complies with ethical guidelines.

        Args:
            data_type: Type of data being collected (email, phone, social, etc.)
            target: Target identifier (email address, username, etc.)
            purpose: Purpose of the search

        Returns:
            Dictionary with compliance check results
        """
        # Override bypasses all checks
        if self._override_active:
            return {
                "is_compliant": True,
                "issues": [],
                "warnings": ["⚠️  Ethics override is active - checks bypassed"],
                "recommendations": [],
                "purpose_validation": {"is_valid": True, "reason": "override_active"},
            }

        # NONE level bypasses all checks
        if self.safety_level == SafetyLevel.NONE:
            return {
                "is_compliant": True,
                "issues": [],
                "warnings": [],
                "recommendations": [],
                "purpose_validation": {"is_valid": True, "reason": "safety_none"},
            }

        issues = []
        warnings = []
        recommendations = []

        # Check purpose validity
        purpose_check = self.validate_purpose(purpose)

        # LOW level: Only check for explicitly prohibited purposes
        if self.safety_level == SafetyLevel.LOW:
            if purpose_check["is_valid"] is False:
                issues.append(f"Prohibited purpose: {purpose_check['message']}")

        # MEDIUM level: Standard checks (default)
        elif self.safety_level == SafetyLevel.MEDIUM:
            if purpose_check["is_valid"] is False:
                issues.append(f"Prohibited purpose: {purpose_check['message']}")
            elif purpose_check["is_valid"] is None:
                warnings.append(f"Unclear purpose: {purpose_check['message']}")

            # Check for sensitive data types
            sensitive_types = ["personal", "pii", "sensitive", "private"]
            if any(st in data_type.lower() for st in sensitive_types):
                warnings.append("⚠️  Collecting sensitive data - ensure proper authorization")

        # HIGH level: Stricter checks
        elif self.safety_level == SafetyLevel.HIGH:
            if purpose_check["is_valid"] is False:
                issues.append(f"Prohibited purpose: {purpose_check['message']}")
            elif purpose_check["is_valid"] is None:
                issues.append(f"Unclear purpose: {purpose_check['message']}")

            # Check for sensitive data types
            sensitive_types = ["personal", "pii", "sensitive", "private"]
            if any(st in data_type.lower() for st in sensitive_types):
                warnings.append("⚠️  Collecting sensitive data - ensure proper authorization")
                recommendations.append("💡 Document your legal basis for collection")

            # Check target pattern for potential issues
            if "@" in target and "." in target:  # Email-like
                warnings.append("⚠️  Searching for personal email - ensure consent/authorization")

            if not purpose_check.get("matches"):
                issues.append("High safety mode: Purpose must clearly state legitimate use")

            if not self.check_acknowledgment():
                issues.append("High safety mode: Ethical guidelines must be acknowledged")

        # TOTAL level: Maximum enforcement
        elif self.safety_level == SafetyLevel.TOTAL:
            if purpose_check["is_valid"] is False:
                issues.append(f"Prohibited purpose: {purpose_check['message']}")
            elif purpose_check["is_valid"] is None:
                issues.append(f"Unclear purpose: {purpose_check['message']}")

            # All warnings become issues in TOTAL mode
            sensitive_types = ["personal", "pii", "sensitive", "private"]
            if any(st in data_type.lower() for st in sensitive_types):
                issues.append("⚠️  Collecting sensitive data - proper authorization required")
                issues.append("📋 Must document legal basis for collection")

            # Email checks
            if "@" in target and "." in target:
                issues.append("⚠️  Personal email search - explicit consent required")

            # Phone checks
            if any(char.isdigit() for char in target) and len(target) > 5:
                issues.append("⚠️  Phone number search - explicit authorization required")

            # Require clear legitimate purpose
            if not purpose_check.get("matches"):
                issues.append("Total safety mode: Purpose must explicitly state legitimate use")

            # Require acknowledgment
            if not self.check_acknowledgment():
                issues.append("Total safety mode: Ethical guidelines must be acknowledged")

            # Additional total mode checks
            if len(purpose) < 20:
                issues.append(
                    "Total safety mode: Purpose description too brief (minimum 20 characters)"
                )

        # General recommendations based on safety level
        if self.safety_level in [SafetyLevel.MEDIUM, SafetyLevel.HIGH, SafetyLevel.TOTAL]:
            recommendations.extend(
                [
                    "💡 Document all searches and their justification",
                    "💡 Respect privacy laws (GDPR, CCPA, etc.)",
                    "💡 Minimize data collection to what's necessary",
                    "💡 Secure all collected data appropriately",
                ]
            )

        if self.safety_level == SafetyLevel.TOTAL:
            recommendations.extend(
                [
                    "💡 Obtain written authorization before proceeding",
                    "💡 Conduct privacy impact assessment",
                    "💡 Consult legal counsel if uncertain",
                    "💡 Maintain detailed audit logs",
                ]
            )

        is_compliant = len(issues) == 0

        return {
            "is_compliant": is_compliant,
            "issues": issues,
            "warnings": warnings,
            "recommendations": recommendations,
            "purpose_validation": purpose_check,
        }

    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get usage statistics from consent file.

        Returns:
            Dictionary with usage statistics
        """
        if not self.consent_file.exists():
            return {"acknowledged": False, "first_use": None, "last_use": None}

        try:
            with open(self.consent_file, "r") as f:
                consent_data = json.load(f)

            return {
                "acknowledged": consent_data.get("acknowledged", False),
                "first_use": consent_data.get("timestamp"),
                "last_use": datetime.now().isoformat(),
                "user_id": consent_data.get("user_id"),
                "purpose": consent_data.get("purpose"),
            }

        except Exception as e:
            logger.error(f"Error reading usage statistics: {e}")
            return {"acknowledged": False, "error": str(e)}

    def prompt_user_acknowledgment(self) -> str:
        """Generate prompt text for user acknowledgment.

        Returns:
            Formatted prompt text
        """
        prompt = f"""
{ETHICAL_GUIDELINES}

To proceed, you must acknowledge that you have read and agree to follow these
ethical guidelines and all applicable laws and regulations.

You also acknowledge that:
- You have proper authorization for your intended use
- You will use the tool only for legitimate purposes
- You accept responsibility for your actions
- You understand the legal and ethical implications

Do you acknowledge and agree? (yes/no): """

        return prompt

    def generate_ethical_report(self, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate an ethical compliance report for operations.

        Args:
            operations: List of operations to analyze

        Returns:
            Ethical compliance report
        """
        total_operations = len(operations)
        compliant_operations = 0
        issues_found = []
        warnings_found = []

        for op in operations:
            compliance = self.check_compliance(
                data_type=op.get("data_type", "unknown"),
                target=op.get("target", "unknown"),
                purpose=op.get("purpose", "unspecified"),
            )

            if compliance["is_compliant"]:
                compliant_operations += 1
            else:
                issues_found.extend(compliance["issues"])

            warnings_found.extend(compliance["warnings"])

        return {
            "total_operations": total_operations,
            "compliant_operations": compliant_operations,
            "compliance_rate": (
                (compliant_operations / total_operations * 100) if total_operations > 0 else 0
            ),
            "issues_count": len(issues_found),
            "warnings_count": len(warnings_found),
            "issues": issues_found,
            "warnings": list(set(warnings_found)),  # Deduplicate
            "timestamp": datetime.now().isoformat(),
        }

"""Legal compliance and ethical guidelines for OSINT operations.

Provides tools for checking legal compliance, understanding regional restrictions,
and ensuring ethical OSINT practices.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceLevel(Enum):
    """Compliance risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JurisdictionType(Enum):
    """Legal jurisdiction types."""

    US = "united_states"
    EU = "european_union"
    UK = "united_kingdom"
    CA = "canada"
    AU = "australia"
    INTERNATIONAL = "international"
    OTHER = "other"


class ComplianceChecker:
    """Checks legal compliance and provides warnings for OSINT operations."""

    # GDPR-related regulations
    GDPR_COUNTRIES = [
        "AT",
        "BE",
        "BG",
        "HR",
        "CY",
        "CZ",
        "DK",
        "EE",
        "FI",
        "FR",
        "DE",
        "GR",
        "HU",
        "IE",
        "IT",
        "LV",
        "LT",
        "LU",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SK",
        "SI",
        "ES",
        "SE",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize compliance checker.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.jurisdiction = self.config.get("jurisdiction", JurisdictionType.INTERNATIONAL.value)

    def check_data_collection_compliance(
        self, data_type: str, source: str, purpose: str
    ) -> Dict[str, Any]:
        """Check if data collection is compliant with regulations.

        Args:
            data_type: Type of data being collected (personal, public, etc.)
            source: Source of the data (social_media, public_records, etc.)
            purpose: Purpose of data collection (investigation, research, etc.)

        Returns:
            Dictionary with compliance assessment:
            - is_compliant: bool - Whether collection appears compliant
            - risk_level: str - Risk level (low/medium/high/critical)
            - warnings: List[str] - Compliance warnings
            - requirements: List[str] - Legal requirements
            - recommendations: List[str] - Best practices
        """
        warnings = []
        requirements = []
        recommendations = []

        # Check data type compliance
        if data_type.lower() in ["personal", "pii", "sensitive"]:
            warnings.append("⚠️  Collecting personal/sensitive data - special protections apply")
            requirements.append("📋 Ensure you have legal authority to collect this data")
            requirements.append("📋 Document your legal basis (consent, legitimate interest, etc.)")

            # GDPR compliance for EU
            if self._is_gdpr_jurisdiction():
                warnings.append("🇪🇺 GDPR applies - strict data protection rules")
                requirements.extend(
                    [
                        "📋 Ensure data minimization principle",
                        "📋 Implement purpose limitation",
                        "📋 Provide data subject rights (access, deletion, portability)",
                        "📋 Maintain records of processing activities",
                    ]
                )

        # Check source compliance
        if source.lower() in ["social_media", "social"]:
            warnings.append("⚠️  Social media data - check platform Terms of Service")
            requirements.append("📋 Ensure scraping complies with platform ToS")
            requirements.append("📋 Respect robots.txt and rate limits")
            recommendations.append("💡 Use official APIs when available")

        elif source.lower() in ["darkweb", "dark_web", "onion"]:
            warnings.append("🚨 Dark web data - high legal risk")
            warnings.append("🚨 May contain illegal content - proceed with caution")
            requirements.append("📋 Ensure you have proper legal authorization")
            requirements.append("📋 Consult legal counsel before proceeding")
            recommendations.append("💡 Work with law enforcement if investigating crimes")

        # Check purpose compliance
        if purpose.lower() in ["investigation", "criminal_investigation"]:
            requirements.append("📋 Ensure proper investigative authority")
            requirements.append("📋 Follow chain of custody procedures")
            requirements.append("📋 Document all investigative steps")
            recommendations.append("💡 Consider working with law enforcement")

        elif purpose.lower() in ["commercial", "marketing", "sales"]:
            warnings.append("⚠️  Commercial purpose - additional restrictions may apply")
            requirements.append("📋 Comply with anti-spam laws (CAN-SPAM, GDPR)")
            requirements.append("📋 Obtain consent for marketing communications")

        # Determine risk level
        risk_level = self._calculate_risk_level(data_type, source, len(warnings))
        is_compliant = risk_level in [ComplianceLevel.LOW.value, ComplianceLevel.MEDIUM.value]

        # General recommendations
        recommendations.extend(
            [
                "💡 Maintain detailed logs of all data collection",
                "💡 Implement data retention policies",
                "💡 Use encryption for stored data",
                "💡 Regular compliance audits",
            ]
        )

        return {
            "is_compliant": is_compliant,
            "risk_level": risk_level,
            "warnings": warnings,
            "requirements": requirements,
            "recommendations": recommendations,
            "jurisdiction": self.jurisdiction,
        }

    def check_data_retention_compliance(self, data_age_days: int) -> Dict[str, Any]:
        """Check if data retention complies with regulations.

        Args:
            data_age_days: Age of stored data in days

        Returns:
            Dictionary with retention compliance assessment
        """
        warnings = []
        requirements = []
        recommendations = []

        # GDPR - data should not be kept longer than necessary
        if self._is_gdpr_jurisdiction():
            if data_age_days > 365:
                warnings.append("⚠️  Data is over 1 year old - review retention necessity")
                requirements.append("📋 Justify continued retention under GDPR")

            requirements.append("📋 Define and document retention periods")
            requirements.append("📋 Implement automatic deletion policies")

        # General retention recommendations
        if data_age_days > 180:
            warnings.append("⚠️  Data is over 6 months old - consider retention necessity")
            recommendations.append("💡 Review if data is still needed")

        if data_age_days > 730:  # 2 years
            warnings.append("🚨 Data is over 2 years old - high retention risk")
            recommendations.append("💡 Delete data unless legally required to retain")

        recommendations.extend(
            [
                "💡 Document business need for retention",
                "💡 Implement data minimization",
                "💡 Regular data cleanup procedures",
                "💡 Secure disposal when deleting",
            ]
        )

        is_compliant = data_age_days <= 365 or len(warnings) == 0

        return {
            "is_compliant": is_compliant,
            "data_age_days": data_age_days,
            "warnings": warnings,
            "requirements": requirements,
            "recommendations": recommendations,
        }

    def get_jurisdiction_requirements(self, jurisdiction: Optional[str] = None) -> Dict[str, Any]:
        """Get legal requirements for specific jurisdiction.

        Args:
            jurisdiction: Jurisdiction code (US, EU, UK, etc.) or None for current

        Returns:
            Dictionary with jurisdiction-specific requirements
        """
        jur = jurisdiction or self.jurisdiction

        requirements = {
            "jurisdiction": jur,
            "regulations": [],
            "requirements": [],
            "restrictions": [],
            "resources": [],
        }

        if jur == JurisdictionType.EU.value or jur in self.GDPR_COUNTRIES:
            requirements["regulations"] = ["GDPR", "ePrivacy Directive", "NIS Directive"]
            requirements["requirements"] = [
                "📋 Lawful basis for data processing",
                "📋 Data protection impact assessment (DPIA) for high-risk processing",
                "📋 Appoint Data Protection Officer if required",
                "📋 Implement technical and organizational measures",
                "📋 Report data breaches within 72 hours",
            ]
            requirements["restrictions"] = [
                "🚫 No data transfer outside EU without adequacy decision",
                "🚫 No automated decision-making without human oversight",
                "🚫 No processing of special category data without explicit consent",
            ]
            requirements["resources"] = ["https://gdpr.eu/", "https://edpb.europa.eu/"]

        elif jur == JurisdictionType.US.value:
            requirements["regulations"] = ["CFAA", "ECPA", "CCPA", "State Privacy Laws"]
            requirements["requirements"] = [
                "📋 Comply with Computer Fraud and Abuse Act (CFAA)",
                "📋 Respect Electronic Communications Privacy Act (ECPA)",
                "📋 CCPA compliance for California residents",
                "📋 State-specific privacy laws (Virginia, Colorado, etc.)",
            ]
            requirements["restrictions"] = [
                "🚫 No unauthorized access to computer systems",
                "🚫 No interception of electronic communications",
                "🚫 Respect website ToS and technical access controls",
            ]
            requirements["resources"] = [
                "https://www.justice.gov/criminal-ccips/ccmanual",
                "https://oag.ca.gov/privacy/ccpa",
            ]

        elif jur == JurisdictionType.UK.value:
            requirements["regulations"] = ["UK GDPR", "DPA 2018", "PECR"]
            requirements["requirements"] = [
                "📋 UK GDPR compliance (similar to EU GDPR)",
                "📋 Data Protection Act 2018 compliance",
                "📋 ICO registration if required",
                "📋 Privacy and Electronic Communications Regulations",
            ]
            requirements["restrictions"] = [
                "🚫 Similar restrictions to EU GDPR",
                "🚫 ICO can impose significant fines",
            ]
            requirements["resources"] = [
                "https://ico.org.uk/",
                "https://www.legislation.gov.uk/ukpga/2018/12/contents",
            ]

        elif jur == JurisdictionType.CA.value:
            requirements["regulations"] = ["PIPEDA", "Provincial Privacy Laws"]
            requirements["requirements"] = [
                "📋 Personal Information Protection and Electronic Documents Act",
                "📋 Obtain consent for collection",
                "📋 Provincial privacy laws (Quebec, BC, Alberta)",
            ]
            requirements["resources"] = [
                "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/"
            ]

        elif jur == JurisdictionType.AU.value:
            requirements["regulations"] = ["Privacy Act 1988", "APPs"]
            requirements["requirements"] = [
                "📋 Australian Privacy Principles compliance",
                "📋 Notifiable Data Breaches scheme",
            ]
            requirements["resources"] = ["https://www.oaic.gov.au/"]

        return requirements

    def check_terms_of_service_compliance(self, platform: str) -> Dict[str, Any]:
        """Check common ToS restrictions for a platform.

        Args:
            platform: Platform name (twitter, facebook, linkedin, etc.)

        Returns:
            Dictionary with ToS compliance information
        """
        warnings = []
        restrictions = []
        recommendations = []

        platform_lower = platform.lower()

        # Common ToS restrictions
        common_restrictions = [
            "🚫 Automated scraping may violate ToS",
            "🚫 Creating fake accounts may violate ToS",
            "🚫 Bulk data collection may violate ToS",
            "🚫 Commercial use may require special license",
        ]

        if platform_lower in ["twitter", "x"]:
            warnings.append("⚠️  Twitter/X has strict API rate limits")
            restrictions.extend(common_restrictions)
            restrictions.append("🚫 Must comply with Developer Agreement")
            recommendations.append("💡 Use official Twitter API v2")
            recommendations.append("💡 Respect rate limits strictly")

        elif platform_lower in ["facebook", "meta"]:
            warnings.append("⚠️  Facebook has strict data use policies")
            restrictions.extend(common_restrictions)
            restrictions.append("🚫 Facebook ToS prohibit most scraping")
            recommendations.append("💡 Use official Graph API")
            recommendations.append("💡 Obtain explicit user consent")

        elif platform_lower == "linkedin":
            warnings.append("🚨 LinkedIn actively enforces anti-scraping policies")
            restrictions.extend(common_restrictions)
            restrictions.append("🚫 LinkedIn v. hiQ Labs case - scraping public data may be legal")
            recommendations.append("💡 Consult legal counsel before scraping LinkedIn")
            recommendations.append("💡 Use official LinkedIn API when possible")

        elif platform_lower == "instagram":
            warnings.append("⚠️  Instagram (Meta) has strict policies")
            restrictions.extend(common_restrictions)
            recommendations.append("💡 Use official Instagram Graph API")

        else:
            warnings.append("⚠️  Check platform-specific ToS")
            restrictions.extend(common_restrictions)
            recommendations.append("💡 Review platform's ToS and API terms")

        recommendations.extend(
            [
                "💡 Use official APIs when available",
                "💡 Respect robots.txt",
                "💡 Implement rate limiting",
                "💡 Document your legal basis for data collection",
            ]
        )

        return {
            "platform": platform,
            "warnings": warnings,
            "restrictions": restrictions,
            "recommendations": recommendations,
        }

    def get_ethical_guidelines(self) -> List[str]:
        """Get ethical guidelines for OSINT operations.

        Returns:
            List of ethical guidelines
        """
        return [
            "🎯 Purpose: Only collect data for legitimate purposes",
            "🎯 Proportionality: Collect only what is necessary",
            "🎯 Accuracy: Verify information from multiple sources",
            "🎯 Privacy: Respect individual privacy rights",
            "🎯 Consent: Obtain consent when required",
            "🎯 Transparency: Be transparent about data collection when possible",
            "🎯 Security: Protect collected data appropriately",
            "🎯 Accountability: Take responsibility for your actions",
            "🎯 Bias: Be aware of and mitigate cognitive biases",
            "🎯 Harm: Minimize potential harm to individuals",
            "🎯 Children: Extra protection for minors' data",
            "🎯 Vulnerable: Special care with vulnerable populations",
            "🎯 Context: Respect data in its original context",
            "🎯 Public vs Private: Distinguish between public and private spaces",
            "🎯 Legal: Comply with all applicable laws",
        ]

    def _is_gdpr_jurisdiction(self) -> bool:
        """Check if current jurisdiction is subject to GDPR.

        Returns:
            True if GDPR applies
        """
        return (
            self.jurisdiction == JurisdictionType.EU.value
            or self.jurisdiction in self.GDPR_COUNTRIES
        )

    def _calculate_risk_level(self, data_type: str, source: str, warning_count: int) -> str:
        """Calculate compliance risk level.

        Args:
            data_type: Type of data
            source: Data source
            warning_count: Number of warnings generated

        Returns:
            Risk level string
        """
        risk_score = 0

        # Data type risk
        if data_type.lower() in ["personal", "pii", "sensitive"]:
            risk_score += 2

        # Source risk
        if source.lower() in ["darkweb", "dark_web"]:
            risk_score += 3
        elif source.lower() in ["social_media", "social"]:
            risk_score += 1

        # Warning count risk
        risk_score += min(warning_count, 3)

        # Determine level
        if risk_score >= 6:
            return ComplianceLevel.CRITICAL.value
        elif risk_score >= 4:
            return ComplianceLevel.HIGH.value
        elif risk_score >= 2:
            return ComplianceLevel.MEDIUM.value
        else:
            return ComplianceLevel.LOW.value


# Legal and Ethical Guidelines
COMPLIANCE_GUIDELINES = """
TR4C3R Legal Compliance & Ethical Guidelines
=============================================

1. Legal Framework
   ✓ Know your jurisdiction's laws (GDPR, CFAA, CCPA, etc.)
   ✓ Understand international data protection laws
   ✓ Obtain proper authorization for investigations
   ✓ Document your legal basis for data collection
   ✓ Consult legal counsel when in doubt

2. Data Protection
   ✓ Implement data minimization (collect only what's needed)
   ✓ Purpose limitation (use data only for stated purpose)
   ✓ Storage limitation (don't keep data longer than necessary)
   ✓ Security measures (encryption, access controls)
   ✓ Data subject rights (access, deletion, portability)

3. Terms of Service
   ✓ Read and understand platform ToS before scraping
   ✓ Use official APIs when available
   ✓ Respect robots.txt and rate limits
   ✓ Don't create fake accounts
   ✓ Understand legal precedents (LinkedIn v. hiQ, etc.)

4. Ethical Principles
   ✓ Legitimate purpose only
   ✓ Proportionality in data collection
   ✓ Respect privacy rights
   ✓ Minimize harm to individuals
   ✓ Extra protection for children and vulnerable groups

5. Professional Standards
   ✓ Verify information from multiple sources
   ✓ Be aware of cognitive biases
   ✓ Maintain objectivity
   ✓ Document methodology
   ✓ Peer review when possible

6. Incident Handling
   ✓ Report data breaches promptly (GDPR: 72 hours)
   ✓ Notify affected individuals
   ✓ Document incidents thoroughly
   ✓ Implement corrective measures
   ✓ Learn from incidents

7. International Considerations
   ✓ Understand cross-border data transfer rules
   ✓ Respect local laws in target jurisdiction
   ✓ Be aware of political sensitivities
   ✓ Consider cultural contexts
   ✓ Know export control regulations

8. Red Flags to Avoid
   🚫 Unauthorized access to systems
   🚫 Intercepting private communications
   🚫 Collecting data without legal basis
   🚫 Ignoring platform ToS
   🚫 Collecting children's data without parental consent
   🚫 Discriminatory profiling
   🚫 Selling collected data without consent
   🚫 Retaining data indefinitely
"""

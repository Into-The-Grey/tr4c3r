"""API security validation and best practices.

Provides tools for validating API key security, detecting insecure configurations,
and recommending best practices for credential management.
"""

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)


class APISecurityValidator:
    """Validates API key security and provides recommendations."""

    # Patterns for detecting API keys in code
    API_KEY_PATTERNS = [
        r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
        r'apikey\s*=\s*["\']([^"\']+)["\']',
        r'api[_-]?secret\s*=\s*["\']([^"\']+)["\']',
        r'access[_-]?token\s*=\s*["\']([^"\']+)["\']',
        r'auth[_-]?token\s*=\s*["\']([^"\']+)["\']',
        r'password\s*=\s*["\']([^"\']+)["\']',
        r"bearer\s+([A-Za-z0-9\-_\.]+)",
    ]

    # Files that should never contain API keys
    DANGEROUS_FILES = [
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".md",
        ".txt",
        ".sh",
        ".bash",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize API security validator.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}

    def validate_environment_variables(self) -> Dict[str, Any]:
        """Validate that API keys are stored in environment variables.

        Returns:
            Dictionary with validation results:
            - is_valid: bool - Whether configuration is secure
            - issues: List[str] - List of security issues found
            - recommendations: List[str] - Security recommendations
            - keys_in_env: List[str] - API keys found in environment
        """
        logger.info("Validating environment variable security...")

        issues = []
        recommendations = []
        keys_in_env = []

        # Check for API keys in environment
        api_key_env_vars = [
            "GOOGLE_API_KEY",
            "TWITTER_API_KEY",
            "TWITTER_API_SECRET",
            "FACEBOOK_ACCESS_TOKEN",
            "INSTAGRAM_ACCESS_TOKEN",
            "LINKEDIN_ACCESS_TOKEN",
            "SHODAN_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "CENSYS_API_ID",
            "CENSYS_API_SECRET",
            "HIBP_API_KEY",
            "HAVEIBEENPWNED_API_KEY",
        ]

        for var in api_key_env_vars:
            if os.environ.get(var):
                keys_in_env.append(var)

        # Check if .env file exists
        env_file = Path(".env")
        if env_file.exists():
            recommendations.append("✅ .env file found - ensure it's in .gitignore")

            # Check if .env is in .gitignore
            gitignore = Path(".gitignore")
            if gitignore.exists():
                gitignore_content = gitignore.read_text()
                if ".env" not in gitignore_content:
                    issues.append("⚠️  .env file not in .gitignore - risk of credential leak")
                    recommendations.append("💡 Add .env to .gitignore immediately")
            else:
                issues.append("⚠️  No .gitignore file found")
                recommendations.append("💡 Create .gitignore and add .env to it")
        else:
            recommendations.append("💡 Consider creating .env file for API keys")

        # General recommendations
        recommendations.extend(
            [
                "🔒 Store all API keys in environment variables",
                "🔒 Use different keys for development and production",
                "🔒 Rotate API keys regularly (every 90 days)",
                "🔒 Use key management services (AWS KMS, HashiCorp Vault) for production",
                "🔒 Never commit API keys to version control",
            ]
        )

        is_valid = len(issues) == 0

        return {
            "is_valid": is_valid,
            "issues": issues,
            "recommendations": recommendations,
            "keys_in_env": keys_in_env,
            "env_file_exists": env_file.exists(),
        }

    def scan_for_hardcoded_secrets(self, directory: str = ".") -> Dict[str, Any]:
        """Scan source code for hardcoded API keys and secrets.

        Args:
            directory: Directory to scan (default: current directory)

        Returns:
            Dictionary with scan results:
            - files_scanned: int - Number of files scanned
            - secrets_found: int - Number of potential secrets found
            - vulnerable_files: List[Dict] - Files with potential secrets
            - severity: str - Overall severity (low/medium/high/critical)
        """
        logger.info(f"Scanning for hardcoded secrets in {directory}...")

        vulnerable_files = []
        files_scanned = 0
        secrets_found = 0

        try:
            path = Path(directory)

            # Scan source files
            for file_path in path.rglob("*"):
                # Skip directories and non-text files
                if file_path.is_dir():
                    continue

                # Check if file extension is dangerous
                if not any(file_path.suffix == ext for ext in self.DANGEROUS_FILES):
                    continue

                # Skip test files and dependencies
                if (
                    "test" in str(file_path)
                    or "node_modules" in str(file_path)
                    or ".venv" in str(file_path)
                ):
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    files_scanned += 1

                    # Check for API key patterns
                    matches = []
                    for pattern in self.API_KEY_PATTERNS:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            matches.append(
                                {
                                    "pattern": pattern,
                                    "match": match.group(0),
                                    "line": content[: match.start()].count("\n") + 1,
                                }
                            )
                            secrets_found += 1

                    if matches:
                        vulnerable_files.append(
                            {
                                "file": str(file_path),
                                "matches": matches,
                                "match_count": len(matches),
                            }
                        )

                except Exception as e:
                    logger.debug(f"Could not read {file_path}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
            return {
                "files_scanned": 0,
                "secrets_found": 0,
                "vulnerable_files": [],
                "severity": "unknown",
                "error": str(e),
            }

        # Determine severity
        if secrets_found == 0:
            severity = "low"
        elif secrets_found <= 5:
            severity = "medium"
        elif secrets_found <= 10:
            severity = "high"
        else:
            severity = "critical"

        return {
            "files_scanned": files_scanned,
            "secrets_found": secrets_found,
            "vulnerable_files": vulnerable_files,
            "severity": severity,
        }

    def validate_api_key_format(self, api_key: str, key_type: str = "generic") -> Dict[str, Any]:
        """Validate API key format and strength.

        Args:
            api_key: The API key to validate
            key_type: Type of API key (generic, jwt, oauth, etc.)

        Returns:
            Dictionary with validation results:
            - is_valid: bool - Whether key format is valid
            - strength: str - Key strength (weak/medium/strong)
            - issues: List[str] - Format issues
            - recommendations: List[str] - Improvement recommendations
        """
        issues = []
        recommendations = []

        # Check key length
        if len(api_key) < 16:
            issues.append("⚠️  API key is too short (< 16 characters)")
            recommendations.append("💡 Use keys with at least 32 characters")

        # Check for common weak patterns
        if api_key.lower() in ["test", "demo", "example", "sample", "default"]:
            issues.append("🚨 API key appears to be a placeholder/test key")
            recommendations.append("💡 Replace with actual production key")

        # Check character diversity
        has_upper = any(c.isupper() for c in api_key)
        has_lower = any(c.islower() for c in api_key)
        has_digit = any(c.isdigit() for c in api_key)
        has_special = any(not c.isalnum() for c in api_key)

        diversity_score = sum([has_upper, has_lower, has_digit, has_special])

        if diversity_score < 2:
            issues.append("⚠️  API key has low character diversity")
            recommendations.append(
                "💡 Keys should contain uppercase, lowercase, digits, and symbols"
            )

        # Determine strength
        if len(api_key) < 16 or diversity_score < 2:
            strength = "weak"
        elif len(api_key) >= 32 and diversity_score >= 3:
            strength = "strong"
        else:
            strength = "medium"

        is_valid = len(issues) == 0

        # Add general recommendations
        if not is_valid:
            recommendations.append("🔒 Generate new key using cryptographically secure method")
            recommendations.append("🔒 Store key in environment variable or key vault")

        return {
            "is_valid": is_valid,
            "strength": strength,
            "issues": issues,
            "recommendations": recommendations,
            "length": len(api_key),
            "diversity_score": diversity_score,
        }

    def get_key_rotation_recommendations(self, key_age_days: int = 0) -> List[str]:
        """Get API key rotation recommendations based on key age.

        Args:
            key_age_days: Age of the API key in days

        Returns:
            List of rotation recommendations
        """
        recommendations = []

        if key_age_days == 0:
            recommendations.append("📅 Track API key creation date for rotation scheduling")
        elif key_age_days > 365:
            recommendations.append("🚨 API key is over 1 year old - rotate immediately")
            recommendations.append("💡 Implement automated key rotation")
        elif key_age_days > 180:
            recommendations.append("⚠️  API key is over 6 months old - consider rotating")
        elif key_age_days > 90:
            recommendations.append("💡 API key is over 90 days old - plan rotation soon")
        else:
            recommendations.append("✅ API key age is within acceptable range")

        # General rotation recommendations
        recommendations.extend(
            [
                "🔒 Rotate keys every 90 days for high-security applications",
                "🔒 Rotate keys immediately if compromise is suspected",
                "🔒 Use multiple keys and rotate them on a staggered schedule",
                "🔒 Test new keys in staging before production rotation",
                "🔒 Keep old keys valid for 24-48h during rotation",
            ]
        )

        return recommendations

    def check_secure_storage(self) -> Dict[str, Any]:
        """Check if API keys are stored securely.

        Returns:
            Dictionary with storage security assessment:
            - is_secure: bool - Whether storage is secure
            - storage_method: str - Detected storage method
            - issues: List[str] - Security issues
            - recommendations: List[str] - Improvements
        """
        issues = []
        recommendations = []
        storage_methods = []

        # Check for environment variables
        if any(key.endswith("_API_KEY") or key.endswith("_TOKEN") for key in os.environ):
            storage_methods.append("environment_variables")
            recommendations.append("✅ Using environment variables - good practice")

        # Check for .env file
        if Path(".env").exists():
            storage_methods.append("dotenv_file")
            recommendations.append("✅ .env file found - ensure proper permissions (600)")

            # Check file permissions
            try:
                env_stat = Path(".env").stat()
                if oct(env_stat.st_mode)[-3:] != "600":
                    issues.append("⚠️  .env file has overly permissive permissions")
                    recommendations.append("💡 Set .env permissions to 600 (chmod 600 .env)")
            except Exception as e:
                logger.debug(f"Could not check .env permissions: {e}")

        # Check for config files
        config_files = ["config.yaml", "config.yml", "config.json", "settings.py"]
        for config_file in config_files:
            if Path(config_file).exists():
                storage_methods.append(f"config_file_{config_file}")
                issues.append(f"⚠️  Config file {config_file} may contain secrets")
                recommendations.append(f"💡 Ensure {config_file} uses environment variables")

        # General recommendations
        recommendations.extend(
            [
                "🔒 Use key management services for production (AWS KMS, Azure Key Vault)",
                "🔒 Implement least-privilege access to secrets",
                "🔒 Audit secret access regularly",
                "🔒 Use encrypted secrets in CI/CD pipelines",
                "🔒 Never log API keys or tokens",
            ]
        )

        is_secure = len(issues) == 0 and len(storage_methods) > 0
        storage_method = ", ".join(storage_methods) if storage_methods else "unknown"

        return {
            "is_secure": is_secure,
            "storage_method": storage_method,
            "issues": issues,
            "recommendations": recommendations,
        }


# API Security Best Practices
API_SECURITY_BEST_PRACTICES = """
TR4C3R API Security Best Practices
===================================

1. Key Storage
   ✓ Store all API keys in environment variables
   ✓ Use .env file for local development (add to .gitignore)
   ✓ Use key management services in production (AWS KMS, Azure Key Vault)
   ✓ Never hardcode keys in source code
   ✓ Set restrictive file permissions (chmod 600 .env)

2. Key Rotation
   ✓ Rotate keys every 90 days minimum
   ✓ Rotate immediately if compromise suspected
   ✓ Use multiple keys with staggered rotation
   ✓ Test new keys before production deployment
   ✓ Maintain key rotation logs

3. Access Control
   ✓ Use separate keys for different environments (dev/staging/prod)
   ✓ Implement least-privilege access
   ✓ Use API key scoping when available
   ✓ Restrict keys to specific IP addresses when possible
   ✓ Monitor key usage patterns

4. Key Generation
   ✓ Use cryptographically secure random generation
   ✓ Minimum 32 characters length
   ✓ Include uppercase, lowercase, digits, and symbols
   ✓ Avoid predictable patterns
   ✓ Use provider-generated keys when available

5. Monitoring & Auditing
   ✓ Log all API key usage
   ✓ Set up alerts for unusual activity
   ✓ Regular security audits
   ✓ Track key age and rotation status
   ✓ Monitor for leaked keys (GitHub, GitLab scanners)

6. Incident Response
   ✓ Have key revocation procedure ready
   ✓ Rotate compromised keys immediately
   ✓ Investigate scope of compromise
   ✓ Notify affected parties if needed
   ✓ Document incidents for future prevention
"""

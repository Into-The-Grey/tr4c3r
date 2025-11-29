"""Configuration management system for TR4C3R.

This module provides centralized configuration loading from multiple sources:
- YAML/TOML configuration files
- Environment variables (.env)
- Default values

Includes validation to ensure configuration values are correct.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore

import yaml
from dotenv import load_dotenv


@dataclass
class ValidationResult:
    """Result of configuration validation."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    missing_api_keys: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        """Add an error message."""
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)

    def __str__(self) -> str:
        """Format validation result as string."""
        lines = []
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"  - {e}" for e in self.errors)
        if self.warnings:
            lines.append("Warnings:")
            lines.extend(f"  - {w}" for w in self.warnings)
        if self.missing_api_keys:
            lines.append("Missing API keys (optional):")
            lines.extend(f"  - {k}" for k in self.missing_api_keys)
        if not lines:
            return "Configuration is valid."
        return "\n".join(lines)


class Config:
    """Configuration manager for TR4C3R."""

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_file: Path to YAML or TOML config file (optional)
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._config: Dict[str, Any] = {}

        # Load .env file if it exists
        env_path = Path(".env")
        if env_path.exists():
            load_dotenv(env_path)
            self.logger.info("Loaded environment variables from .env")

        # Load configuration file if provided
        if config_file:
            self._load_config_file(config_file)
        else:
            # Try to find config file automatically
            self._auto_load_config()

        # Load defaults
        self._load_defaults()

    def _load_config_file(self, config_file: str) -> None:
        """Load configuration from YAML or TOML file."""
        config_path = Path(config_file)

        if not config_path.exists():
            self.logger.warning(f"Config file not found: {config_file}")
            return

        try:
            with open(config_path, "rb") as f:
                if config_file.endswith((".yaml", ".yml")):
                    self._config = yaml.safe_load(f)
                    self.logger.info(f"Loaded YAML config from {config_file}")
                elif config_file.endswith(".toml"):
                    self._config = tomllib.load(f)
                    self.logger.info(f"Loaded TOML config from {config_file}")
                else:
                    self.logger.error(f"Unsupported config format: {config_file}")
        except Exception as e:
            self.logger.error(f"Failed to load config file {config_file}: {e}")

    def _auto_load_config(self) -> None:
        """Automatically find and load config file."""
        config_dir = Path("config")

        # Try different config file names
        candidates = [
            config_dir / "tr4c3r.yaml",
            config_dir / "tr4c3r.yml",
            config_dir / "tr4c3r.toml",
            Path("tr4c3r.yaml"),
            Path("tr4c3r.yml"),
            Path("tr4c3r.toml"),
        ]

        for candidate in candidates:
            if candidate.exists():
                self._load_config_file(str(candidate))
                return

        self.logger.debug("No config file found, using defaults and environment variables")

    def _load_defaults(self) -> None:
        """Load default configuration values."""
        defaults = {
            "logging": {
                "level": "INFO",
                "file": "logs/tr4c3r.log",
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            },
            "search": {
                "max_variants": 50,
                "timeout_seconds": 30,
                "max_concurrent_requests": 10,
                "user_agent": "TR4C3R OSINT Tool/1.0",
            },
            "database": {"path": "tr4c3r.db", "cache_ttl_seconds": 3600},
            "api_keys": {
                "github_token": "",
                "reddit_user_agent": "",
                "hibp_api_key": "",
                "hunter_api_key": "",
                "numverify_api_key": "",
                "pipl_api_key": "",
                "clearbit_api_key": "",
                "twilio_account_sid": "",
                "twilio_auth_token": "",
            },
            "sites": {
                "github": {
                    "enabled": True,
                    "url_template": "https://github.com/{username}",
                    "api_url": "https://api.github.com/users/{username}",
                },
                "reddit": {
                    "enabled": True,
                    "url_template": "https://www.reddit.com/user/{username}",
                },
                "twitter": {"enabled": True, "url_template": "https://twitter.com/{username}"},
                "instagram": {
                    "enabled": True,
                    "url_template": "https://www.instagram.com/{username}",
                },
                "linkedin": {
                    "enabled": True,
                    "url_template": "https://www.linkedin.com/in/{username}",
                },
            },
            "correlation": {"min_confidence": 0.5, "max_depth": 3, "enable_visualization": True},
        }

        # Merge defaults with loaded config (loaded config takes precedence)
        for key, value in defaults.items():
            if key not in self._config:
                self._config[key] = value
            elif isinstance(value, dict):
                # Deep merge for nested dicts
                self._config[key] = {**value, **self._config.get(key, {})}

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.

        Supports dot notation for nested keys: "logging.level"

        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        # First check environment variables (highest priority)
        env_key = key.upper().replace(".", "_")
        env_value = os.getenv(env_key)
        if env_value is not None:
            return env_value

        # Then check config file
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value at runtime.

        Supports dot notation for nested keys: "logging.level"

        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split(".")
        config = self._config

        # Navigate to the parent dict
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        # Set the value
        config[keys[-1]] = value
        self.logger.debug(f"Set config {key} = {value}")

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.

        Args:
            section: Section name (e.g., "logging", "api_keys")

        Returns:
            Dictionary with section configuration
        """
        return self._config.get(section, {})

    def get_api_key(self, service: str) -> str:
        """
        Get API key for a service.

        Args:
            service: Service name (e.g., "github", "hibp")

        Returns:
            API key or empty string if not configured
        """
        # Try environment variable first
        env_key = f"{service.upper()}_API_KEY"
        if not env_key.endswith("_KEY"):
            # Try alternate formats
            env_key_token = f"{service.upper()}_TOKEN"
            env_value = os.getenv(env_key, os.getenv(env_key_token, ""))
        else:
            env_value = os.getenv(env_key, "")

        if env_value:
            return env_value

        # Then check config - try both formats
        api_key = self.get(f"api_keys.{service}_api_key", "")
        if not api_key:
            api_key = self.get(f"api_keys.{service}_token", "")

        return api_key

    def is_site_enabled(self, site_name: str) -> bool:
        """
        Check if a site is enabled for searching.

        Args:
            site_name: Site name (e.g., "github", "reddit")

        Returns:
            True if site is enabled
        """
        return self.get(f"sites.{site_name}.enabled", True)

    def get_site_config(self, site_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific site.

        Args:
            site_name: Site name (e.g., "github", "reddit")

        Returns:
            Site configuration dictionary
        """
        return self.get_section("sites").get(site_name, {})

    def to_dict(self) -> Dict[str, Any]:
        """
        Get all configuration as dictionary.

        Returns:
            Complete configuration dictionary
        """
        return self._config.copy()

    def reload(self, config_file: Optional[str] = None) -> None:
        """
        Reload configuration from file.

        Args:
            config_file: Path to config file (optional, uses original if not provided)
        """
        self._config = {}
        self._auto_load_config()
        self._load_defaults()
        if config_file:
            self._load_config_file(config_file)
        self.logger.info("Configuration reloaded")

    def validate(self) -> ValidationResult:
        """
        Validate the configuration.

        Checks:
        - Required sections exist
        - Value types are correct
        - Paths are valid
        - API keys are present (warnings for missing)

        Returns:
            ValidationResult with errors and warnings
        """
        result = ValidationResult(is_valid=True)

        # Validate logging configuration
        log_level = self.get("logging.level", "INFO")
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if log_level.upper() not in valid_levels:
            result.add_error(
                f"Invalid logging level '{log_level}'. Must be one of: {', '.join(valid_levels)}"
            )

        log_file = self.get("logging.file", "")
        if log_file:
            log_dir = Path(log_file).parent
            if not log_dir.exists():
                result.add_warning(f"Log directory does not exist: {log_dir}")

        # Validate search configuration
        max_variants = self.get("search.max_variants", 50)
        if not isinstance(max_variants, int) or max_variants < 1:
            result.add_error("search.max_variants must be a positive integer")

        timeout = self.get("search.timeout_seconds", 30)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            result.add_error("search.timeout_seconds must be a positive number")

        max_concurrent = self.get("search.max_concurrent_requests", 10)
        if not isinstance(max_concurrent, int) or max_concurrent < 1:
            result.add_error("search.max_concurrent_requests must be a positive integer")
        elif max_concurrent > 50:
            result.add_warning(
                f"search.max_concurrent_requests={max_concurrent} is high, "
                "may cause rate limiting"
            )

        # Validate database configuration
        db_path = self.get("database.path", "tr4c3r.db")
        if db_path:
            db_dir = Path(db_path).parent
            if db_dir and str(db_dir) != "." and not db_dir.exists():
                result.add_warning(f"Database directory does not exist: {db_dir}")

        cache_ttl = self.get("database.cache_ttl_seconds", 3600)
        if not isinstance(cache_ttl, int) or cache_ttl < 0:
            result.add_error("database.cache_ttl_seconds must be a non-negative integer")

        # Validate correlation configuration
        min_confidence = self.get("correlation.min_confidence", 0.5)
        if not isinstance(min_confidence, (int, float)) or not 0 <= min_confidence <= 1:
            result.add_error("correlation.min_confidence must be a number between 0 and 1")

        max_depth = self.get("correlation.max_depth", 3)
        if not isinstance(max_depth, int) or max_depth < 1:
            result.add_error("correlation.max_depth must be a positive integer")

        # Check API keys (warnings only - they're optional)
        api_key_services = [
            ("github", "GitHub API access"),
            ("hibp", "Have I Been Pwned breach checks"),
            ("hunter", "Hunter.io email verification"),
            ("numverify", "Phone number validation"),
            ("clearbit", "Company/person enrichment"),
        ]

        for service, description in api_key_services:
            key = self.get_api_key(service)
            if not key:
                result.missing_api_keys.append(f"{service}: {description}")

        # Log validation results
        if not result.is_valid:
            for error in result.errors:
                self.logger.error(f"Config validation error: {error}")
        for warning in result.warnings:
            self.logger.warning(f"Config validation warning: {warning}")

        return result

    def validate_and_raise(self) -> None:
        """
        Validate configuration and raise exception if invalid.

        Raises:
            ValueError: If configuration is invalid
        """
        result = self.validate()
        if not result.is_valid:
            raise ValueError(f"Invalid configuration:\n{result}")


# Global configuration instance
_global_config: Optional[Config] = None


def get_config(config_file: Optional[str] = None) -> Config:
    """
    Get global configuration instance.

    Args:
        config_file: Path to config file (only used on first call)

    Returns:
        Config instance
    """
    global _global_config

    if _global_config is None:
        _global_config = Config(config_file)

    return _global_config


def reload_config(config_file: Optional[str] = None) -> None:
    """
    Reload global configuration.

    Args:
        config_file: Path to config file (optional)
    """
    global _global_config

    if _global_config is not None:
        _global_config.reload(config_file)
    else:
        _global_config = Config(config_file)

"""Tests for the configuration system."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from src.core.config import Config, get_config, reload_config


class TestConfig:
    """Test the Config class."""

    @pytest.fixture
    def temp_yaml_config(self) -> str:
        """Create a temporary YAML config file."""
        config_data = {
            "logging": {"level": "DEBUG", "file": "test.log"},
            "search": {"max_variants": 100, "timeout_seconds": 60},
            "api_keys": {"github_token": "test_token_123"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        yield temp_path

        # Cleanup
        Path(temp_path).unlink(missing_ok=True)

    def test_config_initialization(self) -> None:
        """Test that config initializes with defaults."""
        config = Config()

        assert config.get("logging.level") == "INFO"
        assert config.get("search.max_variants") == 50
        assert config.get("database.path") == "tr4c3r.db"

    def test_load_yaml_config(self, temp_yaml_config: str) -> None:
        """Test loading configuration from YAML file."""
        config = Config(temp_yaml_config)

        assert config.get("logging.level") == "DEBUG"
        assert config.get("logging.file") == "test.log"
        assert config.get("search.max_variants") == 100
        assert config.get("search.timeout_seconds") == 60

    def test_get_with_default(self) -> None:
        """Test getting config value with default."""
        config = Config()

        # Existing key
        assert config.get("logging.level", "DEFAULT") == "INFO"

        # Non-existing key
        assert config.get("nonexistent.key", "DEFAULT") == "DEFAULT"

    def test_set_config_value(self) -> None:
        """Test setting config value at runtime."""
        config = Config()

        config.set("logging.level", "ERROR")
        assert config.get("logging.level") == "ERROR"

        config.set("new.nested.value", "test")
        assert config.get("new.nested.value") == "test"

    def test_get_section(self) -> None:
        """Test getting entire config section."""
        config = Config()

        logging_config = config.get_section("logging")
        assert "level" in logging_config
        assert "file" in logging_config
        assert logging_config["level"] == "INFO"

    def test_environment_variable_override(self, monkeypatch) -> None:
        """Test that environment variables override config file."""
        # Set environment variable
        monkeypatch.setenv("LOGGING_LEVEL", "CRITICAL")

        config = Config()

        # Environment variable should take precedence
        assert config.get("logging.level") == "CRITICAL"

    def test_get_api_key(self, temp_yaml_config: str) -> None:
        """Test getting API keys."""
        config = Config(temp_yaml_config)

        # From config file
        assert config.get_api_key("github") == "test_token_123"

        # Non-existent
        assert config.get_api_key("nonexistent") == ""

    def test_get_api_key_from_env(self, monkeypatch) -> None:
        """Test getting API key from environment variable."""
        monkeypatch.setenv("HIBP_API_KEY", "env_key_456")

        config = Config()

        # Environment variable should be found
        assert config.get_api_key("hibp") == "env_key_456"

    def test_is_site_enabled(self) -> None:
        """Test checking if site is enabled."""
        config = Config()

        # Default sites should be enabled
        assert config.is_site_enabled("github") is True
        assert config.is_site_enabled("reddit") is True

    def test_get_site_config(self) -> None:
        """Test getting site configuration."""
        config = Config()

        github_config = config.get_site_config("github")
        assert "enabled" in github_config
        assert "url_template" in github_config
        assert github_config["url_template"] == "https://github.com/{username}"

    def test_to_dict(self) -> None:
        """Test converting config to dictionary."""
        config = Config()

        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert "logging" in config_dict
        assert "search" in config_dict
        assert "api_keys" in config_dict

    def test_reload_config(self, temp_yaml_config: str) -> None:
        """Test reloading configuration."""
        config = Config()

        # Initial value
        assert config.get("search.max_variants") == 50

        # Reload with different config
        config.reload(temp_yaml_config)

        # Should have new value
        assert config.get("search.max_variants") == 100

    def test_global_config_singleton(self) -> None:
        """Test that get_config returns singleton."""
        config1 = get_config()
        config2 = get_config()

        assert config1 is config2

    def test_nested_key_access(self) -> None:
        """Test accessing deeply nested keys."""
        config = Config()

        # Multiple levels deep
        config.set("level1.level2.level3", "deep_value")
        assert config.get("level1.level2.level3") == "deep_value"

    def test_site_config_defaults(self) -> None:
        """Test that default site configs are present."""
        config = Config()

        sites = config.get_section("sites")

        # Check some expected sites
        assert "github" in sites
        assert "reddit" in sites
        assert "twitter" in sites
        assert "linkedin" in sites

    def test_correlation_config(self) -> None:
        """Test correlation engine configuration."""
        config = Config()

        correlation = config.get_section("correlation")
        assert "min_confidence" in correlation
        assert "max_depth" in correlation
        assert "enable_visualization" in correlation

        assert correlation["min_confidence"] == 0.5
        assert correlation["max_depth"] == 3

    def test_invalid_config_file(self) -> None:
        """Test handling of invalid config file."""
        # Non-existent file should not crash
        config = Config("/nonexistent/path/config.yaml")

        # Should still have defaults
        assert config.get("logging.level") == "INFO"

    def test_unsupported_format(self, tmp_path: Path) -> None:
        """Test handling of unsupported config format."""
        config_file = tmp_path / "config.txt"
        config_file.write_text("invalid format")

        config = Config(str(config_file))

        # Should still have defaults
        assert config.get("logging.level") == "INFO"

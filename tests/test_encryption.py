"""Tests for data encryption utilities."""

import json
import tempfile
from pathlib import Path

import pytest

from src.security.encryption import (
    APIKeyVault,
    EncryptionError,
    EncryptionManager,
    FieldEncryption,
    SecureConfig,
    derive_key_from_password,
    generate_encryption_key,
    initialize_encryption,
)


class TestEncryptionManager:
    """Tests for EncryptionManager."""

    def test_generate_master_key(self):
        """Test master key generation."""
        mgr = EncryptionManager()
        # Key should be generated automatically
        assert mgr._master_key is not None
        assert len(mgr._master_key) == 32

    def test_encrypt_decrypt_string(self):
        """Test encrypting and decrypting strings."""
        mgr = EncryptionManager(master_key="test_key")

        original = "sensitive data"
        encrypted = mgr.encrypt(original)

        # Encrypted should be different from original
        assert encrypted != original

        # Decryption should return original
        decrypted = mgr.decrypt(encrypted)
        assert decrypted == original

    def test_encrypt_decrypt_bytes(self):
        """Test encrypting and decrypting bytes."""
        mgr = EncryptionManager(master_key="test_key")

        original = b"sensitive bytes"
        encrypted = mgr.encrypt(original)
        decrypted = mgr.decrypt(encrypted)

        assert decrypted == original.decode("utf-8")

    def test_decrypt_wrong_key(self):
        """Test decryption with wrong key fails."""
        mgr1 = EncryptionManager(master_key="key_one")
        mgr2 = EncryptionManager(master_key="key_two")

        encrypted = mgr1.encrypt("secret data")

        with pytest.raises(EncryptionError):
            mgr2.decrypt(encrypted)

    def test_encrypt_dict(self):
        """Test encrypting dictionary values."""
        mgr = EncryptionManager(master_key="test_key")

        data = {
            "username": "user1",
            "api_key": "secret_key_123",
            "email": "user@example.com",
        }

        encrypted = mgr.encrypt_dict(data, ["api_key"])

        # Non-encrypted fields should be unchanged
        assert encrypted["username"] == "user1"
        assert encrypted["email"] == "user@example.com"

        # Encrypted field should be different
        assert encrypted["api_key"] != "secret_key_123"

        # Should be decryptable
        decrypted = mgr.decrypt_dict(encrypted, ["api_key"])
        assert decrypted["api_key"] == "secret_key_123"

    def test_encrypt_empty_values(self):
        """Test handling of empty/None values."""
        mgr = EncryptionManager(master_key="test_key")

        data = {
            "present": "value",
            "empty": "",
            "none": None,
        }

        encrypted = mgr.encrypt_dict(data, ["present", "empty", "none"])

        # Empty and None should remain unchanged
        assert encrypted["empty"] == ""
        assert encrypted["none"] is None
        # Present value should be encrypted
        assert encrypted["present"] != "value"

    def test_get_master_key_hash(self):
        """Test getting master key hash."""
        mgr = EncryptionManager(master_key="test_key")

        hash1 = mgr.get_master_key_hash()
        hash2 = mgr.get_master_key_hash()

        # Same key should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex = 64 chars

        # Different key should produce different hash
        mgr2 = EncryptionManager(master_key="other_key")
        assert mgr2.get_master_key_hash() != hash1


class TestAPIKeyVault:
    """Tests for APIKeyVault."""

    @pytest.fixture
    def vault(self):
        """Create vault for testing."""
        mgr = EncryptionManager(master_key="test_vault_key")
        return APIKeyVault(mgr)

    def test_store_and_get_key(self, vault):
        """Test storing and retrieving API keys."""
        vault.store_key("openai", "sk-test-123456")

        retrieved = vault.get_key("openai")
        assert retrieved == "sk-test-123456"

    def test_get_nonexistent_key(self, vault):
        """Test getting non-existent key returns None."""
        assert vault.get_key("nonexistent") is None

    def test_delete_key(self, vault):
        """Test deleting API keys."""
        vault.store_key("test_key", "value123")
        assert vault.get_key("test_key") == "value123"

        result = vault.delete_key("test_key")
        assert result is True
        assert vault.get_key("test_key") is None

    def test_delete_nonexistent_key(self, vault):
        """Test deleting non-existent key returns False."""
        result = vault.delete_key("nonexistent")
        assert result is False

    def test_list_keys(self, vault):
        """Test listing stored keys."""
        vault.store_key("key1", "value1")
        vault.store_key("key2", "value2")
        vault.store_key("key3", "value3")

        keys = vault.list_keys()
        assert set(keys) == {"key1", "key2", "key3"}

    def test_rotate_key(self, vault):
        """Test key rotation."""
        vault.store_key("api_key", "old_value")
        assert vault.get_key("api_key") == "old_value"

        result = vault.rotate_key("api_key", "new_value")
        assert result is True
        assert vault.get_key("api_key") == "new_value"

    def test_rotate_nonexistent_key(self, vault):
        """Test rotating non-existent key returns False."""
        result = vault.rotate_key("nonexistent", "value")
        assert result is False

    def test_persistence(self):
        """Test vault persistence to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "keys.json"
            mgr = EncryptionManager(master_key="persist_test")

            # Create vault and store key
            vault1 = APIKeyVault(mgr, storage_path)
            vault1.store_key("persistent_key", "secret_value")

            # Create new vault instance
            vault2 = APIKeyVault(mgr, storage_path)

            # Should load persisted key
            assert vault2.get_key("persistent_key") == "secret_value"


class TestSecureConfig:
    """Tests for SecureConfig."""

    @pytest.fixture
    def config(self):
        """Create secure config for testing."""
        mgr = EncryptionManager(master_key="test_config_key")
        return SecureConfig(mgr)

    def test_set_get_normal_value(self, config):
        """Test setting and getting normal values."""
        config.set("database_host", "localhost")
        assert config.get("database_host") == "localhost"

    def test_set_get_sensitive_value(self, config):
        """Test sensitive values are encrypted."""
        config.set("database_password", "secret123")

        # Value should be stored encrypted
        entry = config._config["database_password"]
        assert entry["encrypted"] is True
        assert entry["value"] != "secret123"

        # But get() should return decrypted value
        assert config.get("database_password") == "secret123"

    def test_sensitive_key_detection(self, config):
        """Test detection of sensitive keys."""
        assert config._is_sensitive("api_key") is True
        assert config._is_sensitive("API_SECRET") is True
        assert config._is_sensitive("db_password") is True
        assert config._is_sensitive("auth_token") is True
        assert config._is_sensitive("database_host") is False
        assert config._is_sensitive("port") is False

    def test_get_default(self, config):
        """Test getting non-existent key returns default."""
        assert config.get("nonexistent") is None
        assert config.get("nonexistent", "default") == "default"

    def test_to_dict(self, config):
        """Test converting config to dictionary."""
        config.set("host", "localhost")
        config.set("api_key", "secret_key")

        # With decrypt=True (default)
        result = config.to_dict(decrypt=True)
        assert result["host"] == "localhost"
        assert result["api_key"] == "secret_key"

        # With decrypt=False
        result = config.to_dict(decrypt=False)
        assert result["host"] == "localhost"
        assert result["api_key"] == "[ENCRYPTED]"

    def test_from_dict(self, config):
        """Test loading config from dictionary."""
        data = {
            "host": "localhost",
            "port": 5432,
            "db_password": "secret",
        }

        config.from_dict(data)

        assert config.get("host") == "localhost"
        assert config.get("port") == 5432
        assert config.get("db_password") == "secret"


class TestFieldEncryption:
    """Tests for FieldEncryption."""

    @pytest.fixture
    def field_enc(self):
        """Create field encryption for testing."""
        mgr = EncryptionManager(master_key="test_field_key")
        return FieldEncryption(mgr)

    def test_encrypt_decrypt_field(self, field_enc):
        """Test encrypting and decrypting single field."""
        original = "sensitive_value"
        encrypted = field_enc.encrypt_field(original)
        decrypted = field_enc.decrypt_field(encrypted)

        assert encrypted != original
        assert decrypted == original

    def test_encrypt_none_field(self, field_enc):
        """Test encrypting None returns empty string."""
        assert field_enc.encrypt_field(None) == ""

    def test_decrypt_empty_field(self, field_enc):
        """Test decrypting empty string returns empty string."""
        assert field_enc.decrypt_field("") == ""

    def test_encrypt_record(self, field_enc):
        """Test encrypting record fields."""
        record = {
            "id": 1,
            "username": "user1",
            "email": "user@example.com",
            "ssn": "123-45-6789",
        }

        encrypted = field_enc.encrypt_record(record, ["ssn"])

        # Non-encrypted fields unchanged
        assert encrypted["id"] == 1
        assert encrypted["username"] == "user1"
        assert encrypted["email"] == "user@example.com"

        # Encrypted field changed
        assert encrypted["ssn"] != "123-45-6789"

    def test_decrypt_record(self, field_enc):
        """Test decrypting record fields."""
        record = {
            "id": 1,
            "username": "user1",
            "ssn": "123-45-6789",
        }

        encrypted = field_enc.encrypt_record(record, ["ssn"])
        decrypted = field_enc.decrypt_record(encrypted, ["ssn"])

        assert decrypted["ssn"] == "123-45-6789"

    def test_encrypt_record_missing_field(self, field_enc):
        """Test encrypting record with missing field."""
        record = {"id": 1, "name": "test"}

        # Should not raise, just skip missing field
        encrypted = field_enc.encrypt_record(record, ["nonexistent"])
        assert encrypted == record


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_generate_encryption_key(self):
        """Test encryption key generation."""
        key1 = generate_encryption_key()
        key2 = generate_encryption_key()

        # Should be different each time
        assert key1 != key2

        # Should be valid base64
        import base64

        decoded = base64.urlsafe_b64decode(key1)
        assert len(decoded) == 32

    def test_derive_key_from_password(self):
        """Test key derivation from password."""
        password = "my_secure_password"

        key1, salt1 = derive_key_from_password(password)

        # Same password with same salt should give same key
        key2, _ = derive_key_from_password(password, salt1)
        assert key1 == key2

        # Same password with different salt should give different key
        key3, salt3 = derive_key_from_password(password)
        assert key1 != key3

    def test_initialize_encryption(self):
        """Test global encryption initialization."""
        mgr = initialize_encryption(master_key="global_test_key")

        assert mgr is not None

        # Test that we can use it
        encrypted = mgr.encrypt("test")
        decrypted = mgr.decrypt(encrypted)
        assert decrypted == "test"


class TestIntegrationScenarios:
    """Integration tests for encryption workflows."""

    def test_api_key_workflow(self):
        """Test complete API key management workflow."""
        mgr = EncryptionManager(master_key="integration_test")
        vault = APIKeyVault(mgr)

        # Store multiple API keys
        vault.store_key("openai", "sk-openai-test-key")
        vault.store_key("github", "ghp-github-token")
        vault.store_key("aws", "AKIAIOSFODNN7EXAMPLE")

        # Retrieve and verify
        assert vault.get_key("openai") == "sk-openai-test-key"
        assert vault.get_key("github") == "ghp-github-token"
        assert vault.get_key("aws") == "AKIAIOSFODNN7EXAMPLE"

        # List keys
        assert set(vault.list_keys()) == {"openai", "github", "aws"}

        # Rotate a key
        vault.rotate_key("openai", "sk-new-openai-key")
        assert vault.get_key("openai") == "sk-new-openai-key"

        # Delete a key
        vault.delete_key("github")
        assert vault.get_key("github") is None
        assert set(vault.list_keys()) == {"openai", "aws"}

    def test_config_workflow(self):
        """Test secure configuration workflow."""
        mgr = EncryptionManager(master_key="config_test")
        config = SecureConfig(mgr)

        # Set up configuration
        config.set("database_host", "localhost")
        config.set("database_port", 5432)
        config.set("database_password", "super_secret_password")
        config.set("api_key", "my-api-key-12345")

        # Export to dict (with encryption markers)
        exported = config.to_dict(decrypt=False)
        assert exported["database_host"] == "localhost"
        assert exported["database_port"] == 5432
        assert exported["database_password"] == "[ENCRYPTED]"
        assert exported["api_key"] == "[ENCRYPTED]"

        # Export decrypted (for internal use)
        decrypted = config.to_dict(decrypt=True)
        assert decrypted["database_password"] == "super_secret_password"
        assert decrypted["api_key"] == "my-api-key-12345"

    def test_database_record_encryption(self):
        """Test encrypting database records."""
        mgr = EncryptionManager(master_key="db_test")
        field_enc = FieldEncryption(mgr)

        # Simulate database records with PII
        records = [
            {"id": 1, "name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"},
            {"id": 2, "name": "Jane Doe", "ssn": "987-65-4321", "email": "jane@example.com"},
        ]

        sensitive_fields = ["ssn"]

        # Encrypt before storing
        encrypted_records = [field_enc.encrypt_record(r, sensitive_fields) for r in records]

        # Verify encryption
        for i, enc_record in enumerate(encrypted_records):
            assert enc_record["ssn"] != records[i]["ssn"]
            assert enc_record["name"] == records[i]["name"]  # Not encrypted
            assert enc_record["email"] == records[i]["email"]  # Not encrypted

        # Decrypt when retrieving
        decrypted_records = [
            field_enc.decrypt_record(r, sensitive_fields) for r in encrypted_records
        ]

        # Verify decryption
        for i, dec_record in enumerate(decrypted_records):
            assert dec_record["ssn"] == records[i]["ssn"]

    def test_persistent_vault_with_password(self):
        """Test vault with password-derived key and persistence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "secure_keys.json"

            # Derive key from password
            password = "user_master_password"
            derived_key, salt = derive_key_from_password(password)

            # Create vault with derived key
            mgr1 = EncryptionManager(master_key=derived_key)
            vault1 = APIKeyVault(mgr1, storage_path)

            # Store some keys
            vault1.store_key("secret1", "value1")
            vault1.store_key("secret2", "value2")

            # Simulate app restart - derive same key from password
            derived_key2, _ = derive_key_from_password(password, salt)
            mgr2 = EncryptionManager(master_key=derived_key2)
            vault2 = APIKeyVault(mgr2, storage_path)

            # Should be able to read stored keys
            assert vault2.get_key("secret1") == "value1"
            assert vault2.get_key("secret2") == "value2"

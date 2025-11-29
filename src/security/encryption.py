"""Data encryption utilities for TR4C3R.

Provides encryption for sensitive data including API keys, database fields,
and secure configuration management.
"""

import base64
import hashlib
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""

    pass


class EncryptionManager:
    """Manages encryption and decryption of sensitive data."""

    def __init__(self, master_key: Optional[str] = None):
        """Initialize encryption manager.

        Args:
            master_key: Master encryption key. If None, generates a new one.
        """
        if master_key:
            self._master_key = master_key.encode() if isinstance(master_key, str) else master_key
        else:
            self._master_key = self._generate_master_key()

        self._fernet = self._create_fernet(self._master_key)

    def _generate_master_key(self) -> bytes:
        """Generate a cryptographically secure master key.

        Returns:
            32-byte random key
        """
        return secrets.token_bytes(32)

    def _create_fernet(self, key: bytes) -> Fernet:
        """Create Fernet cipher from key.

        Args:
            key: Encryption key (any length)

        Returns:
            Fernet cipher instance
        """
        # Derive a proper Fernet key from any key using PBKDF2
        salt = b"tr4c3r_salt_v1"  # Static salt for deterministic key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key))
        return Fernet(derived_key)

    def encrypt(self, data: Union[str, bytes]) -> str:
        """Encrypt data.

        Args:
            data: Data to encrypt (string or bytes)

        Returns:
            Base64-encoded encrypted data
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        encrypted = self._fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data.

        Args:
            encrypted_data: Base64-encoded encrypted data

        Returns:
            Decrypted string

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode("ascii"))
            decrypted = self._fernet.decrypt(encrypted_bytes)
            return decrypted.decode("utf-8")
        except InvalidToken:
            raise EncryptionError("Decryption failed: Invalid token or wrong key")
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}")

    def encrypt_dict(self, data: Dict[str, Any], keys_to_encrypt: list[str]) -> Dict[str, Any]:
        """Encrypt specific keys in a dictionary.

        Args:
            data: Dictionary with data
            keys_to_encrypt: List of keys whose values should be encrypted

        Returns:
            Dictionary with encrypted values
        """
        result = data.copy()
        for key in keys_to_encrypt:
            if key in result and result[key]:
                value = str(result[key])
                result[key] = self.encrypt(value)
        return result

    def decrypt_dict(self, data: Dict[str, Any], keys_to_decrypt: list[str]) -> Dict[str, Any]:
        """Decrypt specific keys in a dictionary.

        Args:
            data: Dictionary with encrypted data
            keys_to_decrypt: List of keys whose values should be decrypted

        Returns:
            Dictionary with decrypted values
        """
        result = data.copy()
        for key in keys_to_decrypt:
            if key in result and result[key]:
                result[key] = self.decrypt(str(result[key]))
        return result

    def get_master_key_hash(self) -> str:
        """Get hash of master key for verification.

        Returns:
            SHA256 hash of master key (hex string)
        """
        return hashlib.sha256(self._master_key).hexdigest()


class APIKeyVault:
    """Secure storage for API keys."""

    def __init__(self, encryption_manager: EncryptionManager, storage_path: Optional[Path] = None):
        """Initialize API key vault.

        Args:
            encryption_manager: Encryption manager instance
            storage_path: Path to store encrypted keys (optional)
        """
        self.encryption = encryption_manager
        self.storage_path = storage_path
        self._keys: Dict[str, str] = {}  # In-memory cache of encrypted keys

        if storage_path and storage_path.exists():
            self._load_keys()

    def _load_keys(self):
        """Load encrypted keys from storage."""
        if self.storage_path and self.storage_path.exists():
            import json

            try:
                with open(self.storage_path, "r") as f:
                    self._keys = json.load(f)
                logger.info(f"Loaded {len(self._keys)} API keys from vault")
            except Exception as e:
                logger.error(f"Failed to load API keys: {e}")

    def _save_keys(self):
        """Save encrypted keys to storage."""
        if self.storage_path:
            import json

            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, "w") as f:
                json.dump(self._keys, f)
            # Set restrictive permissions
            os.chmod(self.storage_path, 0o600)

    def store_key(self, name: str, api_key: str) -> None:
        """Store an API key securely.

        Args:
            name: Name/identifier for the API key
            api_key: The API key value
        """
        encrypted = self.encryption.encrypt(api_key)
        self._keys[name] = encrypted
        self._save_keys()
        logger.info(f"Stored API key: {name}")

    def get_key(self, name: str) -> Optional[str]:
        """Retrieve a decrypted API key.

        Args:
            name: Name/identifier for the API key

        Returns:
            Decrypted API key or None if not found
        """
        encrypted = self._keys.get(name)
        if encrypted:
            try:
                return self.encryption.decrypt(encrypted)
            except EncryptionError as e:
                logger.error(f"Failed to decrypt API key {name}: {e}")
                return None
        return None

    def delete_key(self, name: str) -> bool:
        """Delete an API key.

        Args:
            name: Name/identifier for the API key

        Returns:
            True if key was deleted, False if not found
        """
        if name in self._keys:
            del self._keys[name]
            self._save_keys()
            logger.info(f"Deleted API key: {name}")
            return True
        return False

    def list_keys(self) -> list[str]:
        """List all stored API key names.

        Returns:
            List of API key names (not the actual keys)
        """
        return list(self._keys.keys())

    def rotate_key(self, name: str, new_key: str) -> bool:
        """Rotate an API key.

        Args:
            name: Name/identifier for the API key
            new_key: New API key value

        Returns:
            True if rotation successful, False if key not found
        """
        if name not in self._keys:
            return False

        old_key = self.get_key(name)
        self.store_key(name, new_key)
        logger.info(f"Rotated API key: {name}")
        return True


class SecureConfig:
    """Secure configuration with encrypted sensitive values."""

    # Keys that should be encrypted
    SENSITIVE_KEYS = [
        "api_key",
        "api_secret",
        "password",
        "secret",
        "token",
        "credential",
        "private_key",
    ]

    def __init__(self, encryption_manager: EncryptionManager):
        """Initialize secure config.

        Args:
            encryption_manager: Encryption manager instance
        """
        self.encryption = encryption_manager
        self._config: Dict[str, Any] = {}

    def _is_sensitive(self, key: str) -> bool:
        """Check if a key should be encrypted.

        Args:
            key: Configuration key name

        Returns:
            True if key contains sensitive data
        """
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            key: Configuration key
            value: Value (auto-encrypted if sensitive)
        """
        if self._is_sensitive(key) and value:
            self._config[key] = {"encrypted": True, "value": self.encryption.encrypt(str(value))}
        else:
            self._config[key] = {"encrypted": False, "value": value}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            key: Configuration key
            default: Default value if not found

        Returns:
            Configuration value (auto-decrypted if encrypted)
        """
        if key not in self._config:
            return default

        entry = self._config[key]
        if entry.get("encrypted"):
            try:
                return self.encryption.decrypt(entry["value"])
            except EncryptionError:
                logger.error(f"Failed to decrypt config key: {key}")
                return default
        return entry["value"]

    def to_dict(self, decrypt: bool = True) -> Dict[str, Any]:
        """Convert config to dictionary.

        Args:
            decrypt: Whether to decrypt sensitive values

        Returns:
            Configuration dictionary
        """
        result = {}
        for key, entry in self._config.items():
            if entry.get("encrypted") and decrypt:
                try:
                    result[key] = self.encryption.decrypt(entry["value"])
                except EncryptionError:
                    result[key] = "[ENCRYPTED]"
            elif entry.get("encrypted"):
                result[key] = "[ENCRYPTED]"
            else:
                result[key] = entry["value"]
        return result

    def from_dict(self, data: Dict[str, Any]) -> None:
        """Load config from dictionary.

        Args:
            data: Configuration dictionary
        """
        for key, value in data.items():
            self.set(key, value)


class FieldEncryption:
    """Field-level encryption for database records."""

    def __init__(self, encryption_manager: EncryptionManager):
        """Initialize field encryption.

        Args:
            encryption_manager: Encryption manager instance
        """
        self.encryption = encryption_manager

    def encrypt_field(self, value: Any) -> str:
        """Encrypt a single field value.

        Args:
            value: Value to encrypt

        Returns:
            Encrypted value as string
        """
        if value is None:
            return ""
        return self.encryption.encrypt(str(value))

    def decrypt_field(self, encrypted_value: str) -> str:
        """Decrypt a single field value.

        Args:
            encrypted_value: Encrypted value

        Returns:
            Decrypted value
        """
        if not encrypted_value:
            return ""
        return self.encryption.decrypt(encrypted_value)

    def encrypt_record(self, record: Dict[str, Any], fields: list[str]) -> Dict[str, Any]:
        """Encrypt specific fields in a record.

        Args:
            record: Database record
            fields: Fields to encrypt

        Returns:
            Record with encrypted fields
        """
        result = record.copy()
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.encrypt_field(result[field])
        return result

    def decrypt_record(self, record: Dict[str, Any], fields: list[str]) -> Dict[str, Any]:
        """Decrypt specific fields in a record.

        Args:
            record: Record with encrypted fields
            fields: Fields to decrypt

        Returns:
            Record with decrypted fields
        """
        result = record.copy()
        for field in fields:
            if field in result and result[field]:
                try:
                    result[field] = self.decrypt_field(result[field])
                except EncryptionError:
                    result[field] = "[DECRYPTION_FAILED]"
        return result


def generate_encryption_key() -> str:
    """Generate a new encryption key.

    Returns:
        Base64-encoded 32-byte key
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> tuple[str, bytes]:
    """Derive an encryption key from a password.

    Args:
        password: Password to derive key from
        salt: Salt for key derivation (generated if None)

    Returns:
        Tuple of (derived key as base64 string, salt used)
    """
    if salt is None:
        salt = secrets.token_bytes(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key.decode("ascii"), salt


# Global encryption manager (to be initialized by application)
_encryption_manager: Optional[EncryptionManager] = None


def initialize_encryption(master_key: Optional[str] = None) -> EncryptionManager:
    """Initialize global encryption manager.

    Args:
        master_key: Master encryption key

    Returns:
        Encryption manager instance
    """
    global _encryption_manager
    _encryption_manager = EncryptionManager(master_key)
    logger.info("Encryption manager initialized")
    return _encryption_manager


def get_encryption_manager() -> EncryptionManager:
    """Get global encryption manager.

    Returns:
        Encryption manager instance

    Raises:
        RuntimeError: If not initialized
    """
    if _encryption_manager is None:
        raise RuntimeError("Encryption not initialized. Call initialize_encryption() first.")
    return _encryption_manager

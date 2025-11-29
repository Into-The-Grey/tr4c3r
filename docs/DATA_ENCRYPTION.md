# Data Encryption Infrastructure

This document describes the comprehensive data encryption capabilities in TR4C3R.

## Overview

TR4C3R implements multi-layered encryption for protecting sensitive data:

- **At-Rest Encryption**: Fernet symmetric encryption for stored data
- **API Key Vault**: Secure storage for third-party API credentials
- **Field-Level Encryption**: Selective encryption of database fields
- **Secure Configuration**: Automatic encryption of sensitive config values

## Quick Start

```python
from src.security.encryption import (
    EncryptionManager,
    APIKeyVault,
    SecureConfig,
    FieldEncryption,
    initialize_encryption,
)

# Initialize with a master key
encryption = initialize_encryption(master_key="your-secret-master-key")

# Encrypt sensitive data
encrypted = encryption.encrypt("sensitive data")
decrypted = encryption.decrypt(encrypted)
```

## Components

### EncryptionManager

Core encryption functionality using Fernet (AES-128-CBC with HMAC-SHA256).

```python
from src.security.encryption import EncryptionManager

# Create with explicit key
mgr = EncryptionManager(master_key="my-master-key")

# Or let it generate a key
mgr = EncryptionManager()
print(f"Save this key: {mgr.get_master_key_hash()}")
```

#### String Encryption

```python
# Encrypt a string
encrypted = mgr.encrypt("my secret password")
print(f"Encrypted: {encrypted}")

# Decrypt
decrypted = mgr.decrypt(encrypted)
assert decrypted == "my secret password"
```

#### Dictionary Encryption

Encrypt specific fields in a dictionary:

```python
user_data = {
    "username": "john_doe",
    "email": "john@example.com",
    "api_key": "sk-secret-key-12345",
    "ssn": "123-45-6789",
}

# Encrypt sensitive fields
encrypted_data = mgr.encrypt_dict(user_data, ["api_key", "ssn"])
# Returns: {"username": "john_doe", "email": "...", "api_key": "gAAA...", "ssn": "gAAA..."}

# Decrypt when needed
decrypted_data = mgr.decrypt_dict(encrypted_data, ["api_key", "ssn"])
```

### APIKeyVault

Secure storage for API keys and credentials:

```python
from src.security.encryption import EncryptionManager, APIKeyVault
from pathlib import Path

mgr = EncryptionManager(master_key="vault-key")

# Create vault with file persistence
vault = APIKeyVault(mgr, Path("~/.tr4c3r/keys.json"))

# Store API keys
vault.store_key("openai", "sk-proj-...")
vault.store_key("shodan", "api-key-...")
vault.store_key("hunter", "api-key-...")

# Retrieve when needed
openai_key = vault.get_key("openai")

# List all stored keys (names only, not values)
key_names = vault.list_keys()  # ["openai", "shodan", "hunter"]

# Rotate a key
vault.rotate_key("openai", "sk-new-key-...")

# Delete when no longer needed
vault.delete_key("shodan")
```

### SecureConfig

Automatic encryption for configuration values:

```python
from src.security.encryption import EncryptionManager, SecureConfig

mgr = EncryptionManager(master_key="config-key")
config = SecureConfig(mgr)

# Set configuration values
config.set("database_host", "localhost")  # Stored in plain text
config.set("database_password", "secret")  # Auto-encrypted (contains 'password')
config.set("api_key", "sk-12345")  # Auto-encrypted (contains 'key')

# Values are automatically decrypted when retrieved
password = config.get("database_password")  # Returns "secret"

# Export config (safe for logging)
safe_export = config.to_dict(decrypt=False)
# {"database_host": "localhost", "database_password": "[ENCRYPTED]", "api_key": "[ENCRYPTED]"}

# Export for internal use
full_export = config.to_dict(decrypt=True)
# {"database_host": "localhost", "database_password": "secret", "api_key": "sk-12345"}
```

**Sensitive Key Patterns** (auto-encrypted):

- `*password*`, `*passwd*`
- `*secret*`
- `*key*`, `*api_key*`
- `*token*`
- `*credential*`

### FieldEncryption

Field-level encryption for database records:

```python
from src.security.encryption import EncryptionManager, FieldEncryption

mgr = EncryptionManager(master_key="db-key")
field_enc = FieldEncryption(mgr)

# Define which fields are sensitive
sensitive_fields = ["ssn", "credit_card", "phone"]

# Encrypt a record before storing
record = {
    "id": 1,
    "name": "John Doe",
    "ssn": "123-45-6789",
    "email": "john@example.com",
}

encrypted_record = field_enc.encrypt_record(record, sensitive_fields)
# Store encrypted_record in database

# Decrypt when retrieving
decrypted_record = field_enc.decrypt_record(encrypted_record, sensitive_fields)
```

## Helper Functions

### Key Generation

```python
from src.security.encryption import generate_encryption_key

# Generate a new random key (URL-safe base64)
key = generate_encryption_key()
print(f"New key: {key}")
# Output: "eW91cl9yYW5kb21fa2V5X2hlcmU..."
```

### Password-Based Key Derivation

Derive an encryption key from a user password:

```python
from src.security.encryption import derive_key_from_password

# Derive key from password (generates new salt)
key, salt = derive_key_from_password("user-password")

# Store salt alongside encrypted data
# ...

# Re-derive same key with stored salt
key2, _ = derive_key_from_password("user-password", salt)
assert key == key2
```

## Security Best Practices

### 1. Master Key Management

```python
import os

# Option 1: Environment variable (recommended)
master_key = os.environ.get("TR4C3R_MASTER_KEY")
if not master_key:
    raise ValueError("Master key not configured")

mgr = EncryptionManager(master_key=master_key)

# Option 2: Derive from password
password = input("Enter master password: ")
key, salt = derive_key_from_password(password)
# Store salt in secure configuration
```

### 2. Key Rotation

```python
# Rotate master key (requires re-encrypting all data)
old_mgr = EncryptionManager(master_key=old_key)
new_mgr = EncryptionManager(master_key=new_key)

# Re-encrypt all API keys
for key_name in vault.list_keys():
    value = vault.get_key(key_name)  # Decrypt with old key
    # Store with new vault instance
    new_vault.store_key(key_name, value)  # Encrypt with new key
```

### 3. Audit Logging

```python
from src.core.logging_setup import get_audit_logger

audit = get_audit_logger()

# Log encryption operations
audit.log_security("encryption_operation", {
    "action": "encrypt_field",
    "field_name": "ssn",
    "record_id": 123,
})
```

## Integration Examples

### FastAPI Endpoint

```python
from fastapi import APIRouter, Depends
from src.security.encryption import EncryptionManager, APIKeyVault

router = APIRouter()

def get_vault():
    """Dependency to get API key vault."""
    mgr = EncryptionManager(master_key=os.environ["MASTER_KEY"])
    return APIKeyVault(mgr)

@router.post("/api-keys")
async def store_api_key(
    name: str,
    value: str,
    vault: APIKeyVault = Depends(get_vault)
):
    vault.store_key(name, value)
    return {"status": "stored", "name": name}

@router.get("/api-keys/{name}")
async def get_api_key(
    name: str,
    vault: APIKeyVault = Depends(get_vault)
):
    value = vault.get_key(name)
    if not value:
        raise HTTPException(404, "Key not found")
    return {"name": name, "value": value}
```

### Database Model Integration

```python
from dataclasses import dataclass
from src.security.encryption import FieldEncryption

SENSITIVE_FIELDS = ["ssn", "drivers_license", "credit_card"]

@dataclass
class User:
    id: int
    name: str
    email: str
    ssn: str
    
    def encrypt_for_storage(self, field_enc: FieldEncryption) -> dict:
        """Encrypt sensitive fields before database storage."""
        data = self.__dict__.copy()
        return field_enc.encrypt_record(data, SENSITIVE_FIELDS)
    
    @classmethod
    def from_encrypted(cls, data: dict, field_enc: FieldEncryption) -> "User":
        """Create instance from encrypted database record."""
        decrypted = field_enc.decrypt_record(data, SENSITIVE_FIELDS)
        return cls(**decrypted)
```

## Configuration

### Environment Variables

```bash
# Master encryption key (required in production)
export TR4C3R_MASTER_KEY="your-secure-master-key"

# Key vault storage location
export TR4C3R_KEY_VAULT_PATH="~/.tr4c3r/keys.json"
```

### YAML Configuration

```yaml
# config/tr4c3r.yaml
security:
  encryption:
    enabled: true
    key_vault_path: "~/.tr4c3r/keys.json"
    
  sensitive_fields:
    - ssn
    - credit_card
    - api_key
    - password
```

## Error Handling

```python
from src.security.encryption import EncryptionError

try:
    decrypted = mgr.decrypt(encrypted_data)
except EncryptionError as e:
    # Handle decryption failure
    # - Wrong key
    # - Corrupted data
    # - Invalid format
    logger.error(f"Decryption failed: {e}")
```

## Testing

Run encryption tests:

```bash
# All encryption tests
pipenv run pytest tests/test_encryption.py -v

# Specific test class
pipenv run pytest tests/test_encryption.py::TestAPIKeyVault -v

# Integration tests
pipenv run pytest tests/test_encryption.py::TestIntegrationScenarios -v
```

## API Reference

### API: EncryptionManager

| Method | Description |
|--------|-------------|
| `encrypt(data)` | Encrypt string or bytes |
| `decrypt(data)` | Decrypt encrypted data |
| `encrypt_dict(data, fields)` | Encrypt specified dictionary fields |
| `decrypt_dict(data, fields)` | Decrypt specified dictionary fields |
| `get_master_key_hash()` | Get SHA-256 hash of master key |

### API: APIKeyVault

| Method | Description |
|--------|-------------|
| `store_key(name, value)` | Store encrypted API key |
| `get_key(name)` | Retrieve decrypted API key |
| `delete_key(name)` | Delete API key |
| `rotate_key(name, value)` | Replace existing key |
| `list_keys()` | List all stored key names |

### API: SecureConfig

| Method | Description |
|--------|-------------|
| `set(key, value)` | Set config value (auto-encrypts sensitive) |
| `get(key, default)` | Get config value (auto-decrypts) |
| `to_dict(decrypt)` | Export as dictionary |
| `from_dict(data)` | Import from dictionary |

### API: FieldEncryption

| Method | Description |
|--------|-------------|
| `encrypt_field(value)` | Encrypt single field |
| `decrypt_field(value)` | Decrypt single field |
| `encrypt_record(record, fields)` | Encrypt record fields |
| `decrypt_record(record, fields)` | Decrypt record fields |

## Related Documentation

- [Authentication](AUTHENTICATION.md) - JWT tokens and user management
- [Logging Infrastructure](LOGGING_INFRASTRUCTURE.md) - Audit logging for security events
- [Security Guidelines](SECURITY_GUIDELINES_SUMMARY.md) - Overall security practices

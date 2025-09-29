"""
Centralized crypto module for Scrambled Eggs.

This module provides a unified interface for all crypto operations,
re-exporting from the services.encryption module for backward compatibility.
"""

from typing import Any, Dict, Optional, Union

# Import from services.encryption
from .encryption import (
    ConfigurationError,
    DecryptionError,
    EncryptionError,
    EncryptionLayer,
    EncryptionResult,
    IntegrityCheckError,
    KeyManagementError,
    ScrambledEggsCrypto,
    crypto,
)

# Re-export for backward compatibility
__all__ = [
    "ScrambledEggsCrypto",
    "crypto",
    "EncryptionLayer",
    "EncryptionResult",
    "EncryptionError",
    "DecryptionError",
    "IntegrityCheckError",
    "ConfigurationError",
    "KeyManagementError",
    "generate_key",
    "encrypt",
    "decrypt",
]


def generate_key(key_size: int = 32) -> bytes:
    """Generate a new encryption key.

    Args:
        key_size: Size of the key in bytes

    Returns:
        A new encryption key as bytes
    """
    return os.urandom(key_size)


def encrypt(data: Union[bytes, str], key: Optional[bytes] = None, **kwargs) -> Dict[str, Any]:
    """Encrypt data using the default encryption layer.

    Args:
        data: Data to encrypt
        key: Optional encryption key (generated if not provided)
        **kwargs: Additional encryption parameters

    Returns:
        Dictionary containing encrypted data and metadata
    """
    if key is None:
        key = generate_key()
    if isinstance(data, str):
        data = data.encode("utf-8")
    return crypto.encrypt(data, key=key, **kwargs)


def decrypt(encrypted_data: Dict[str, Any], key: bytes) -> bytes:
    """Decrypt data using the default encryption layer.

    Args:
        encrypted_data: Dictionary containing encrypted data and metadata
        key: Encryption key

    Returns:
        Decrypted data as bytes
    """
    return crypto.decrypt(encrypted_data, key=key)

"""Scrambled Eggs Encryption Module.

This module provides the primary encryption functionality for the application
using the Scrambled Eggs encryption protocol.
"""

import os
from typing import Any, Dict, Optional, Union

# Import exceptions
from app.core.exceptions import (
    ConfigurationError,
    DecryptionError,
    EncryptionError,
    IntegrityCheckError,
    KeyManagementError,
)

# Import from the services module
from app.services import ScrambledEggsCrypto, crypto

# Import the encryption layer and result types
from app.services.encryption.encryption_layer import EncryptionLayer
from app.services.encryption.encryption_result import EncryptionResult


def encrypt(
    data: Union[bytes, str], key: Optional[bytes] = None, layer: Optional[EncryptionLayer] = None
) -> Dict[str, Any]:
    """
    Encrypt data using the specified encryption layer.

    Args:
        data: The data to encrypt (bytes or string)
        key: Optional encryption key (generated if not provided)
        layer: Encryption layer to use (defaults to SCRAMBLED_EGGS)

    Returns:
        Dictionary containing the encrypted data and metadata
    """
    if key is None:
        key = generate_key()
    if isinstance(data, str):
        data = data.encode("utf-8")
    return crypto.encrypt(data, key=key, layer=layer)


def decrypt(encrypted_data: Dict[str, Any], key: bytes) -> bytes:
    """
    Decrypt data using the appropriate algorithm based on the encrypted data.

    Args:
        encrypted_data: Dictionary containing encrypted data and metadata
        key: The encryption key (required if not stored in the result)

    Returns:
        The decrypted data as bytes
    """
    return crypto.decrypt(encrypted_data, key=key)


def generate_key(key_size: int = 32) -> bytes:
    """
    Generate a new encryption key.

    Args:
        key_size: Size of the key in bytes (default: 32)

    Returns:
        A new encryption key as bytes
    """
    return os.urandom(key_size)


# Re-export important classes and functions
__all__ = [
    "crypto",
    "ScrambledEggsCrypto",
    "EncryptionLayer",
    "EncryptionResult",
    "encrypt",
    "decrypt",
    "generate_key",
    "EncryptionError",
    "DecryptionError",
    "IntegrityCheckError",
    "ConfigurationError",
    "KeyManagementError",
]

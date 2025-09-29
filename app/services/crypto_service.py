"""
Crypto Service for Scrambled Eggs.

This module provides a centralized service for cryptographic operations.
"""

import logging

# Import exceptions
from app.core.exceptions import (
    ConfigurationError,
    DecryptionError,
    EncryptionError,
    IntegrityCheckError,
    KeyManagementError,
)

from .encryption.encryption_layer import EncryptionLayer
from .encryption.encryption_result import EncryptionResult
from .encryption.scrambled_eggs_crypto import ScrambledEggsCrypto

logger = logging.getLogger(__name__)

# Create a singleton instance of ScrambledEggsCrypto
_crypto_instance = None


def get_crypto():
    """Get or create a singleton instance of ScrambledEggsCrypto."""
    global _crypto_instance
    if _crypto_instance is None:
        _crypto_instance = ScrambledEggsCrypto()
    return _crypto_instance


# Export the crypto instance
crypto = get_crypto()

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
]

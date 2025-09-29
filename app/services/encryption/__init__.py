"""
Encryption Service for Scrambled Eggs encryption.

This module provides a high-level interface for encryption and decryption operations
using the Scrambled Eggs encryption scheme with secure key management.
"""

import logging
from typing import Any, Dict

# Import exceptions
from app.core.exceptions import (
    ConfigurationError,
    DecryptionError,
    EncryptionError,
    IntegrityCheckError,
    KeyManagementError,
)

# Import the encryption layer and result types
from .encryption_layer import EncryptionLayer
from .encryption_result import EncryptionResult

logger = logging.getLogger(__name__)

# Type aliases
EncryptionResultType = Dict[str, Any]
DecryptionResultType = Dict[str, Any]

# Import the crypto instance and ScrambledEggsCrypto
from .crypto_instance import crypto
from .scrambled_eggs_crypto import ScrambledEggsCrypto

# Export for backward compatibility
__all__ = [
    "crypto",
    "ScrambledEggsCrypto",
    "EncryptionLayer",
    "EncryptionResult",
    "EncryptionError",
    "DecryptionError",
    "IntegrityCheckError",
    "ConfigurationError",
    "KeyManagementError",
]

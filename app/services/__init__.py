"""
Business logic and service layer.
"""
# Import the crypto module
from .crypto import (
    ScrambledEggsCrypto,
    crypto,
    EncryptionLayer,
    EncryptionResult,
    EncryptionError,
    DecryptionError,
    IntegrityCheckError,
    ConfigurationError,
    KeyManagementError,
    generate_key,
    encrypt,
    decrypt
)

# Re-export for backward compatibility
__all__ = [
    'ScrambledEggsCrypto',
    'crypto',
    'EncryptionLayer',
    'EncryptionResult',
    'EncryptionError',
    'DecryptionError',
    'IntegrityCheckError',
    'ConfigurationError',
    'KeyManagementError',
    'generate_key',
    'encrypt',
    'decrypt'
]

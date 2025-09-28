"""
Centralized crypto module for Scrambled Eggs.

This module provides a unified interface for all crypto operations,
re-exporting from the services.encryption module for backward compatibility.
"""
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass, field
from enum import Enum

# Re-export from services.encryption
from app.services.encryption import (
    ScrambledEggsCrypto,
    crypto,
    EncryptionLayer,
    EncryptionResult
)

# Re-export for backward compatibility
__all__ = [
    'ScrambledEggsCrypto',
    'crypto',
    'EncryptionLayer',
    'EncryptionResult',
    'generate_key',
    'encrypt',
    'decrypt'
]

# Backward compatibility functions
def generate_key(key_size: int = 32) -> bytes:
    """Generate a new encryption key.
    
    Args:
        key_size: Size of the key in bytes
        
    Returns:
        A new encryption key as bytes
    """
    return os.urandom(key_size)

def encrypt(data: bytes, key: Optional[bytes] = None, **kwargs) -> Dict[str, Any]:
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

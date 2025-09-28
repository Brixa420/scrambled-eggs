"""
Encryption Layer Module

Defines the EncryptionLayer enum for different encryption algorithms.
"""
from enum import Enum

class EncryptionLayer(str, Enum):
    """Supported encryption layers."""
    SCRAMBLED_EGGS = "scrambled_eggs"
    AES_256_GCM = "aes_256_gcm"
    
    @classmethod
    def get_default(cls) -> 'EncryptionLayer':
        """Get the default encryption layer."""
        return cls.SCRAMBLED_EGGS

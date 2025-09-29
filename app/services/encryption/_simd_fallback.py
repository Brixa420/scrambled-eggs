"""
Fallback implementation of encryption operations without SIMD optimizations.

This module provides pure Python implementations that work on any CPU.
"""
import os
from typing import List

def bytes_to_ints(data: bytes) -> List[int]:
    """Convert bytes to a list of 32-bit integers (little-endian)."""
    return [
        int.from_bytes(data[i:i+4], 'little')
        for i in range(0, len(data), 4)
    ]

def ints_to_bytes(ints: List[int]) -> bytes:
    """Convert a list of 32-bit integers to bytes (little-endian)."""
    return b''.join(i.to_bytes(4, 'little') for i in ints)

def aes_encrypt_fallback(block: bytes, key: bytes) -> bytes:
    """AES block encryption (fallback implementation).
    
    This is a simplified implementation for demonstration purposes.
    In a real application, you would use a proper cryptographic library.
    """
    # This is a placeholder that just XORs with the key
    # A real implementation would include the full AES algorithm
    return bytes(a ^ b for a, b in zip(block, key))

def aes_decrypt_fallback(block: bytes, key: bytes) -> bytes:
    """AES block decryption (fallback implementation)."""
    # For AES, decryption is similar to encryption in this simplified version
    return aes_encrypt_fallback(block, key)

def gcm_mult_fallback(x: bytes, y: bytes) -> bytes:
    """GCM multiplication (fallback implementation)."""
    # This is a placeholder for GCM's GF(2^128) multiplication
    # A real implementation would include the proper finite field arithmetic
    return bytes(a ^ b for a, b in zip(x, y))

def ctr_increment_fallback(counter: int) -> int:
    """Increment counter (fallback implementation)."""
    return (counter + 1) & 0xFFFFFFFFFFFFFFFF

# Export the functions
__all__ = [
    'aes_encrypt_fallback',
    'aes_decrypt_fallback',
    'gcm_mult_fallback',
    'ctr_increment_fallback'
]

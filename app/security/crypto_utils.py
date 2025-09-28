"""
Crypto Utilities

Shared utilities and data structures for cryptographic operations.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class KeyPair:
    """Represents a public/private key pair."""
    public_key: bytes
    private_key: Optional[bytes] = None

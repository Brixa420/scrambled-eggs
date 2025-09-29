"""
Post-Quantum Cryptography (PQC) Module

This module provides implementations of post-quantum cryptographic algorithms,
including key encapsulation mechanisms (KEM) and digital signatures.

Supported Algorithms:
- Kyber (Key Encapsulation Mechanism)
- Dilithium (Digital Signatures)
- Hybrid schemes combining classical and post-quantum cryptography
"""

from .crypto import PQCrypto

# For backward compatibility, we'll keep the PQCrypto class as the main export
__all__ = ["PQCrypto"]

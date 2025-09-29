"""
Advanced Security Module
-----------------------

Implements advanced security features including breach detection,
behavioral analysis, memory protection, key derivation, and hybrid encryption.
"""

from .behavior_analysis import BehaviorAnalyzer
from .breach_detection import BreachDetector
from .hybrid_encryption import (
    EncryptionError,
    HybridEncryption,
    KeySize,
    decrypt_data,
    default_hybrid_encryption,
    encrypt_data,
)
from .key_derivation import (
    KDFType,
    KeyDerivation,
    KeyDerivationError,
    default_key_derivation,
    derive_key,
)
from .memory_protection import MemoryProtector
from .threat_response import ThreatResponder

__all__ = [
    # Core security components
    "BreachDetector",
    "BehaviorAnalyzer",
    "ThreatResponder",
    "MemoryProtector",
    # Key derivation
    "KeyDerivation",
    "KDFType",
    "KeyDerivationError",
    "default_key_derivation",
    "derive_key",
    # Hybrid encryption
    "HybridEncryption",
    "EncryptionError",
    "KeySize",
    "default_hybrid_encryption",
    "encrypt_data",
    "decrypt_data",
]

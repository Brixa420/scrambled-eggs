"""
Advanced Security Module
-----------------------

Implements advanced security features including breach detection,
behavioral analysis, memory protection, key derivation, and hybrid encryption.
"""
from .breach_detection import BreachDetector
from .behavior_analysis import BehaviorAnalyzer
from .threat_response import ThreatResponder
from .memory_protection import MemoryProtector
from .key_derivation import KeyDerivation, KDFType, KeyDerivationError, default_key_derivation, derive_key
from .hybrid_encryption import (
    HybridEncryption, 
    EncryptionError, 
    KeySize, 
    default_hybrid_encryption,
    encrypt_data,
    decrypt_data
)

__all__ = [
    # Core security components
    'BreachDetector',
    'BehaviorAnalyzer',
    'ThreatResponder',
    'MemoryProtector',
    
    # Key derivation
    'KeyDerivation',
    'KDFType',
    'KeyDerivationError',
    'default_key_derivation',
    'derive_key',
    
    # Hybrid encryption
    'HybridEncryption',
    'EncryptionError',
    'KeySize',
    'default_hybrid_encryption',
    'encrypt_data',
    'decrypt_data',
]

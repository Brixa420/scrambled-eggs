"""
Kyber Key Encapsulation Mechanism (KEM) Implementation

This module provides a Python interface to the Kyber KEM, a post-quantum
key encapsulation mechanism that is a finalist in the NIST PQC standardization
process.
"""
import os
import json
from typing import Tuple, Dict, Optional
from dataclasses import dataclass
from enum import Enum

# Try to import the reference implementation
HAS_PQCRYPTO = False
try:
    import pqcrypto
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
    from pqcrypto.kem.kyber768 import generate_keypair as generate_keypair_768
    from pqcrypto.kem.kyber768 import encrypt as encrypt_768
    from pqcrypto.kem.kyber768 import decrypt as decrypt_768
    from pqcrypto.kem.kyber1024 import generate_keypair as generate_keypair_1024
    from pqcrypto.kem.kyber1024 import encrypt as encrypt_1024
    from pqcrypto.kem.kyber1024 import decrypt as decrypt_1024
    HAS_PQCRYPTO = True
except ImportError:
    # Fallback to a pure-Python implementation if available
    try:
        from ._kyber_python import (
            generate_keypair, encrypt, decrypt,
            generate_keypair_768, encrypt_768, decrypt_768,
            generate_keypair_1024, encrypt_1024, decrypt_1024
        )
        HAS_PQCRYPTO = True
    except ImportError:
        pass


class KyberVariant(Enum):
    """Kyber security variants."""
    KYBER512 = "Kyber512"  # NIST Security Level 1
    KYBER768 = "Kyber768"  # NIST Security Level 3 (Recommended)
    KYBER1024 = "Kyber1024"  # NIST Security Level 5


@dataclass(frozen=True)
class KyberKeyPair:
    """Container for Kyber key pair."""
    public_key: bytes
    secret_key: bytes
    variant: KyberVariant = KyberVariant.KYBER768
    
    def to_dict(self) -> Dict[str, str]:
        """Serialize key pair to a dictionary."""
        return {
            'public_key': self.public_key.hex(),
            'secret_key': self.secret_key.hex(),
            'variant': self.variant.value,
            'kty': 'KYBER',
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'KyberKeyPair':
        """Deserialize key pair from a dictionary."""
        return cls(
            public_key=bytes.fromhex(data['public_key']),
            secret_key=bytes.fromhex(data['secret_key']),
            variant=KyberVariant(data.get('variant', 'Kyber768'))
        )


class KyberKEM:
    """
    Kyber Key Encapsulation Mechanism (KEM) implementation.
    
    This class provides a high-level interface to the Kyber KEM, supporting
    multiple security levels and both standard and deterministic key generation.
    """
    
    def __init__(self, variant: KyberVariant = KyberVariant.KYBER768):
        """
        Initialize the Kyber KEM with the specified security variant.
        
        Args:
            variant: The Kyber security variant to use (default: KYBER768)
        """
        if not HAS_PQCRYPTO:
            raise RuntimeError(
                "Required PQCrypto library not found. "
                "Install with: pip install pqcrypto"
            )
        
        self.variant = variant
        self._key_size = {
            KyberVariant.KYBER512: 32,
            KyberVariant.KYBER768: 32,
            KyberVariant.KYBER1024: 32
        }[variant]
        
        # Select the appropriate functions based on variant
        if variant == KyberVariant.KYBER512:
            self._generate_keypair = generate_keypair
            self._encapsulate = encrypt
            self._decapsulate = decrypt
        elif variant == KyberVariant.KYBER768:
            self._generate_keypair = generate_keypair_768
            self._encapsulate = encrypt_768
            self._decapsulate = decrypt_768
        elif variant == KyberVariant.KYBER1024:
            self._generate_keypair = generate_keypair_1024
            self._encapsulate = encrypt_1024
            self._decapsulate = decrypt_1024
        else:
            raise ValueError(f"Unsupported Kyber variant: {variant}")
    
    def generate_keypair(self, seed: Optional[bytes] = None) -> KyberKeyPair:
        """
        Generate a new Kyber key pair.
        
        Args:
            seed: Optional random seed for deterministic key generation
            
        Returns:
            A KyberKeyPair containing the public and secret keys
        """
        if seed is not None:
            # Use the seed to generate deterministic keys for testing
            if len(seed) < 64:  # Ensure sufficient entropy
                seed = self._stretch_seed(seed)
            
            # Use the seed to initialize a deterministic RNG
            rng = self._get_deterministic_rng(seed)
            
            # Generate key pair using the deterministic RNG
            public_key, secret_key = self._generate_keypair(rng)
        else:
            # Use system's secure RNG
            public_key, secret_key = self._generate_keypair()
        
        return KyberKeyPair(public_key, secret_key, self.variant)
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Generate a shared secret and its encapsulation.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            A tuple of (shared_secret, ciphertext)
        """
        try:
            ciphertext, shared_secret = self._encapsulate(public_key)
            return shared_secret, ciphertext
        except Exception as e:
            raise ValueError(f"Encapsulation failed: {str(e)}")
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using the recipient's secret key.
        
        Args:
            ciphertext: The encapsulated shared secret
            secret_key: The recipient's secret key
            
        Returns:
            The shared secret
        """
        try:
            return self._decapsulate(ciphertext, secret_key)
        except Exception as e:
            raise ValueError(f"Decapsulation failed: {str(e)}")
    
    def _stretch_seed(self, seed: bytes, output_length: int = 64) -> bytes:
        """Stretch a seed to the required length using HKDF."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        hkdf = HKDF(
            algorithm=hashes.SHAKE256(output_length),
            length=output_length,
            salt=None,
            info=b'KyberKEM seed stretching',
        )
        return hkdf.derive(seed)
    
    def _get_deterministic_rng(self, seed: bytes):
        """Get a deterministic RNG for testing purposes."""
        # This is a simple PRNG for testing only
        # In production, always use the system's secure RNG
        class SimpleRNG:
            def __init__(self, seed):
                self.state = seed
                self.pos = 0
            
            def __call__(self, length: int) -> bytes:
                result = bytearray()
                while len(result) < length:
                    # Simple PRNG (not cryptographically secure)
                    self.state = hashlib.sha256(self.state + bytes([self.pos])).digest()
                    result.extend(self.state)
                    self.pos += 1
                return bytes(result[:length])
        
        return SimpleRNG(seed)


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a Kyber key pair (compatibility wrapper)."""
    return KyberKEM().generate_keypair()

def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret (compatibility wrapper)."""
    return KyberKEM().encapsulate(public_key)

def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Decapsulate a shared secret (compatibility wrapper)."""
    return KyberKEM().decapsulate(ciphertext, secret_key)

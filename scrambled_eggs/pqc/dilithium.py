"""
Dilithium Digital Signature Scheme Implementation

This module provides a Python interface to the Dilithium digital signature scheme,
a post-quantum signature algorithm that is a finalist in the NIST PQC
standardization process.
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
    from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
    from pqcrypto.sign.dilithium3 import generate_keypair as generate_keypair_3
    from pqcrypto.sign.dilithium3 import sign as sign_3
    from pqcrypto.sign.dilithium3 import verify as verify_3
    from pqcrypto.sign.dilithium5 import generate_keypair as generate_keypair_5
    from pqcrypto.sign.dilithium5 import sign as sign_5
    from pqcrypto.sign.dilithium5 import verify as verify_5
    HAS_PQCRYPTO = True
except ImportError:
    # Fallback to a pure-Python implementation if available
    try:
        from ._dilithium_python import (
            generate_keypair, sign, verify,
            generate_keypair_3, sign_3, verify_3,
            generate_keypair_5, sign_5, verify_5
        )
        HAS_PQCRYPTO = True
    except ImportError:
        pass


class DilithiumVariant(Enum):
    """Dilithium security variants."""
    DILITHIUM2 = "Dilithium2"  # NIST Security Level 2
    DILITHIUM3 = "Dilithium3"  # NIST Security Level 3 (Recommended)
    DILITHIUM5 = "Dilithium5"  # NIST Security Level 5


@dataclass(frozen=True)
class DilithiumKeyPair:
    """Container for Dilithium key pair."""
    public_key: bytes
    secret_key: bytes
    variant: DilithiumVariant = DilithiumVariant.DILITHIUM3
    
    def to_dict(self) -> Dict[str, str]:
        """Serialize key pair to a dictionary."""
        return {
            'public_key': self.public_key.hex(),
            'secret_key': self.secret_key.hex(),
            'variant': self.variant.value,
            'kty': 'DILITHIUM',
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'DilithiumKeyPair':
        """Deserialize key pair from a dictionary."""
        return cls(
            public_key=bytes.fromhex(data['public_key']),
            secret_key=bytes.fromhex(data['secret_key']),
            variant=DilithiumVariant(data.get('variant', 'Dilithium3'))
        )


class Dilithium:
    """
    Dilithium Digital Signature Scheme implementation.
    
    This class provides a high-level interface to the Dilithium signature scheme,
    supporting multiple security levels and both standard and deterministic key generation.
    """
    
    def __init__(self, variant: DilithiumVariant = DilithiumVariant.DILITHIUM3):
        """
        Initialize the Dilithium signature scheme with the specified security variant.
        
        Args:
            variant: The Dilithium security variant to use (default: DILITHIUM3)
        """
        if not HAS_PQCRYPTO:
            raise RuntimeError(
                "Required PQCrypto library not found. "
                "Install with: pip install pqcrypto"
            )
        
        self.variant = variant
        
        # Select the appropriate functions based on variant
        if variant == DilithiumVariant.DILITHIUM2:
            self._generate_keypair = generate_keypair
            self._sign = sign
            self._verify = verify
        elif variant == DilithiumVariant.DILITHIUM3:
            self._generate_keypair = generate_keypair_3
            self._sign = sign_3
            self._verify = verify_3
        elif variant == DilithiumVariant.DILITHIUM5:
            self._generate_keypair = generate_keypair_5
            self._sign = sign_5
            self._verify = verify_5
        else:
            raise ValueError(f"Unsupported Dilithium variant: {variant}")
    
    def generate_keypair(self, seed: Optional[bytes] = None) -> DilithiumKeyPair:
        """
        Generate a new Dilithium key pair.
        
        Args:
            seed: Optional random seed for deterministic key generation
            
        Returns:
            A DilithiumKeyPair containing the public and secret keys
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
        
        return DilithiumKeyPair(public_key, secret_key, self.variant)
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message using the secret key.
        
        Args:
            message: The message to sign
            secret_key: The signer's secret key
            
        Returns:
            The signature
        """
        try:
            return self._sign(secret_key, message)
        except Exception as e:
            raise ValueError(f"Signing failed: {str(e)}")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature on a message using the public key.
        
        Args:
            message: The message that was signed
            signature: The signature to verify
            public_key: The signer's public key
            
        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            self._verify(public_key, message, signature)
            return True
        except (ValueError, Exception):
            return False
    
    def _stretch_seed(self, seed: bytes, output_length: int = 64) -> bytes:
        """Stretch a seed to the required length using HKDF."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        hkdf = HKDF(
            algorithm=hashes.SHAKE256(output_length),
            length=output_length,
            salt=None,
            info=b'Dilithium seed stretching',
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
    """Generate a Dilithium key pair (compatibility wrapper)."""
    return Dilithium().generate_keypair()

def sign(message: bytes, secret_key: bytes) -> bytes:
    """Sign a message (compatibility wrapper)."""
    return Dilithium().sign(message, secret_key)

def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a signature (compatibility wrapper)."""
    return Dilithium().verify(message, signature, public_key)

"""
Key Derivation Module
-------------------

Implements secure key derivation functions for generating cryptographic keys
from passwords or other low-entropy sources.
"""
import os
import hmac
import hashlib
import struct
from typing import Optional, Union, Tuple, List, Dict, Any
from enum import Enum, auto

# Try to import Argon2 if available
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

class KDFType(Enum):
    """Key Derivation Function types."""
    PBKDF2 = auto()
    SCRYPT = auto()
    ARGON2 = auto()
    HKDF = auto()
    BCRYPT = auto()

class KeyDerivationError(Exception):
    """Base exception for key derivation errors."""
    pass

class KeyDerivation:
    """A class for secure key derivation from passwords."""
    
    DEFAULT_ITERATIONS = {
        KDFType.PBKDF2: 600000,  # ~100ms on modern hardware
        KDFType.SCRYPT: 16384,   # N parameter for scrypt
        KDFType.ARGON2: 3,       # Time cost for Argon2
    }
    
    DEFAULT_HASH_ALG = 'sha256'
    
    def __init__(self, 
                 kdf_type: KDFType = KDFType.ARGON2 if HAS_ARGON2 else KDFType.PBKDF2,
                 hash_alg: str = DEFAULT_HASH_ALG,
                 salt: Optional[bytes] = None,
                 iterations: Optional[int] = None,
                 **kwargs):
        """Initialize the key derivation function.
        
        Args:
            kdf_type: The type of KDF to use (default: Argon2 if available, else PBKDF2)
            hash_alg: Hash algorithm to use (for PBKDF2 and HKDF)
            salt: Optional salt (randomly generated if not provided)
            iterations: Number of iterations (defaults based on KDF type)
            **kwargs: Additional parameters for specific KDFs
        """
        self.kdf_type = kdf_type
        self.hash_alg = hash_alg
        self.salt = salt or os.urandom(32)
        
        # Set default iterations if not specified
        if iterations is None:
            self.iterations = self.DEFAULT_ITERATIONS.get(kdf_type, 100000)
        else:
            self.iterations = iterations
            
        # KDF-specific parameters
        self.kwargs = kwargs
        
    def derive(self, password: Union[str, bytes], key_length: int = 32) -> bytes:
        """Derive a key from a password.
        
        Args:
            password: The password to derive the key from
            key_length: Desired key length in bytes
            
        Returns:
            Derived key as bytes
            
        Raises:
            KeyDerivationError: If key derivation fails
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        try:
            if self.kdf_type == KDFType.PBKDF2:
                return self._pbkdf2_derive(password, key_length)
            elif self.kdf_type == KDFType.SCRYPT:
                return self._scrypt_derive(password, key_length)
            elif self.kdf_type == KDFType.ARGON2:
                if not HAS_ARGON2:
                    raise KeyDerivationError("Argon2 is not available. Install with: pip install argon2-cffi")
                return self._argon2_derive(password, key_length)
            elif self.kdf_type == KDFType.HKDF:
                return self._hkdf_derive(password, key_length)
            else:
                raise KeyDerivationError(f"Unsupported KDF type: {self.kdf_type}")
        except Exception as e:
            raise KeyDerivationError(f"Key derivation failed: {e}") from e
    
    def _pbkdf2_derive(self, password: bytes, key_length: int) -> bytes:
        """Derive a key using PBKDF2."""
        import hmac
        import hashlib
        
        # Get the hash function
        hash_func = getattr(hashlib, self.hash_alg, None)
        if not hash_func:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_alg}")
            
        # Derive the key
        dk = hashlib.pbkdf2_hmac(
            hash_name=self.hash_alg,
            password=password,
            salt=self.salt,
            iterations=self.iterations,
            dklen=key_length
        )
        
        return dk
    
    def _scrypt_derive(self, password: bytes, key_length: int) -> bytes:
        """Derive a key using scrypt."""
        import hashlib
        
        # Get scrypt parameters
        n = self.kwargs.get('n', self.iterations)  # CPU/memory cost
        r = self.kwargs.get('r', 8)                # block size
        p = self.kwargs.get('p', 1)                # parallelization
        
        # Derive the key
        dk = hashlib.scrypt(
            password=password,
            salt=self.salt,
            n=n,
            r=r,
            p=p,
            dklen=key_length
        )
        
        return dk
    
    def _argon2_derive(self, password: bytes, key_length: int) -> bytes:
        """Derive a key using Argon2."""
        if not HAS_ARGON2:
            raise KeyDerivationError("Argon2 is not available. Install with: pip install argon2-cffi")
            
        # Get Argon2 parameters
        time_cost = self.kwargs.get('time_cost', self.iterations)
        memory_cost = self.kwargs.get('memory_cost', 65536)  # 64MB
        parallelism = self.kwargs.get('parallelism', 4)
        
        # Derive the key
        dk = hash_secret_raw(
            secret=password,
            salt=self.salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=Argon2Type.ID
        )
        
        return dk
    
    def _hkdf_derive(self, password: bytes, key_length: int) -> bytes:
        """Derive a key using HKDF."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.backends import default_backend
        
        # Get the hash algorithm
        hash_alg = getattr(hashes, self.hash_alg.upper(), None)
        if not hash_alg:
            raise ValueError(f"Unsupported hash algorithm for HKDF: {self.hash_alg}")
        
        # Derive the key
        hkdf = HKDF(
            algorithm=hash_alg(),
            length=key_length,
            salt=self.salt,
            info=self.kwargs.get('info', b'scrambled-eggs-hkdf-info'),
            backend=default_backend()
        )
        
        return hkdf.derive(password)
    
    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'KeyDerivation':
        """Create a KeyDerivation instance from a configuration dictionary."""
        kdf_type = KDFType[config.get('type', 'ARGON2' if HAS_ARGON2 else 'PBKDF2')]
        hash_alg = config.get('hash_alg', cls.DEFAULT_HASH_ALG)
        salt = config.get('salt')
        if salt and isinstance(salt, str):
            salt = bytes.fromhex(salt)
        iterations = config.get('iterations')
        
        return cls(
            kdf_type=kdf_type,
            hash_alg=hash_alg,
            salt=salt,
            iterations=iterations,
            **{k: v for k, v in config.items() 
               if k not in ('type', 'hash_alg', 'salt', 'iterations')}
        )
    
    def to_config(self) -> Dict[str, Any]:
        """Convert the KeyDerivation instance to a configuration dictionary."""
        config = {
            'type': self.kdf_type.name,
            'hash_alg': self.hash_alg,
            'salt': self.salt.hex(),
            'iterations': self.iterations,
            **self.kwargs
        }
        return config
    
    def __eq__(self, other: object) -> bool:
        """Check if two KeyDerivation instances are equal."""
        if not isinstance(other, KeyDerivation):
            return False
            
        return (self.kdf_type == other.kdf_type and
                self.hash_alg == other.hash_alg and
                self.salt == other.salt and
                self.iterations == other.iterations and
                self.kwargs == other.kwargs)

# Default key derivation instance for convenience
default_key_derivation = KeyDerivation()

def derive_key(password: Union[str, bytes], 
              salt: Optional[bytes] = None, 
              key_length: int = 32,
              **kwargs) -> bytes:
    """Convenience function to derive a key from a password.
    
    Args:
        password: The password to derive the key from
        salt: Optional salt (randomly generated if not provided)
        key_length: Desired key length in bytes
        **kwargs: Additional arguments to pass to KeyDerivation
        
    Returns:
        Derived key as bytes
    """
    kdf = KeyDerivation(salt=salt, **kwargs)
    return kdf.derive(password, key_length)

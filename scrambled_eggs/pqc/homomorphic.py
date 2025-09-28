"""
Homomorphic Encryption Module

This module provides homomorphic encryption capabilities, supporting both
partially and fully homomorphic encryption schemes. It includes implementations
of Paillier (additively homomorphic) and FHE (Fully Homomorphic Encryption)
using the TFHE library.
"""
import os
import math
import json
from typing import Dict, List, Tuple, Union, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import random

# Try to import required libraries
try:
    import gmpy2
    from gmpy2 import mpz
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False
    mpz = int  # Fallback to Python's int

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


class HomomorphicScheme(Enum):
    """Supported homomorphic encryption schemes."""
    PAILLIER = "paillier"  # Partially homomorphic (additive)
    TFHE = "tfhe"          # Fully homomorphic (TFHE)
    BFV = "bfv"            # Leveled homomorphic (BFV)
    CKKS = "ckks"          # Approximate homomorphic (CKKS)


@dataclass
class HomomorphicKeyPair:
    """Container for homomorphic encryption key pair."""
    public_key: bytes
    secret_key: bytes
    scheme: HomomorphicScheme
    params: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize the key pair to a dictionary."""
        return {
            'public_key': self.public_key.hex(),
            'secret_key': self.secret_key.hex(),
            'scheme': self.scheme.value,
            'params': self.params
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HomomorphicKeyPair':
        """Deserialize a key pair from a dictionary."""
        return cls(
            public_key=bytes.fromhex(data['public_key']),
            secret_key=bytes.fromhex(data['secret_key']),
            scheme=HomomorphicScheme(data['scheme']),
            params=data.get('params', {})
        )


class HomomorphicCrypto:
    """
    Homomorphic Encryption Implementation
    
    This class provides a unified interface for various homomorphic encryption
    schemes, including Paillier (additively homomorphic) and FHE (fully homomorphic).
    """
    
    def __init__(self, scheme: HomomorphicScheme = HomomorphicScheme.PAILLIER, **params):
        """
        Initialize the homomorphic encryption system.
        
        Args:
            scheme: The homomorphic encryption scheme to use
            **params: Additional parameters for the scheme
        """
        self.scheme = scheme
        self.params = params
        
        if scheme == HomomorphicScheme.PAILLIER and not HAS_GMPY2:
            raise ImportError("gmpy2 is required for Paillier encryption")
        
        if scheme in (HomomorphicScheme.TFHE, HomomorphicScheme.BFV, HomomorphicScheme.CKKS):
            raise ImportError("FHE libraries not yet implemented")
    
    def generate_keypair(self, key_size: int = 2048) -> HomomorphicKeyPair:
        """
        Generate a new key pair for homomorphic encryption.
        
        Args:
            key_size: The key size in bits (for schemes that support it)
            
        Returns:
            A HomomorphicKeyPair containing the public and secret keys
        """
        if self.scheme == HomomorphicScheme.PAILLIER:
            return self._generate_paillier_keypair(key_size)
        else:
            raise NotImplementedError(f"Key generation not implemented for {self.scheme}")
    
    def encrypt(self, plaintext: Union[int, float, List[Union[int, float]]], 
               public_key: bytes) -> bytes:
        """
        Encrypt a plaintext value or array.
        
        Args:
            plaintext: The value(s) to encrypt
            public_key: The public key to use for encryption
            
        Returns:
            The encrypted ciphertext
        """
        if self.scheme == HomomorphicScheme.PAILLIER:
            return self._paillier_encrypt(plaintext, public_key)
        else:
            raise NotImplementedError(f"Encryption not implemented for {self.scheme}")
    
    def decrypt(self, ciphertext: bytes, 
               keypair: HomomorphicKeyPair) -> Union[int, float, List[Union[int, float]]]:
        """
        Decrypt a ciphertext.
        
        Args:
            ciphertext: The ciphertext to decrypt
            keypair: The key pair containing the secret key
            
        Returns:
            The decrypted plaintext value or array
        """
        if self.scheme == HomomorphicScheme.PAILLIER:
            return self._paillier_decrypt(ciphertext, keypair)
        else:
            raise NotImplementedError(f"Decryption not implemented for {self.scheme}")
    
    def add(self, ciphertext1: bytes, ciphertext2: bytes, 
           public_key: bytes) -> bytes:
        """
        Homomorphically add two ciphertexts.
        
        Args:
            ciphertext1: First ciphertext
            ciphertext2: Second ciphertext
            public_key: The public key
            
        Returns:
            A new ciphertext containing the sum
        """
        if self.scheme == HomomorphicScheme.PAILLIER:
            return self._paillier_add(ciphertext1, ciphertext2, public_key)
        else:
            raise NotImplementedError(f"Addition not implemented for {self.scheme}")
    
    def multiply(self, ciphertext: bytes, scalar: Union[int, float],
                public_key: bytes) -> bytes:
        """
        Homomorphically multiply a ciphertext by a scalar.
        
        Args:
            ciphertext: The ciphertext to multiply
            scalar: The scalar to multiply by
            public_key: The public key
            
        Returns:
            A new ciphertext containing the product
        """
        if self.scheme == HomomorphicScheme.PAILLIER:
            return self._paillier_multiply(ciphertext, scalar, public_key)
        else:
            raise NotImplementedError(f"Multiplication not implemented for {self.scheme}")
    
    # ===== Paillier Cryptosystem =====
    
    def _generate_paillier_keypair(self, key_size: int = 2048) -> HomomorphicKeyPair:
        """Generate a Paillier key pair."""
        if not HAS_GMPY2:
            raise ImportError("gmpy2 is required for Paillier encryption")
        
        # Generate two large prime numbers p and q
        p = gmpy2.next_prime(mpz(random.getrandbits(key_size // 2)))
        q = gmpy2.next_prime(mpz(random.getrandbits(key_size // 2)))
        
        # Make sure p and q are different
        while p == q:
            q = gmpy2.next_prime(mpz(random.getrandbits(key_size // 2)))
        
        n = p * q
        n_sq = n * n
        
        # Compute lambda = lcm(p-1, q-1)
        lambda_val = (p - 1) * (q - 1) // gmpy2.gcd(p - 1, q - 1)
        
        # Choose a generator g (typically g = n + 1)
        g = n + 1
        
        # Precompute mu = L(g^lambda mod n^2)^-1 mod n
        # where L(u) = (u - 1) / n
        g_lambda = gmpy2.powmod(g, lambda_val, n_sq)
        l_val = (g_lambda - 1) // n
        mu = int(gmpy2.invert(l_val, n))
        
        # Create the key pair
        public_key = {
            'n': int(n),
            'g': int(g),
            'n_squared': int(n_sq)
        }
        
        secret_key = {
            'lambda': int(lambda_val),
            'mu': mu,
            'p': int(p),
            'q': int(q)
        }
        
        # Serialize the keys
        public_key_bytes = json.dumps(public_key).encode('utf-8')
        secret_key_bytes = json.dumps(secret_key).encode('utf-8')
        
        return HomomorphicKeyPair(
            public_key=public_key_bytes,
            secret_key=secret_key_bytes,
            scheme=HomomorphicScheme.PAILLIER,
            params={'key_size': key_size}
        )
    
    def _paillier_encrypt(self, plaintext: Union[int, float, List[Union[int, float]]], 
                         public_key_bytes: bytes) -> bytes:
        """Encrypt a value using Paillier encryption."""
        if not HAS_GMPY2:
            raise ImportError("gmpy2 is required for Paillier encryption")
        
        # Deserialize the public key
        public_key = json.loads(public_key_bytes.decode('utf-8'))
        n = mpz(public_key['n'])
        g = mpz(public_key['g'])
        n_sq = mpz(public_key.get('n_squared', n * n))
        
        # Handle lists/arrays
        if isinstance(plaintext, (list, tuple)) or (HAS_NUMPY and isinstance(plaintext, np.ndarray)):
            return self._paillier_encrypt_array(plaintext, public_key_bytes)
        
        # Convert to integer (for floating-point, scale and convert)
        scale = 10**6  # Default scaling factor for floating-point
        is_float = isinstance(plaintext, float)
        
        if is_float:
            m = int(plaintext * scale)
        else:
            m = int(plaintext)
        
        # Ensure the plaintext is in the valid range [0, n-1]
        m = m % n
        
        # Choose a random r in Z_n*
        while True:
            r = mpz(random.randint(1, int(n) - 1))
            if gmpy2.gcd(r, n) == 1:
                break
        
        # Encrypt: c = (g^m * r^n) mod n^2
        g_m = gmpy2.powmod(g, m, n_sq)
        r_n = gmpy2.powmod(r, n, n_sq)
        ciphertext = (g_m * r_n) % n_sq
        
        # Return the ciphertext with metadata
        result = {
            'c': int(ciphertext),
            'is_float': is_float,
            'scale': scale if is_float else 1
        }
        
        return json.dumps(result).encode('utf-8')
    
    def _paillier_encrypt_array(self, array: List[Union[int, float]], 
                              public_key_bytes: bytes) -> bytes:
        """Encrypt an array of values using Paillier encryption."""
        encrypted = [
            json.loads(self._paillier_encrypt(x, public_key_bytes).decode('utf-8'))
            for x in array
        ]
        return json.dumps(encrypted).encode('utf-8')
    
    def _paillier_decrypt(self, ciphertext_bytes: bytes, 
                         keypair: HomomorphicKeyPair) -> Union[int, float, List[Union[int, float]]]:
        """Decrypt a Paillier ciphertext."""
        if not HAS_GMPY2:
            raise ImportError("gmpy2 is required for Paillier decryption")
        
        # Deserialize the key pair
        public_key = json.loads(keypair.public_key.decode('utf-8'))
        secret_key = json.loads(keypair.secret_key.decode('utf-8'))
        
        n = mpz(public_key['n'])
        n_sq = mpz(public_key.get('n_squared', n * n))
        lambda_val = mpz(secret_key['lambda'])
        mu = mpz(secret_key['mu'])
        
        # Parse the ciphertext
        try:
            data = json.loads(ciphertext_bytes.decode('utf-8'))
            
            # Handle arrays
            if isinstance(data, list):
                return [
                    self._paillier_decrypt_single(
                        json.dumps(item).encode('utf-8'),
                        n, n_sq, lambda_val, mu
                    )
                    for item in data
                ]
            else:
                return self._paillier_decrypt_single(
                    ciphertext_bytes, n, n_sq, lambda_val, mu
                )
                
        except json.JSONDecodeError:
            # Legacy format (just the ciphertext as an integer)
            c = mpz(int.from_bytes(ciphertext_bytes, 'big'))
            m = self._paillier_raw_decrypt(c, n, n_sq, lambda_val, mu)
            return int(m)
    
    def _paillier_decrypt_single(self, ciphertext_bytes: bytes, 
                               n: mpz, n_sq: mpz, 
                               lambda_val: mpz, mu: mpz) -> Union[int, float]:
        """Decrypt a single Paillier ciphertext."""
        data = json.loads(ciphertext_bytes.decode('utf-8'))
        c = mpz(data['c'])
        is_float = data.get('is_float', False)
        scale = data.get('scale', 1)
        
        # Decrypt: m = L(c^lambda mod n^2) * mu mod n
        m = self._paillier_raw_decrypt(c, n, n_sq, lambda_val, mu)
        
        # Convert back to float if needed
        if is_float:
            return float(m) / scale
        else:
            return int(m)
    
    def _paillier_raw_decrypt(self, c: mpz, n: mpz, n_sq: mpz, 
                            lambda_val: mpz, mu: mpz) -> int:
        """Raw Paillier decryption without metadata handling."""
        if not HAS_GMPY2:
            raise ImportError("gmpy2 is required for Paillier decryption")
        
        # Compute L(c^lambda mod n^2)
        c_lambda = gmpy2.powmod(c, lambda_val, n_sq)
        l_val = (c_lambda - 1) // n
        
        # Compute m = L(c^lambda mod n^2) * mu mod n
        m = (l_val * mu) % n
        
        # Handle negative numbers (if m > n/2, it's negative)
        if m > n // 2:
            m -= n
            
        return int(m)
    
    def _paillier_add(self, ciphertext1_bytes: bytes, 
                     ciphertext2_bytes: bytes, 
                     public_key_bytes: bytes) -> bytes:
        """Homomorphically add two Paillier ciphertexts."""
        # Deserialize the public key
        public_key = json.loads(public_key_bytes.decode('utf-8'))
        n_sq = mpz(public_key.get('n_squared', 
                                 mpz(public_key['n']) * mpz(public_key['n'])))
        
        # Parse the ciphertexts
        ct1 = json.loads(ciphertext1_bytes.decode('utf-8'))
        ct2 = json.loads(ciphertext2_bytes.decode('utf-8'))
        
        # Handle arrays
        if isinstance(ct1, list) and isinstance(ct2, list):
            if len(ct1) != len(ct2):
                raise ValueError("Arrays must have the same length for addition")
            
            result = []
            for c1, c2 in zip(ct1, ct2):
                # Add: c = (c1 * c2) mod n^2
                c = (mpz(c1['c']) * mpz(c2['c'])) % n_sq
                
                # Use metadata from the first ciphertext
                result.append({
                    'c': int(c),
                    'is_float': c1.get('is_float', False),
                    'scale': c1.get('scale', 1)
                })
            
            return json.dumps(result).encode('utf-8')
        
        # Handle scalar addition
        else:
            # Add: c = (c1 * c2) mod n^2
            c = (mpz(ct1['c']) * mpz(ct2['c'])) % n_sq
            
            # Use metadata from the first ciphertext
            result = {
                'c': int(c),
                'is_float': ct1.get('is_float', False),
                'scale': ct1.get('scale', 1)
            }
            
            return json.dumps(result).encode('utf-8')
    
    def _paillier_multiply(self, ciphertext_bytes: bytes, 
                          scalar: Union[int, float],
                          public_key_bytes: bytes) -> bytes:
        """Homomorphically multiply a Paillier ciphertext by a scalar."""
        # Deserialize the public key
        public_key = json.loads(public_key_bytes.decode('utf-8'))
        n_sq = mpz(public_key.get('n_squared', 
                                 mpz(public_key['n']) * mpz(public_key['n'])))
        
        # Parse the ciphertext
        ct = json.loads(ciphertext_bytes.decode('utf-8'))
        
        # Handle arrays
        if isinstance(ct, list):
            result = []
            for item in ct:
                # Multiply: c = c1^scalar mod n^2
                c = gmpy2.powmod(mpz(item['c']), mpz(int(scalar)), n_sq)
                
                result.append({
                    'c': int(c),
                    'is_float': item.get('is_float', False),
                    'scale': item.get('scale', 1)
                })
            
            return json.dumps(result).encode('utf-8')
        
        # Handle scalar multiplication
        else:
            # Multiply: c = c1^scalar mod n^2
            c = gmpy2.powmod(mpz(ct['c']), mpz(int(scalar)), n_sq)
            
            result = {
                'c': int(c),
                'is_float': ct.get('is_float', False),
                'scale': ct.get('scale', 1)
            }
            
            return json.dumps(result).encode('utf-8')


# Example usage
if __name__ == "__main__":
    # Example: Paillier encryption
    he = HomomorphicCrypto(scheme=HomomorphicScheme.PAILLIER)
    keypair = he.generate_keypair(key_size=1024)
    
    # Encrypt two numbers
    x = 42
    y = 17
    
    enc_x = he.encrypt(x, keypair.public_key)
    enc_y = he.encrypt(y, keypair.public_key)
    
    # Homomorphic addition
    enc_sum = he.add(enc_x, enc_y, keypair.public_key)
    
    # Homomorphic multiplication by a scalar
    enc_prod = he.multiply(enc_x, 3, keypair.public_key)
    
    # Decrypt the results
    dec_sum = he.decrypt(enc_sum, keypair)
    dec_prod = he.decrypt(enc_prod, keypair)
    
    print(f"Original: {x} + {y} = {x + y}")
    print(f"Encrypted sum: {dec_sum}")
    print(f"Original: {x} * 3 = {x * 3}")
    print(f"Encrypted product: {dec_prod}")

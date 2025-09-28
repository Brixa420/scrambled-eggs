"""
Enhanced security utilities for Scrambled Eggs.
"""
import os
import hmac
import hashlib
import struct
from typing import Tuple, Optional

# Third-party imports for enhanced security
import argon2
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class KeyDerivation:
    """Enhanced key derivation with Argon2 and PBKDF2."""
    
    @staticmethod
    def derive_key(
        password: bytes,
        salt: Optional[bytes] = None,
        iterations: int = 100000,
        memory_cost: int = 65536,
        parallelism: int = 4,
        key_length: int = 32
    ) -> Tuple[bytes, bytes]:
        """
        Derive a secure key using Argon2.
        
        Args:
            password: The password to derive key from
            salt: Optional salt (generated if not provided)
            iterations: Number of iterations
            memory_cost: Memory cost parameter for Argon2
            parallelism: Parallelism parameter for Argon2
            key_length: Length of the derived key in bytes
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(16)
            
        # Use Argon2 for key derivation
        hasher = argon2.PasswordHasher(
            time_cost=iterations,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            salt_len=len(salt)
        )
        
        # Derive key using Argon2
        key_hex = hasher.using(secret=password, salt=salt).hash("")
        key = bytes.fromhex(key_hex.split('$')[-1])
        
        return key, salt

class HybridEncryption:
    """Hybrid encryption using RSA and AES-GCM."""
    
    @staticmethod
    def generate_key_pair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, bytes]:
        """Generate RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_key, public_bytes
    
    @staticmethod
    def encrypt_with_public_key(
        public_key_pem: bytes,
        data: bytes
    ) -> bytes:
        """Encrypt data with RSA public key."""
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Encrypt with RSA-OAEP
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    @staticmethod
    def decrypt_with_private_key(
        private_key: rsa.RSAPrivateKey,
        ciphertext: bytes
    ) -> bytes:
        """Decrypt data with RSA private key."""
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            raise DecryptionError(f"RSA decryption failed: {str(e)}")

class MemoryProtection:
    """Utilities for secure memory handling."""
    
    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def secure_erase(data: bytearray) -> None:
        """Securely erase sensitive data from memory."""
        for i in range(len(data)):
            data[i] = 0
        
        # Force garbage collection
        import gc
        gc.collect()

class BreachDetector:
    """Advanced breach detection system."""
    
    def __init__(self, threshold: float = 0.8):
        """
        Initialize breach detector.
        
        Args:
            threshold: Suspicion threshold (0.0 to 1.0)
        """
        self.suspicion_level = 0.0
        self.threshold = threshold
        self.attempts = 0
        self.last_attempt = 0
    
    def analyze_attempt(self, timestamp: float) -> bool:
        """
        Analyze an authentication attempt.
        
        Args:
            timestamp: Timestamp of the attempt
            
        Returns:
            bool: True if breach is detected
        """
        self.attempts += 1
        current_time = time.time()
        
        # Time-based analysis
        if self.last_attempt > 0:
            time_diff = current_time - self.last_attempt
            if time_diff < 0.1:  # Suspiciously fast
                self.suspicion_level += 0.3
            elif time_diff < 1.0:  # Somewhat fast
                self.suspicion_level += 0.1
        
        self.last_attempt = current_time
        
        # Reset suspicion level if it's been a while
        if current_time - self.last_attempt > 300:  # 5 minutes
            self.suspicion_level = max(0, self.suspicion_level - 0.5)
        
        # Check if breach is detected
        if self.suspicion_level >= self.threshold:
            return True
            
        return False
    
    def reset(self) -> None:
        """Reset the breach detector."""
        self.suspicion_level = 0.0
        self.attempts = 0
        self.last_attempt = 0

"""
Scrambled Eggs Encryption Implementation

A secure multi-layered encryption protocol designed for maximum security.
Combines AES-256, ChaCha20, and custom obfuscation techniques.

This module provides a secure encryption service that supports multiple encryption
algorithms, including AES-256-GCM, ChaCha20-Poly1305, and a custom obfuscation
technique called Scrambled Eggs. It also provides key derivation and message
authentication using HMAC.

The encryption service is designed to be secure, flexible, and easy to use.
It provides a simple API for encrypting and decrypting data, as well as
deriving keys from passwords and salts.

The module is designed to be used in a variety of applications, including
file encryption, network communication, and secure data storage.

The encryption service is implemented using the cryptography library, which
provides a secure and well-tested implementation of various encryption
algorithms.

The module is designed to be secure, flexible, and easy to use. It provides a
simple API for encrypting and decrypting data, as well as deriving keys from
passwords and salts.

The encryption service is implemented using the cryptography library, which
provides a secure and well-tested implementation of various encryption
algorithms.
"""
import os
import hmac
import hashlib
from typing import Tuple, Optional
from dataclasses import dataclass
from enum import Enum, auto

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac as hmac_lib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

class EncryptionLayer(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = auto()
    CHACHA20_POLY1305 = auto()
    SCRAMBLED_EGGS = auto()

@dataclass
class EncryptionResult:
    """Result of an encryption operation."""
    ciphertext: bytes
    key: bytes
    salt: bytes
    iv: bytes
    auth_tag: Optional[bytes] = None
    hmac_digest: Optional[bytes] = None

class ScrambledEggsCrypto:
    """
    Scrambled Eggs Encryption Protocol
    
    A multi-layered encryption system that combines:
    1. AES-256-GCM for authenticated encryption
    2. ChaCha20-Poly1305 for additional security
    3. Custom key derivation with PBKDF2 and Scrypt
    4. HMAC for message authentication
    5. Key rotation and re-encryption support
    """
    
    # Default parameters
    SALT_SIZE = 32
    KEY_SIZE = 32  # 256 bits
    IV_SIZE = 12   # 96 bits for GCM
    ITERATIONS = 100000
    BLOCK_SIZE = 16  # AES block size in bytes
    
    def __init__(self, default_layer: EncryptionLayer = EncryptionLayer.SCRAMBLED_EGGS):
        """Initialize the encryption service."""
        self.default_layer = default_layer
        self.backend = default_backend()
    
    def generate_key(self, size: int = KEY_SIZE) -> bytes:
        """Generate a secure random key."""
        return os.urandom(size)
    
    def generate_salt(self, size: int = SALT_SIZE) -> bytes:
        """Generate a secure random salt."""
        return os.urandom(size)
    
    def derive_key(self, password: bytes, salt: bytes, key_length: int = KEY_SIZE) -> bytes:
        """Derive a secure key from a password and salt."""
        # First pass with PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self.backend
        )
        
        # Second pass with Scrypt
        kdf2 = Scrypt(
            salt=salt,
            length=key_length,
            n=2**14,  # CPU/memory cost parameter
            r=8,      # Block size parameter
            p=1,      # Parallelization parameter
            backend=self.backend
        )
        
        key1 = kdf.derive(password)
        key2 = kdf2.derive(password)
        
        # XOR the two derived keys for added security
        return bytes(a ^ b for a, b in zip(key1, key2))
    
    def encrypt(self, data: bytes, key: bytes = None, layer: EncryptionLayer = None) -> EncryptionResult:
        """
        Encrypt data using the specified encryption layer.
        
        Args:
            data: The data to encrypt
            key: Optional encryption key (generated if not provided)
            layer: Encryption layer to use (defaults to SCRAMBLED_EGGS)
            
        Returns:
            EncryptionResult containing ciphertext and metadata
        """
        if layer is None:
            layer = self.default_layer
        
        # Generate a random salt and IV
        salt = self.generate_salt()
        iv = os.urandom(self.IV_SIZE)
        
        # Derive a key if none provided
        if key is None:
            key = self.generate_key()
        
        # Encrypt using the selected layer
        if layer == EncryptionLayer.AES_256_GCM:
            return self._encrypt_aes_gcm(data, key, salt, iv)
        elif layer == EncryptionLayer.CHACHA20_POLY1305:
            return self._encrypt_chacha20_poly1305(data, key, salt, iv)
        elif layer == EncryptionLayer.SCRAMBLED_EGGS:
            return self._encrypt_scrambled_eggs(data, key, salt, iv)
        else:
            raise ValueError(f"Unsupported encryption layer: {layer}")
    
    def decrypt(self, encrypted_data: EncryptionResult, key: bytes = None) -> bytes:
        """
        Decrypt data using the specified encryption result.
        
        Args:
            encrypted_data: The encrypted data and metadata
            key: The encryption key (required if not stored in the result)
            
        Returns:
            Decrypted data
        """
        if not isinstance(encrypted_data, EncryptionResult):
            raise ValueError("Invalid encrypted data format")
        
        # Use the key from the result if available
        if key is None and hasattr(encrypted_data, 'key'):
            key = encrypted_data.key
        
        if key is None:
            raise ValueError("Decryption key is required")
        
        # Determine the encryption layer
        if hasattr(encrypted_data, 'layer'):
            layer = encrypted_data.layer
        else:
            # Default to SCRAMBLED_EGGS for backward compatibility
            layer = self.default_layer
        
        # Decrypt using the appropriate method
        if layer == EncryptionLayer.AES_256_GCM:
            return self._decrypt_aes_gcm(encrypted_data, key)
        elif layer == EncryptionLayer.CHACHA20_POLY1305:
            return self._decrypt_chacha20_poly1305(encrypted_data, key)
        elif layer == EncryptionLayer.SCRAMBLED_EGGS:
            return self._decrypt_scrambled_eggs(encrypted_data, key)
        else:
            raise ValueError(f"Unsupported encryption layer: {layer}")
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes, salt: bytes, iv: bytes) -> EncryptionResult:
        """Encrypt data using AES-256-GCM."""
        # Derive a key from the provided key and salt
        derived_key = self.derive_key(key, salt)
        
        # Create a cipher and encrypt the data
        encryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(iv),
            backend=self.backend
        ).encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return EncryptionResult(
            ciphertext=ciphertext,
            key=key,
            salt=salt,
            iv=iv,
            auth_tag=encryptor.tag
        )
    
    def _decrypt_aes_gcm(self, encrypted_data: EncryptionResult, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM."""
        # Derive the key
        derived_key = self.derive_key(key, encrypted_data.salt)
        
        # Create a cipher and decrypt the data
        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(encrypted_data.iv, encrypted_data.auth_tag),
            backend=self.backend
        ).decryptor()
        
        return decryptor.update(encrypted_data.ciphertext) + decryptor.finalize()
    
    def _encrypt_chacha20_poly1305(self, data: bytes, key: bytes, salt: bytes, iv: bytes) -> EncryptionResult:
        """Encrypt data using ChaCha20-Poly1305."""
        # Derive a key from the provided key and salt
        derived_key = self.derive_key(key, salt)
        
        # Create a cipher and encrypt the data
        encryptor = Cipher(
            algorithms.ChaCha20(derived_key, iv),
            mode=None,
            backend=self.backend
        ).encryptor()
        
        ciphertext = encryptor.update(data)
        
        # Generate a Poly1305 tag for authentication
        h = hmac_lib.HMAC(
            derived_key,
            hashes.SHA256(),
            backend=self.backend
        )
        h.update(iv + ciphertext)
        auth_tag = h.finalize()
        
        return EncryptionResult(
            ciphertext=ciphertext,
            key=key,
            salt=salt,
            iv=iv,
            auth_tag=auth_tag
        )
    
    def _decrypt_chacha20_poly1305(self, encrypted_data: EncryptionResult, key: bytes) -> bytes:
        """Decrypt data using ChaCha20-Poly1305."""
        # Derive the key
        derived_key = self.derive_key(key, encrypted_data.salt)
        
        # Verify the HMAC
        h = hmac_lib.HMAC(
            derived_key,
            hashes.SHA256(),
            backend=self.backend
        )
        h.update(encrypted_data.iv + encrypted_data.ciphertext)
        
        try:
            h.verify(encrypted_data.auth_tag)
        except InvalidTag:
            raise ValueError("Invalid authentication tag")
        
        # Decrypt the data
        decryptor = Cipher(
            algorithms.ChaCha20(derived_key, encrypted_data.iv),
            mode=None,
            backend=self.backend
        ).decryptor()
        
        return decryptor.update(encrypted_data.ciphertext)
    
    def _encrypt_scrambled_eggs(self, data: bytes, key: bytes, salt: bytes, iv: bytes) -> EncryptionResult:
        """Encrypt data using the Scrambled Eggs multi-layer encryption."""
        # First layer: AES-256-GCM
        aes_result = self._encrypt_aes_gcm(data, key, salt, iv)
        
        # Generate a new IV for the second layer
        iv2 = os.urandom(self.IV_SIZE)
        
        # Second layer: ChaCha20-Poly1305
        chacha_result = self._encrypt_chacha20_poly1305(
            aes_result.ciphertext,
            key,
            salt,
            iv2
        )
        
        # Combine the results
        return EncryptionResult(
            ciphertext=chacha_result.ciphertext,
            key=key,
            salt=salt,
            iv=iv + iv2,  # Combine IVs
            auth_tag=aes_result.auth_tag + chacha_result.auth_tag,
            hmac_digest=self._generate_hmac(chacha_result.ciphertext, key, salt)
        )
    
    def _decrypt_scrambled_eggs(self, encrypted_data: EncryptionResult, key: bytes) -> bytes:
        """Decrypt data using the Scrambled Eggs multi-layer encryption."""
        # Split the IVs
        iv1 = encrypted_data.iv[:self.IV_SIZE]
        iv2 = encrypted_data.iv[self.IV_SIZE:]
        
        # Split the auth tags
        tag1 = encrypted_data.auth_tag[:16]  # GCM tag is 16 bytes
        tag2 = encrypted_data.auth_tag[16:]  # HMAC-SHA256 is 32 bytes
        
        # Verify the HMAC if present
        if hasattr(encrypted_data, 'hmac_digest'):
            expected_hmac = self._generate_hmac(encrypted_data.ciphertext, key, encrypted_data.salt)
            if not hmac.compare_digest(encrypted_data.hmac_digest, expected_hmac):
                raise ValueError("HMAC verification failed")
        
        # First layer: Decrypt ChaCha20-Poly1305
        chacha_result = EncryptionResult(
            ciphertext=encrypted_data.ciphertext,
            key=key,
            salt=encrypted_data.salt,
            iv=iv2,
            auth_tag=tag2
        )
        
        aes_ciphertext = self._decrypt_chacha20_poly1305(chacha_result, key)
        
        # Second layer: Decrypt AES-256-GCM
        aes_result = EncryptionResult(
            ciphertext=aes_ciphertext,
            key=key,
            salt=encrypted_data.salt,
            iv=iv1,
            auth_tag=tag1
        )
        
        return self._decrypt_aes_gcm(aes_result, key)
    
    def _generate_hmac(self, data: bytes, key: bytes, salt: bytes) -> bytes:
        """Generate an HMAC for data integrity verification."""
        h = hmac_lib.HMAC(
            self.derive_key(key, salt),
            hashes.SHA512(),
            backend=self.backend
        )
        h.update(data)
        return h.finalize()
    
    def reencrypt(self, encrypted_data: EncryptionResult, new_key: bytes = None) -> EncryptionResult:
        """Re-encrypt data with a new key."""
        # Decrypt the data with the old key
        decrypted = self.decrypt(encrypted_data)
        
        # Generate a new key if none provided
        if new_key is None:
            new_key = self.generate_key()
        
        # Re-encrypt with the new key
        return self.encrypt(decrypted, new_key, layer=encrypted_data.layer if hasattr(encrypted_data, 'layer') else None)

"""
Hybrid Encryption Module
----------------------

Implements hybrid encryption using both symmetric and asymmetric cryptography.
This provides the benefits of both: the speed of symmetric encryption and the
security of asymmetric key exchange.
"""
import os
import json
import base64
from typing import Optional, Tuple, Dict, Any, Union
from enum import Enum, auto

# Try to import cryptography primitives
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, padding, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hmac
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class EncryptionError(Exception):
    """Exception raised for encryption/decryption errors."""
    pass

class KeySize(Enum):
    """Supported key sizes for encryption."""
    AES_128 = 128
    AES_192 = 192
    AES_256 = 256

class HybridEncryption:
    """A class for hybrid encryption using AES for data and RSA for key exchange."""
    
    def __init__(self, 
                 rsa_key_size: int = 4096,
                 symmetric_key_size: KeySize = KeySize.AES_256,
                 hash_algorithm: str = 'SHA256',
                 rsa_padding = asym_padding.OAEP(
                     mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None
                 )):
        """Initialize the hybrid encryption system.
        
        Args:
            rsa_key_size: Size of the RSA key in bits (default: 4096)
            symmetric_key_size: Size of the symmetric key (default: AES-256)
            hash_algorithm: Hash algorithm to use (default: SHA256)
            rsa_padding: Padding scheme for RSA encryption (default: OAEP with SHA256)
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography module is required for hybrid encryption")
            
        self.rsa_key_size = rsa_key_size
        self.symmetric_key_size = symmetric_key_size
        self.hash_algorithm = hash_algorithm
        self.rsa_padding = rsa_padding
        
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def encrypt(self, data: Union[bytes, str], recipient_public_key = None) -> Dict[str, Any]:
        """Encrypt data using hybrid encryption.
        
        Args:
            data: The data to encrypt (bytes or string)
            recipient_public_key: Optional recipient's public key (default: use own public key)
            
        Returns:
            Dictionary containing encrypted data, encrypted key, and metadata
            
        Raises:
            EncryptionError: If encryption fails
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if recipient_public_key is None:
            recipient_public_key = self.public_key
            
        try:
            # Generate a random symmetric key
            key_size = self.symmetric_key_size.value // 8
            symmetric_key = os.urandom(key_size)
            
            # Generate a random IV
            iv = os.urandom(16)  # 128-bit IV for AES
            
            # Create cipher and encrypt the data
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad the data if needed (GCM doesn't require padding, but we'll add it for other modes)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt the data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Get the authentication tag
            tag = encryptor.tag
            
            # Encrypt the symmetric key with RSA
            encrypted_key = recipient_public_key.encrypt(
                symmetric_key,
                self.rsa_padding
            )
            
            # Return the encrypted data and metadata
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'key_size': self.symmetric_key_size.value,
                'algorithm': 'AES-GCM',
                'rsa_key_size': self.rsa_key_size,
                'hash_algorithm': self.hash_algorithm
            }
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt(self, encrypted_data: Dict[str, Any], private_key = None) -> bytes:
        """Decrypt data that was encrypted with hybrid encryption.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            private_key: Optional private key to use for decryption (default: use own private key)
            
        Returns:
            Decrypted data as bytes
            
        Raises:
            EncryptionError: If decryption fails or authentication fails
        """
        if private_key is None:
            private_key = self.private_key
            
        try:
            # Extract data from the encrypted dictionary
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
            iv = base64.b64decode(encrypted_data['iv'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            # Decrypt the symmetric key with RSA
            symmetric_key = private_key.decrypt(
                encrypted_key,
                self.rsa_padding
            )
            
            # Create cipher and decrypt the data
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and unpad the data
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
            
        except (KeyError, ValueError, InvalidTag) as e:
            raise EncryptionError(f"Decryption failed: {e}") from e
        except Exception as e:
            raise EncryptionError(f"Unexpected error during decryption: {e}") from e
    
    def export_public_key(self, format: str = 'PEM') -> bytes:
        """Export the public key in the specified format.
        
        Args:
            format: Output format ('PEM' or 'DER')
            
        Returns:
            Public key in the specified format
        """
        if format.upper() == 'PEM':
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif format.upper() == 'DER':
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError("Unsupported format. Use 'PEM' or 'DER'.")
    
    @classmethod
    def from_config(cls, config: Dict[str, Any]):
        """Create a HybridEncryption instance from a configuration dictionary."""
        return cls(
            rsa_key_size=config.get('rsa_key_size', 4096),
            symmetric_key_size=KeySize(config.get('symmetric_key_size', 256)),
            hash_algorithm=config.get('hash_algorithm', 'SHA256')
        )
    
    def to_config(self) -> Dict[str, Any]:
        """Convert the HybridEncryption instance to a configuration dictionary."""
        return {
            'rsa_key_size': self.rsa_key_size,
            'symmetric_key_size': self.symmetric_key_size.value,
            'hash_algorithm': self.hash_algorithm
        }

# Default hybrid encryption instance for convenience
default_hybrid_encryption = HybridEncryption() if CRYPTO_AVAILABLE else None

def encrypt_data(data: Union[bytes, str], public_key_pem: Optional[bytes] = None) -> Dict[str, Any]:
    """Convenience function to encrypt data using hybrid encryption.
    
    Args:
        data: The data to encrypt (bytes or string)
        public_key_pem: Optional PEM-encoded public key (default: use default key)
        
    Returns:
        Dictionary containing encrypted data and metadata
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography module is required for hybrid encryption")
        
    if public_key_pem:
        from cryptography.hazmat.primitives import serialization
        public_key = serialization.load_pem_public_key(public_key_pem)
        return HybridEncryption().encrypt(data, public_key)
    else:
        return default_hybrid_encryption.encrypt(data)

def decrypt_data(encrypted_data: Dict[str, Any], private_key_pem: Optional[bytes] = None) -> bytes:
    """Convenience function to decrypt data using hybrid encryption.
    
    Args:
        encrypted_data: Dictionary containing encrypted data and metadata
        private_key_pem: Optional PEM-encoded private key (default: use default key)
        
    Returns:
        Decrypted data as bytes
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography module is required for hybrid encryption")
        
    if private_key_pem:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        return HybridEncryption().decrypt(encrypted_data, private_key)
    else:
        return default_hybrid_encryption.decrypt(encrypted_data)

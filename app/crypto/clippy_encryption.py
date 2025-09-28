"""
Clippy Encryption Protocol

A secure, multi-layered encryption system with fail-safe mechanisms.
"""
import os
import json
import hmac
import time
import struct
import base64
import hashlib
import logging
import secrets
from typing import Dict, List, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum, auto

# Cryptography imports
from cryptography.hazmat.primitives import hashes, hmac as hmac_lib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key,
    load_pem_private_key
)
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EncryptionLayer(Enum):
    """Supported encryption layers."""
    AES_256_CBC = auto()
    AES_256_GCM = auto()
    CHACHA20_POLY1305 = auto()

@dataclass
class LayerConfig:
    """Configuration for an encryption layer."""
    layer_type: EncryptionLayer
    key_size: int
    iv_size: int
    use_hmac: bool = True
    hmac_algorithm: str = 'sha512'
    salt_size: int = 32
    iterations: int = 100000

class ClippyEncryption:
    """
    Clippy's Advanced Encryption Protocol
    
    Features:
    - Multi-layered encryption with different algorithms
    - Key stretching with PBKDF2 and HKDF
    - HMAC for data integrity
    - Fail-safe mechanism on decryption failure
    - Support for both symmetric and asymmetric encryption
    - Chunked processing for large files
    """
    
    # Default configurations for each layer type
    LAYER_CONFIGS = {
        EncryptionLayer.AES_256_CBC: LayerConfig(
            layer_type=EncryptionLayer.AES_256_CBC,
            key_size=32,  # 256 bits
            iv_size=16,   # 128 bits
            use_hmac=True,
            hmac_algorithm='sha512',
            salt_size=32,
            iterations=100000
        ),
        EncryptionLayer.AES_256_GCM: LayerConfig(
            layer_type=EncryptionLayer.AES_256_GCM,
            key_size=32,  # 256 bits
            iv_size=12,   # 96 bits for GCM
            use_hmac=False,  # GCM has built-in authentication
            salt_size=32,
            iterations=100000
        ),
        EncryptionLayer.CHACHA20_POLY1305: LayerConfig(
            layer_type=EncryptionLayer.CHACHA20_POLY1305,
            key_size=32,  # 256 bits
            iv_size=12,   # 96 bits
            use_hmac=False,  # ChaCha20-Poly1305 has built-in authentication
            salt_size=32,
            iterations=100000
        )
    }
    
    def __init__(self, 
                 min_layers: int = 3, 
                 max_layers: int = 7,
                 chunk_size: int = 4 * 1024 * 1024,  # 4MB chunks
                 enable_fail_safe: bool = True,
                 max_fail_safe_layers: int = 10):
        """
        Initialize the encryption protocol.
        
        Args:
            min_layers: Minimum number of encryption layers
            max_layers: Maximum number of encryption layers
            chunk_size: Size of chunks for processing large files (in bytes)
            enable_fail_safe: Whether to enable the fail-safe mechanism
            max_fail_safe_layers: Maximum additional layers to add on decryption failure
        """
        self.min_layers = min_layers
        self.max_layers = max_layers
        self.chunk_size = chunk_size
        self.enable_fail_safe = enable_fail_safe
        self.max_fail_safe_layers = max_fail_safe_layers
        
        # Generate or load keys
        self._generate_keys()
    
    def _generate_keys(self):
        """Generate or load encryption keys."""
        # In a real implementation, you'd load these from secure storage
        self._private_key = ec.generate_private_key(
            ec.SECP384R1(),  # Using P-384 for ECDH
            default_backend()
        )
        self._public_key = self._private_key.public_key()
        
        # Generate a master key for symmetric operations
        self._master_key = os.urandom(32)  # 256-bit master key
    
    def _derive_key(self, 
                   password: bytes, 
                   salt: bytes, 
                   key_length: int,
                   iterations: int = 100000) -> bytes:
        """
        Derive a secure key from a password and salt.
        
        Args:
            password: The password to derive the key from
            salt: Random salt
            key_length: Desired key length in bytes
            iterations: Number of iterations for key stretching
            
        Returns:
            Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def _generate_iv(self, size: int) -> bytes:
        """Generate a random initialization vector."""
        return os.urandom(size)
    
    def _generate_salt(self, size: int = 32) -> bytes:
        """Generate a random salt."""
        return os.urandom(size)
    
    def _hmac_sign(self, data: bytes, key: bytes, algorithm: str = 'sha512') -> bytes:
        """Generate HMAC for data integrity."""
        h = hmac_lib.HMAC(
            key,
            getattr(hashes, algorithm.upper())(),
            backend=default_backend()
        )
        h.update(data)
        return h.finalize()
    
    def _hmac_verify(self, data: bytes, signature: bytes, key: bytes, algorithm: str = 'sha512') -> bool:
        """Verify HMAC for data integrity."""
        h = hmac_lib.HMAC(
            key,
            getattr(hashes, algorithm.upper())(),
            backend=default_backend()
        )
        h.update(data)
        try:
            h.verify(signature)
            return True
        except Exception:
            return False
    
    def _encrypt_chunk(self, 
                      chunk: bytes, 
                      key: bytes, 
                      layer_config: LayerConfig) -> Tuple[bytes, Dict]:
        """Encrypt a chunk of data with the specified layer configuration."""
        # Generate a random IV
        iv = self._generate_iv(layer_config.iv_size)
        
        # Encrypt the data based on the layer type
        if layer_config.layer_type == EncryptionLayer.AES_256_CBC:
            # Pad the data for CBC mode
            padder = PKCS7(128).padder()
            padded_data = padder.update(chunk) + padder.finalize()
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            # Generate HMAC if enabled
            hmac_value = None
            if layer_config.use_hmac:
                hmac_value = self._hmac_sign(iv + encrypted, key, layer_config.hmac_algorithm)
            
            return encrypted, {
                'iv': iv,
                'hmac': hmac_value,
                'original_length': len(chunk)
            }
            
        elif layer_config.layer_type == EncryptionLayer.AES_256_GCM:
            # GCM mode
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(chunk) + encryptor.finalize()
            
            return encrypted, {
                'iv': iv,
                'tag': encryptor.tag,
                'original_length': len(chunk)
            }
            
        elif layer_config.layer_type == EncryptionLayer.CHACHA20_POLY1305:
            # ChaCha20-Poly1305
            cipher = Cipher(
                algorithms.ChaCha20(key, iv),
                mode=None,
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(chunk)
            
            # Generate Poly1305 tag
            poly_key = self._hmac_sign(b'POLY1305_KEY_DERIVATION' + iv, key, 'sha256')
            poly = hmac_lib.HMAC(
                poly_key,
                hashes.Poly1305(),
                backend=default_backend()
            )
            poly.update(encrypted)
            tag = poly.finalize()
            
            return encrypted, {
                'iv': iv,
                'tag': tag,
                'original_length': len(chunk)
            }
            
        else:
            raise ValueError(f"Unsupported encryption layer: {layer_config.layer_type}")
    
    def _decrypt_chunk(self, 
                      chunk: bytes, 
                      key: bytes, 
                      layer_config: LayerConfig,
                      metadata: Dict) -> bytes:
        """Decrypt a chunk of data with the specified layer configuration."""
        if layer_config.layer_type == EncryptionLayer.AES_256_CBC:
            # Verify HMAC if enabled
            if layer_config.use_hmac and 'hmac' in metadata:
                if not self._hmac_verify(
                    metadata['iv'] + chunk, 
                    metadata['hmac'], 
                    key, 
                    layer_config.hmac_algorithm
                ):
                    raise ValueError("HMAC verification failed")
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(metadata['iv']),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(chunk) + decryptor.finalize()
            
            # Unpad
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(decrypted) + unpadder.finalize()
            
        elif layer_config.layer_type == EncryptionLayer.AES_256_GCM:
            # GCM mode
            if 'tag' not in metadata:
                raise ValueError("Missing authentication tag for GCM mode")
                
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(metadata['iv'], metadata['tag']),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(chunk) + decryptor.finalize()
            
        elif layer_config.layer_type == EncryptionLayer.CHACHA20_POLY1305:
            # Verify Poly1305 tag
            if 'tag' not in metadata:
                raise ValueError("Missing authentication tag for ChaCha20-Poly1305")
                
            poly_key = self._hmac_sign(b'POLY1305_KEY_DERIVATION' + metadata['iv'], key, 'sha256')
            poly = hmac_lib.HMAC(
                poly_key,
                hashes.Poly1305(),
                backend=default_backend()
            )
            poly.update(chunk)
            
            try:
                poly.verify(metadata['tag'])
            except Exception as e:
                raise ValueError("Poly1305 tag verification failed") from e
            
            # Decrypt
            cipher = Cipher(
                algorithms.ChaCha20(key, metadata['iv']),
                mode=None,
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(chunk)
            
        else:
            raise ValueError(f"Unsupported encryption layer: {layer_config.layer_type}")
    
    def encrypt(self, 
               data: bytes, 
               password: Optional[bytes] = None,
               min_layers: Optional[int] = None,
               max_layers: Optional[int] = None) -> Tuple[bytes, Dict]:
        """
        Encrypt data with multiple layers of encryption.
        
        Args:
            data: The data to encrypt
            password: Optional password for key derivation
            min_layers: Override the minimum number of layers
            max_layers: Override the maximum number of layers
            
        Returns:
            A tuple of (encrypted_data, metadata)
        """
        min_layers = min_layers or self.min_layers
        max_layers = max_layers or self.max_layers
        
        # Generate a random number of layers
        num_layers = secrets.randbelow(max_layers - min_layers + 1) + min_layers
        
        # Generate a random password if none provided
        if password is None:
            password = os.urandom(32)  # 256-bit random password
        
        # Generate a master salt
        master_salt = self._generate_salt()
        
        # Derive a master key from the password
        master_key = self._derive_key(
            password,
            master_salt,
            32,  # 256-bit key
            iterations=100000
        )
        
        # Prepare metadata
        metadata = {
            'version': '1.0',
            'timestamp': int(time.time()),
            'num_layers': num_layers,
            'master_salt': master_salt.hex(),
            'layers': [],
            'chunk_size': self.chunk_size if len(data) > self.chunk_size else 0
        }
        
        # Process data in chunks if it's large
        if len(data) > self.chunk_size:
            chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
            is_chunked = True
        else:
            chunks = [data]
            is_chunked = False
        
        # Encrypt each chunk with all layers
        encrypted_chunks = []
        
        for chunk_idx, chunk in enumerate(chunks):
            current_data = chunk
            chunk_metadata = {'chunk_id': chunk_idx, 'layers': []}
            
            # Apply each encryption layer
            for layer_idx in range(num_layers):
                # Select a random layer type
                layer_type = secrets.choice(list(self.LAYER_CONFIGS.keys()))
                layer_config = self.LAYER_CONFIGS[layer_type]
                
                # Generate a unique salt for this layer and chunk
                layer_salt = self._generate_salt(layer_config.salt_size)
                
                # Derive a key for this layer
                layer_key = self._derive_key(
                    master_key,
                    layer_salt + struct.pack('>I', layer_idx) + struct.pack('>I', chunk_idx),
                    layer_config.key_size,
                    iterations=layer_config.iterations
                )
                
                # Encrypt the chunk
                encrypted_data, layer_meta = self._encrypt_chunk(
                    current_data,
                    layer_key,
                    layer_config
                )
                
                # Update metadata
                layer_meta.update({
                    'layer_type': layer_type.name,
                    'layer_idx': layer_idx,
                    'salt': layer_salt.hex(),
                    'key_size': layer_config.key_size,
                    'iv_size': layer_config.iv_size,
                    'use_hmac': layer_config.use_hmac,
                    'hmac_algorithm': layer_config.hmac_algorithm if layer_config.use_hmac else None,
                    'original_length': len(current_data)
                })
                
                # Convert bytes to hex for JSON serialization
                for k, v in layer_meta.items():
                    if isinstance(v, bytes):
                        layer_meta[k] = v.hex()
                
                chunk_metadata['layers'].append(layer_meta)
                current_data = encrypted_data
            
            encrypted_chunks.append(current_data)
            
            # Only store metadata for the first chunk to save space
            if chunk_idx == 0:
                metadata['layers'] = chunk_metadata['layers']
        
        # Combine all chunks
        encrypted_data = b''.join(encrypted_chunks)
        
        return encrypted_data, metadata
    
    def decrypt(self, 
               encrypted_data: bytes, 
               metadata: Dict,
               password: bytes) -> bytes:
        """
        Decrypt data that was encrypted with this protocol.
        
        Args:
            encrypted_data: The encrypted data
            metadata: The metadata from encryption
            password: The password used for encryption
            
        Returns:
            The decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        # Extract metadata
        master_salt = bytes.fromhex(metadata['master_salt'])
        num_layers = metadata['num_layers']
        chunk_size = metadata.get('chunk_size', 0)
        
        # Derive the master key
        master_key = self._derive_key(
            password,
            master_salt,
            32,  # 256-bit key
            iterations=100000
        )
        
        # Process data in chunks if it was chunked
        if chunk_size > 0:
            # Calculate chunk size after encryption (may have padding)
            # This is a simplification; in practice, you'd need to track chunk sizes
            num_chunks = (len(encrypted_data) + chunk_size - 1) // chunk_size
            chunk_size = (len(encrypted_data) + num_chunks - 1) // num_chunks
            chunks = [encrypted_data[i:i + chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
        else:
            chunks = [encrypted_data]
        
        # Decrypt each chunk
        decrypted_chunks = []
        
        for chunk_idx, chunk in enumerate(chunks):
            current_data = chunk
            
            # Get layer metadata (use first chunk's metadata for all chunks)
            layers_metadata = metadata['layers']
            
            # Apply decryption layers in reverse order
            for layer_meta in reversed(layers_metadata):
                try:
                    # Convert hex strings back to bytes
                    layer_meta_bytes = {}
                    for k, v in layer_meta.items():
                        if isinstance(v, str) and k not in ['layer_type', 'hmac_algorithm']:
                            layer_meta_bytes[k] = bytes.fromhex(v)
                        else:
                            layer_meta_bytes[k] = v
                    
                    # Get layer configuration
                    layer_type = EncryptionLayer[layer_meta_bytes['layer_type']]
                    layer_config = self.LAYER_CONFIGS[layer_type]
                    
                    # Derive the layer key
                    layer_salt = layer_meta_bytes['salt']
                    layer_key = self._derive_key(
                        master_key,
                        layer_salt + struct.pack('>I', layer_meta_bytes['layer_idx']) + struct.pack('>I', chunk_idx),
                        layer_config.key_size,
                        iterations=layer_config.iterations
                    )
                    
                    # Decrypt the chunk
                    current_data = self._decrypt_chunk(
                        current_data,
                        layer_key,
                        layer_config,
                        layer_meta_bytes
                    )
                    
                except Exception as e:
                    if self.enable_fail_safe and len(decrypted_chunks) == 0:  # Only for the first chunk
                        logger.warning(f"Decryption failed at layer {layer_meta['layer_idx']}: {e}")
                        logger.info("Activating fail-safe mechanism")
                        
                        # Add more encryption layers and try again
                        additional_layers = min(10, self.max_fail_safe_layers)
                        logger.info(f"Adding {additional_layers} additional encryption layers")
                        
                        # Generate a new random password
                        new_password = os.urandom(32)
                        
                        # Re-encrypt with additional layers
                        current_data, new_metadata = self.encrypt(
                            current_data,
                            new_password,
                            min_layers=additional_layers,
                            max_layers=additional_layers
                        )
                        
                        # Update metadata
                        metadata['fail_safe_activated'] = True
                        metadata['fail_safe_timestamp'] = int(time.time())
                        metadata['layers'].extend(new_metadata['layers'])
                        
                        # Try decrypting again with the updated data and metadata
                        return self.decrypt(current_data, metadata, new_password)
                    else:
                        raise
            
            decrypted_chunks.append(current_data)
        
        # Combine all chunks
        return b''.join(decrypted_chunks)

# Example usage
if __name__ == "__main__":
    # Initialize the encryption protocol
    crypto = ClippyEncryption(
        min_layers=3,
        max_layers=5,
        chunk_size=1024 * 1024,  # 1MB chunks
        enable_fail_safe=True,
        max_fail_safe_layers=5
    )
    
    # Sample data to encrypt
    data = b"This is a test message for the Clippy encryption protocol." * 1000
    password = b"my_secure_password"
    
    print(f"Original data size: {len(data)} bytes")
    
    # Encrypt the data
    print("Encrypting...")
    encrypted_data, metadata = crypto.encrypt(data, password)
    print(f"Encrypted data size: {len(encrypted_data)} bytes")
    print(f"Number of layers: {metadata['num_layers']}")
    
    # Decrypt the data
    print("\nDecrypting...")
    try:
        decrypted_data = crypto.decrypt(encrypted_data, metadata, password)
        print(f"Decryption successful! Data matches: {decrypted_data == data}")
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise

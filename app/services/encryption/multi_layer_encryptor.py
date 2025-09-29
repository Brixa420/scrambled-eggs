"""
Multi-Layer Encryption with Chunked Processing

This module provides a high-performance, memory-efficient implementation of
multi-layer encryption with support for chunked processing and SIMD optimizations.
"""
import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from .worker_pool import get_worker_pool
from .chunked_processor import ChunkedProcessor, get_chunk_processor as get_file_chunk_processor
from .chunked_data_processor import ChunkedDataProcessor, get_chunked_processor
from .simd_optimizations import SIMDEncryptor, detect_cpu_features

# Configure logging
logger = logging.getLogger(__name__)

class EncryptionMode(Enum):
    """Supported encryption modes."""
    CBC = auto()
    GCM = auto()

@dataclass
class LayerConfig:
    """Configuration for a single encryption layer."""
    mode: EncryptionMode
    key_derivation_salt: bytes
    iv: bytes
    tag: bytes = field(default_factory=bytes)

@dataclass
class EncryptionResult:
    """Result of encryption/decryption operation."""
    data: bytes
    metadata: Dict = field(default_factory=dict)
    duration: float = 0.0

class MultiLayerEncryptor:
    """Handles multi-layer encryption with parallel processing and chunking."""
    
    def __init__(
        self, 
        num_layers: int = 10, 
        max_workers: int = None, 
        use_simd: bool = True,
        chunk_size: int = 4 * 1024 * 1024  # 4MB default chunk size
    ):
        """Initialize the multi-layer encryptor.
        
        Args:
            num_layers: Number of encryption layers to apply
            max_workers: Maximum number of worker threads (default: CPU count * 2)
            use_simd: Whether to use SIMD optimizations if available
            chunk_size: Size of chunks for in-memory processing (in bytes)
        """
        self.num_layers = num_layers
        self.worker_pool = get_worker_pool()
        self.layers: List[LayerConfig] = []
        self.use_simd = use_simd
        self.chunk_size = chunk_size
        self._init_layers()
        
        # Initialize chunked processors
        self.chunked_processor = get_chunked_processor(chunk_size=chunk_size)
        self.file_chunk_processor = get_file_chunk_processor()
        
        # Log CPU features if using SIMD
        if self.use_simd:
            cpu_features = detect_cpu_features()
            logger.info(f"CPU Features: {cpu_features}")
            if not any(cpu_features.values()):
                logger.warning("No SIMD optimizations available, using fallback implementation")
    
    def _init_layers(self) -> None:
        """Initialize encryption layers with secure random configurations."""
        for _ in range(self.num_layers):
            mode = EncryptionMode.CBC  # Default to CBC for now
            salt = os.urandom(32)
            iv = os.urandom(16)
            self.layers.append(LayerConfig(
                mode=mode,
                key_derivation_salt=salt,
                iv=iv
            ))
    
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive a secure key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    async def _encrypt_layer(self, data: bytes, layer_idx: int, password: str) -> bytes:
        """Encrypt data with a single layer."""
        layer = self.layers[layer_idx]
        
        # Run key derivation in the worker pool
        key = await self.worker_pool.submit(
            self._derive_key,
            password.encode(),
            layer.key_derivation_salt
        )
        
        # Process encryption in the worker pool
        def _encrypt() -> bytes:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            if self.use_simd:
                try:
                    mode_str = 'GCM' if layer.mode == EncryptionMode.GCM else 'CBC'
                    encryptor = SIMDEncryptor(key, mode=mode_str, iv=layer.iv)
                    
                    if layer.mode == EncryptionMode.GCM:
                        ciphertext, tag = encryptor.encrypt(padded_data)
                        layer.tag = tag
                        return layer.iv + tag + ciphertext
                    else:  # CBC mode
                        ciphertext = encryptor.encrypt(padded_data)
                        return layer.iv + ciphertext
                except Exception as e:
                    logger.warning(f"SIMD encryption failed, falling back to standard: {e}")
            
            # Fallback to standard implementation
            if layer.mode == EncryptionMode.GCM:
                encryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(layer.iv),
                    backend=default_backend()
                ).encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                layer.tag = encryptor.tag  # Store tag for decryption
                return layer.iv + layer.tag + ciphertext
            else:  # CBC mode
                encryptor = Cipher(
                    algorithms.AES(key),
                    modes.CBC(layer.iv),
                    backend=default_backend()
                ).encryptor()
                return layer.iv + encryptor.update(padded_data) + encryptor.finalize()
                
        return await self.worker_pool.submit(_encrypt)
    
    async def _decrypt_layer(self, data: bytes, layer_idx: int, password: str) -> bytes:
        """Decrypt data with a single layer."""
        layer = self.layers[layer_idx]
        
        # Run key derivation in the worker pool
        key = await self.worker_pool.submit(
            self._derive_key,
            password.encode(),
            layer.key_derivation_salt
        )
        
        # Process decryption in the worker pool
        def _decrypt() -> bytes:
            if self.use_simd:
                try:
                    mode_str = 'GCM' if layer.mode == EncryptionMode.GCM else 'CBC'
                    
                    if layer.mode == EncryptionMode.GCM:
                        iv = data[:16]
                        tag = data[16:32]
                        ciphertext = data[32:]
                        
                        decryptor = SIMDEncryptor(key, mode='GCM', iv=iv)
                        padded_plaintext = decryptor.decrypt(ciphertext, tag=tag)
                    else:  # CBC mode
                        iv = data[:16]
                        ciphertext = data[16:]
                        
                        decryptor = SIMDEncryptor(key, mode='CBC', iv=iv)
                        padded_plaintext = decryptor.decrypt(ciphertext)
                    
                    unpadder = padding.PKCS7(128).unpadder()
                    return unpadder.update(padded_plaintext) + unpadder.finalize()
                    
                except Exception as e:
                    logger.warning(f"SIMD decryption failed, falling back to standard: {e}")
            
            # Fallback to standard implementation
            if layer.mode == EncryptionMode.GCM:
                iv = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
                
                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                ).decryptor()
                
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            else:  # CBC mode
                iv = data[:16]
                ciphertext = data[16:]
                
                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                ).decryptor()
                
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_plaintext) + unpadder.finalize()
            
        return await self.worker_pool.submit(_decrypt)
    
    async def encrypt(self, data: bytes, password: str) -> bytes:
        """Encrypt data through all layers using chunked processing.
        
        Args:
            data: Data to encrypt
            password: Encryption password
            
        Returns:
            Encrypted data
        """
        if not data:
            return b''
            
        # Auto-configure chunk size based on data size
        if len(data) > self.chunk_size * 2:  # Only chunk if data is significantly larger than chunk size
            self.chunked_processor.auto_configure(len(data))
            
            async def encrypt_chunk(chunk: bytes, context: dict) -> bytes:
                """Encrypt a single chunk through all layers."""
                current_data = chunk
                for layer_idx in range(self.num_layers):
                    current_data = await self._encrypt_layer(current_data, layer_idx, password)
                return current_data
                
            # Process data in chunks
            return await self.chunked_processor.process(data, encrypt_chunk, {})
        else:
            # Process small data without chunking
            current_data = data
            for layer_idx in range(self.num_layers):
                current_data = await self._encrypt_layer(current_data, layer_idx, password)
            return current_data
    
    async def decrypt(self, data: bytes, password: str) -> bytes:
        """Decrypt data through all layers in reverse order using chunked processing.
        
        Args:
            data: Data to decrypt
            password: Decryption password
            
        Returns:
            Decrypted data
        """
        if not data:
            return b''
            
        # Auto-configure chunk size based on data size
        if len(data) > self.chunk_size * 2:  # Only chunk if data is significantly larger than chunk size
            self.chunked_processor.auto_configure(len(data))
            
            async def decrypt_chunk(chunk: bytes, context: dict) -> bytes:
                """Decrypt a single chunk through all layers."""
                current_data = chunk
                for layer_idx in reversed(range(self.num_layers)):
                    current_data = await self._decrypt_layer(current_data, layer_idx, password)
                return current_data
                
            # Process data in chunks
            return await self.chunked_processor.process(data, decrypt_chunk, {})
        else:
            # Process small data without chunking
            current_data = data
            for layer_idx in reversed(range(self.num_layers)):
                current_data = await self._decrypt_layer(current_data, layer_idx, password)
            return current_data
    
    async def encrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        password: str
    ) -> EncryptionResult:
        """Encrypt a file in chunks.
        
        Args:
            input_path: Path to input file
            output_path: Path to output file
            password: Encryption password
            
        Returns:
            EncryptionResult with metadata
        """
        start_time = time.time()
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get file size for progress tracking
        file_size = input_path.stat().st_size
        
        async def process_chunk(chunk: bytes, context: dict) -> bytes:
            """Process a single chunk through all encryption layers."""
            current_data = chunk
            for layer_idx in range(self.num_layers):
                current_data = await self._encrypt_layer(current_data, layer_idx, password)
            return current_data
        
        # Process the file in chunks
        await self.file_chunk_processor.process_file(
            input_path=input_path,
            output_path=output_path,
            process_func=process_chunk
        )
        
        return EncryptionResult(
            data=b'',  # Data was written to file
            metadata={
                'input_path': str(input_path),
                'output_path': str(output_path),
                'file_size': file_size,
                'encrypted_size': output_path.stat().st_size,
                'layers': self.num_layers,
                'chunk_size': self.chunk_size
            },
            duration=time.time() - start_time
        )
    
    async def decrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        password: str
    ) -> EncryptionResult:
        """Decrypt a file in chunks.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to output file
            password: Decryption password
            
        Returns:
            EncryptionResult with metadata
        """
        start_time = time.time()
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get file size for progress tracking
        file_size = input_path.stat().st_size
        
        async def process_chunk(chunk: bytes, context: dict) -> bytes:
            """Process a single chunk through all decryption layers."""
            current_data = chunk
            for layer_idx in reversed(range(self.num_layers)):
                current_data = await self._decrypt_layer(current_data, layer_idx, password)
            return current_data
        
        # Process the file in chunks
        await self.file_chunk_processor.process_file(
            input_path=input_path,
            output_path=output_path,
            process_func=process_chunk
        )
        
        return EncryptionResult(
            data=b'',  # Data was written to file
            metadata={
                'input_path': str(input_path),
                'output_path': str(output_path),
                'encrypted_size': file_size,
                'decrypted_size': output_path.stat().st_size,
                'layers': self.num_layers,
                'chunk_size': self.chunk_size
            },
            duration=time.time() - start_time
        )

# Example usage
async def example():
    # Create an encryptor with 5 layers of encryption
    encryptor = MultiLayerEncryptor(num_layers=5)
    
    # Encrypt a file
    result = await encryptor.encrypt_file(
        input_path='sensitive_data.txt',
        output_path='encrypted_data.brixa',
        password='my_secure_password'
    )
    print(f"Encryption complete. Took {result.duration:.2f} seconds")
    
    # Decrypt the file
    result = await encryptor.decrypt_file(
        input_path='encrypted_data.brixa',
        output_path='decrypted_data.txt',
        password='my_secure_password'
    )
    print(f"Decryption complete. Took {result.duration:.2f} seconds")

if __name__ == "__main__":
    asyncio.run(example())

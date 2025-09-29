""
Hardware Acceleration Integration for Multi-Layer Encryption

This module provides integration between the multi-layer encryption system
and hardware-accelerated encryption backends.
"""

import logging
import asyncio
from typing import Optional, Dict, Any, Union, List, Tuple
from dataclasses import dataclass

from .hardware_accel import get_accelerated_encryptor, get_available_backends
from .core import EncryptionMode, LayerConfig, EncryptionResult
from .worker_pool import get_worker_pool

logger = logging.getLogger(__name__)

@dataclass
class HardwareAccelConfig:
    """Configuration for hardware acceleration."""
    enabled: bool = True
    preferred_backend: Optional[str] = None  # 'cuda', 'opencl', 'cpu', None for auto
    min_chunk_size: int = 64 * 1024  # 64KB minimum chunk size for hardware acceleration
    max_chunk_size: int = 16 * 1024 * 1024  # 16MB maximum chunk size for hardware acceleration
    benchmark_mode: bool = False  # Whether to run benchmarks on startup

class HardwareAccelManager:
    """Manages hardware-accelerated encryption operations."""
    
    def __init__(self, config: Optional[HardwareAccelConfig] = None):
        """Initialize with configuration."""
        self.config = config or HardwareAccelConfig()
        self.worker_pool = get_worker_pool()
        self.available_backends = {}
        self.active_backend = None
        self.initialized = False
        
        # Initialize hardware acceleration
        self._init_hardware_accel()
    
    def _init_hardware_accel(self) -> None:
        """Initialize hardware acceleration backends."""
        if not self.config.enabled:
            logger.info("Hardware acceleration is disabled in configuration")
            return
            
        try:
            # Get available backends
            self.available_backends = get_available_backends()
            
            if not self.available_backends:
                logger.warning("No hardware acceleration backends available")
                return
                
            # Log available backends
            logger.info(f"Available hardware backends: {', '.join(self.available_backends.keys())}")
            
            # Get the preferred backend or auto-select
            backend_type = self.config.preferred_backend or 'auto'
            self.active_backend = get_accelerated_encryptor(backend_type)
            
            if self.active_backend:
                logger.info(f"Using hardware backend: {type(self.active_backend).__name__}")
                
                if self.config.benchmark_mode:
                    # Run a quick benchmark
                    speed = self.active_backend.benchmark(16 * 1024 * 1024)  # 16MB test
                    logger.info(f"Hardware acceleration benchmark: {speed:.2f} MB/s")
            else:
                logger.warning("No suitable hardware acceleration backend found")
                
            self.initialized = True
            
        except Exception as e:
            logger.error(f"Failed to initialize hardware acceleration: {e}", exc_info=True)
            self.active_backend = None
    
    def is_available(self) -> bool:
        """Check if hardware acceleration is available and ready to use."""
        return self.initialized and self.active_backend is not None
    
    async def encrypt_chunk(
        self,
        chunk: bytes,
        key: bytes,
        iv: bytes,
        mode: EncryptionMode
    ) -> Tuple[bytes, Optional[bytes]]:
        """Encrypt a chunk of data using hardware acceleration if available.
        
        Args:
            chunk: Data chunk to encrypt
            key: Encryption key
            iv: Initialization vector
            mode: Encryption mode (CBC or GCM)
            
        Returns:
            Tuple of (encrypted_data, tag) where tag is None for CBC mode
        """
        if not self.is_available() or len(chunk) < self.config.min_chunk_size:
            return await self._encrypt_software(chunk, key, iv, mode)
            
        try:
            if mode == EncryptionMode.GCM:
                # For GCM, we need to handle the tag separately
                # This is a simplified example - in practice, you'd need to handle the tag properly
                encrypted = await self.worker_pool.submit(
                    self.active_backend.encrypt,
                    chunk, key, iv
                )
                # In a real implementation, you'd need to extract the tag from the result
                # This is just a placeholder
                tag = encrypted[-16:]  # Last 16 bytes are the tag in this example
                return encrypted[:-16], tag
            else:
                # For CBC mode
                encrypted = await self.worker_pool.submit(
                    self.active_backend.encrypt,
                    chunk, key, iv
                )
                return encrypted, None
                
        except Exception as e:
            logger.warning(f"Hardware encryption failed, falling back to software: {e}")
            return await self._encrypt_software(chunk, key, iv, mode)
    
    async def _encrypt_software(
        self,
        chunk: bytes,
        key: bytes,
        iv: bytes,
        mode: EncryptionMode
    ) -> Tuple[bytes, Optional[bytes]]:
        """Fallback software encryption."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend
        
        def _encrypt() -> Tuple[bytes, Optional[bytes]]:
            if mode == EncryptionMode.GCM:
                encryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv),
                    backend=default_backend()
                ).encryptor()
                ciphertext = encryptor.update(chunk) + encryptor.finalize()
                return ciphertext, encryptor.tag
            else:  # CBC mode
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(chunk) + padder.finalize()
                encryptor = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                ).encryptor()
                return encryptor.update(padded_data) + encryptor.finalize(), None
        
        return await self.worker_pool.submit(_encrypt)
    
    async def process_layers(
        self,
        data: bytes,
        layers: List[LayerConfig],
        password: str,
        progress_callback=None
    ) -> bytes:
        """Process data through multiple encryption layers with hardware acceleration.
        
        Args:
            data: Data to encrypt
            layers: List of layer configurations
            password: Encryption password
            progress_callback: Optional callback for progress updates
            
        Returns:
            Encrypted data
        """
        current_data = data
        total_layers = len(layers)
        
        for i, layer in enumerate(layers):
            # Update progress if callback is provided
            if progress_callback:
                await progress_callback(i, total_layers)
            
            # Process this layer
            key = await self.worker_pool.submit(
                self._derive_key,
                password.encode(),
                layer.key_derivation_salt
            )
            
            # Use hardware acceleration for large chunks
            if len(current_data) > self.config.min_chunk_size:
                encrypted, tag = await self.encrypt_chunk(
                    current_data, key, layer.iv, layer.mode
                )
                if tag is not None:
                    layer.tag = tag
                current_data = layer.iv + (tag or b'') + encrypted
            else:
                # Small chunks use software encryption
                encrypted, tag = await self._encrypt_software(
                    current_data, key, layer.iv, layer.mode
                )
                if tag is not None:
                    layer.tag = tag
                current_data = layer.iv + (tag or b'') + encrypted
        
        return current_data
    
    @staticmethod
    def _derive_key(password: bytes, salt: bytes) -> bytes:
        """Derive a key from a password and salt."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        return kdf.derive(password)


# Global instance for easy access
_hardware_manager = None

def get_hardware_manager(config: Optional[HardwareAccelConfig] = None) -> HardwareAccelManager:
    """Get or create the global hardware acceleration manager."""
    global _hardware_manager
    if _hardware_manager is None:
        _hardware_manager = HardwareAccelManager(config)
    return _hardware_manager

"""
Core Encryption Module
Implements a secure multi-layer encryption system with AES-256.
"""
import os
import base64
import logging
import asyncio
from typing import List, Dict, Optional, Tuple, Union, BinaryIO, AsyncIterator, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import numpy as np
import time

# Import worker pool for parallel processing
from .worker_pool import get_worker_pool
from .chunked_processor import ChunkedProcessor, get_chunk_processor
from .chunked_data_processor import ChunkedDataProcessor, get_chunked_processor
from .simd_optimizations import SIMDEncryptor, detect_cpu_features
from .hardware_integration import HardwareAccelConfig, get_hardware_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EncryptionMode(Enum):
    """Supported encryption modes."""
    CBC = auto()
    GCM = auto()

@dataclass
class LayerConfig:
    """Configuration for an encryption layer."""
    mode: EncryptionMode
    key_derivation_salt: bytes
    iv: bytes
    tag: bytes = None

@dataclass
class EncryptionResult:
    """Result of encryption/decryption operation."""
    data: bytes
    metadata: Dict = field(default_factory=dict)
    duration: float = 0.0

class MultiLayerEncryptor:
    """Handles multi-layer encryption with parallel processing."""
    
    def __init__(
        self, 
        num_layers: int = 10, 
        max_workers: int = None, 
        use_simd: bool = True,
        chunk_size: int = 4 * 1024 * 1024,  # 4MB default chunk size
        use_hardware_accel: bool = True,
        hardware_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize with number of layers and worker threads.
        
        Args:
            num_layers: Number of encryption layers to apply
            max_workers: Maximum number of worker threads (default: CPU count + 4)
            use_simd: Whether to use SIMD optimizations if available
            chunk_size: Size of chunks for in-memory processing (in bytes)
            use_hardware_accel: Whether to use hardware acceleration if available
            hardware_config: Configuration for hardware acceleration
        """
        self.num_layers = num_layers
        self.worker_pool = get_worker_pool()
        self.layers: List[LayerConfig] = []
        self.use_simd = use_simd
        self.chunk_size = chunk_size
        self.use_hardware_accel = use_hardware_accel
        self._init_layers()
        
        # Initialize chunked data processor
        self.chunked_processor = get_chunked_processor(chunk_size=chunk_size)
        
        # Initialize hardware acceleration if enabled
        self.hardware_manager = None
        if self.use_hardware_accel:
            hw_config = HardwareAccelConfig(**(hardware_config or {}))
            self.hardware_manager = get_hardware_manager(hw_config)
            if not self.hardware_manager.is_available():
                logger.warning("Hardware acceleration is not available, falling back to software")
        
        # Log CPU features if using SIMD
        if self.use_simd:
            cpu_features = detect_cpu_features()
            logger.info(f"CPU Features: {cpu_features}")
            if not any(cpu_features.values()):
                logger.warning("No SIMD optimizations available, using fallback implementation")
    
    def _init_layers(self) -> None:
        """Initialize encryption layers with secure random configurations."""
        for _ in range(self.num_layers):
            mode = np.random.choice(list(EncryptionMode))
            salt = os.urandom(32)
            iv = os.urandom(16)
            self.layers.append(LayerConfig(
                mode=mode,
                key_derivation_salt=salt,
                iv=iv
            ))
    
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive a secure key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,  # 256 bits for AES-256
            iterations=600000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    async def encrypt(
        self, 
        data: bytes, 
        password: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> bytes:
        """Encrypt data through all layers using chunked processing.
        
        Args:
            data: Data to encrypt
            password: Password for key derivation
            progress_callback: Optional callback for progress updates
            
        Returns:
            Encrypted data with all layers applied
        """
        start_time = time.time()
        current_data = data
        
        # Process each layer
        for i in range(self.num_layers):
            if progress_callback:
                await progress_callback(i, self.num_layers)
                
            # Get current layer
            layer = self.layers[i]
            
            # Derive key for this layer
            key = await self.worker_pool.submit(
                self._derive_key,
                password.encode(),
                layer.key_derivation_salt
            )
            
            # Use hardware acceleration if available and data is large enough
            if (self.hardware_manager and 
                self.hardware_manager.is_available() and 
                len(current_data) >= self.hardware_manager.config.min_chunk_size):
                
                try:
                    # Use hardware-accelerated encryption
                    encrypted, tag = await self.hardware_manager.encrypt_chunk(
                        current_data, key, layer.iv, layer.mode
                    )
                    
                    if tag is not None:
                        layer.tag = tag
                        current_data = layer.iv + tag + encrypted
                    else:
                        current_data = layer.iv + encrypted
                    continue
                except Exception as e:
                    logger.warning(f"Hardware acceleration failed: {e}")
                    logger.info("Falling back to software encryption")
            
            # Fall back to software implementation
            def _encrypt() -> Tuple[bytes, Optional[bytes]]:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(current_data) + padder.finalize()
                
                if self.use_simd:
                    # Use SIMD-accelerated encryption if available
                    try:
                        mode_str = 'GCM' if layer.mode == EncryptionMode.GCM else 'CBC'
                        encryptor = SIMDEncryptor(key, mode=mode_str, iv=layer.iv)
                        
                        if layer.mode == EncryptionMode.GCM:
                            return encryptor.encrypt(padded_data)
                        return encryptor.encrypt(padded_data), None
                    except Exception as e:
                        logger.warning(f"SIMD encryption failed: {e}")
                
                # Fallback to standard implementation
                if layer.mode == EncryptionMode.GCM:
                    encryptor = Cipher(
                        algorithms.AES(key),
                        modes.GCM(layer.iv),
                        backend=default_backend()
                    ).encryptor()
                    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                    return ciphertext, encryptor.tag
                else:  # CBC mode
                    encryptor = Cipher(
                        algorithms.AES(key),
                        modes.CBC(layer.iv),
                        backend=default_backend()
                    ).encryptor()
                    return encryptor.update(padded_data) + encryptor.finalize(), None
            
            # Execute encryption in worker pool
            encrypted, tag = await self.worker_pool.submit(_encrypt)
            
            # Store tag for GCM mode
            if tag is not None:
                layer.tag = tag
                current_data = layer.iv + tag + encrypted
            else:
                current_data = layer.iv + encrypted
        
        if progress_callback:
            await progress_callback(self.num_layers, self.num_layers)
            
        duration = time.time() - start_time
        data_size_mb = len(data) / (1024 * 1024)
        logger.debug(
            f"Encryption completed in {duration:.4f} seconds "
            f"({data_size_mb/max(duration, 0.001):.2f} MB/s)"
        )
        return current_data
    
    async def encrypt(
        self, 
        data: Union[bytes, str, BinaryIO, Path], 
        password: str,
        output_path: Optional[Union[str, Path]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Union[bytes, EncryptionResult]:
        """Encrypt data through all layers.
        
        Args:
            data: The data to encrypt (bytes, file path, or file-like object)
            password: The password to use for encryption
            output_path: Optional path to save encrypted data (required for file input)
            progress_callback: Optional callback for progress updates
            
        Returns:
            If output_path is None, returns encrypted bytes. Otherwise returns EncryptionResult.
        """
        start_time = time.time()
        
        # Handle different input types
        if isinstance(data, (str, Path)):
            if not output_path:
                output_path = Path(data).with_suffix('.enc')
            return await self._encrypt_file(Path(data), output_path, password, progress_callback)
            
        elif hasattr(data, 'read'):  # File-like object
            if not output_path:
                raise ValueError("output_path is required when data is a file-like object")
            return await self._encrypt_file(data, Path(output_path), password, progress_callback)
        
        # Handle bytes input
        elif isinstance(data, bytes):
            encrypted_data = await self._encrypt_bytes(data, password, progress_callback)
            return encrypted_data
        
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    async def _encrypt_bytes(
        self,
        data: bytes,
        password: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> bytes:
        """Encrypt bytes through all layers."""
        current_data = data
        
        # Process each layer
        for i in range(self.num_layers):
            if progress_callback:
                await progress_callback(i, self.num_layers)
                
            # Get current layer
            layer = self.layers[i]
            
            # Derive key for this layer
            key = await self.worker_pool.submit(
                self._derive_key,
                password.encode(),
                layer.key_derivation_salt
            )
            
            # Use hardware acceleration if available and data is large enough
            if (self.hardware_manager and 
                self.hardware_manager.is_available() and 
                len(current_data) >= self.hardware_manager.config.min_chunk_size):
                
                try:
                    # Use hardware-accelerated encryption
                    encrypted, tag = await self.hardware_manager.encrypt_chunk(
                        current_data, key, layer.iv, layer.mode
                    )
                    
                    if tag is not None:
                        layer.tag = tag
                        current_data = layer.iv + tag + encrypted
                    else:
                        current_data = layer.iv + encrypted
                    continue
                except Exception as e:
                    logger.warning(f"Hardware acceleration failed: {e}")
                    logger.info("Falling back to software encryption")
            
            # Fall back to software implementation
            def _encrypt() -> Tuple[bytes, Optional[bytes]]:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(current_data) + padder.finalize()
                
                if self.use_simd:
                    # Use SIMD-accelerated encryption if available
                    try:
                        mode_str = 'GCM' if layer.mode == EncryptionMode.GCM else 'CBC'
                        encryptor = SIMDEncryptor(key, mode=mode_str, iv=layer.iv)
                        
                        if layer.mode == EncryptionMode.GCM:
                            return encryptor.encrypt(padded_data)
                        return encryptor.encrypt(padded_data), None
                    except Exception as e:
                        logger.warning(f"SIMD encryption failed: {e}")
                
                # Fallback to standard implementation
                if layer.mode == EncryptionMode.GCM:
                    encryptor = Cipher(
                        algorithms.AES(key),
                        modes.GCM(layer.iv),
                        backend=default_backend()
                    ).encryptor()
                    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                    return ciphertext, encryptor.tag
                else:  # CBC mode
                    encryptor = Cipher(
                        algorithms.AES(key),
                        modes.CBC(layer.iv),
                        backend=default_backend()
                    ).encryptor()
                    return encryptor.update(padded_data) + encryptor.finalize(), None
            
            # Execute encryption in worker pool
            encrypted, tag = await self.worker_pool.submit(_encrypt)
            
            # Store tag for GCM mode
            if tag is not None:
                layer.tag = tag
                current_data = layer.iv + tag + encrypted
            else:
                current_data = layer.iv + encrypted
        
        if progress_callback:
            await progress_callback(self.num_layers, self.num_layers)
            
        return current_data
        
    async def _encrypt_file(
        self,
        input_path: Union[str, Path, BinaryIO],
        output_path: Path,
        password: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EncryptionResult:
        """Encrypt a file in chunks.
        
        Args:
            input_path: Path to input file or file-like object
            output_path: Path to save encrypted output
            password: Password for encryption
            progress_callback: Optional progress callback
            
        Returns:
            EncryptionResult with metadata about the operation
        """
        start_time = time.time()
        chunk_processor = get_chunk_processor()
        
        # Track progress
        original_size = (
            os.path.getsize(str(input_path)) 
            if not hasattr(input_path, 'seekable') or input_path.seekable()
            else 0
        )
        processed_size = 0
        
        async def process_chunk(chunk_data: bytes, **_) -> bytes:
            """Process a single chunk through all encryption layers."""
            nonlocal processed_size
            current_data = chunk_data
            
            # Process through all encryption layers
            for layer_idx in range(self.num_layers):
                if progress_callback:
                    # Calculate progress across all layers
                    total_steps = self.num_layers * (1 if original_size == 0 else original_size)
                    current_step = (layer_idx * len(chunk_data)) + processed_size
                    await progress_callback(int(current_step), int(total_steps))
                
                # Get current layer
                layer = self.layers[layer_idx]
                
                # Derive key for this layer
                key = await self.worker_pool.submit(
                    self._derive_key,
                    password.encode(),
                    layer.key_derivation_salt
                )
                
                # Use hardware acceleration if available and data is large enough
                if (self.hardware_manager and 
                    self.hardware_manager.is_available() and 
                    len(current_data) >= self.hardware_manager.config.min_chunk_size):
                    
                    try:
                        # Use hardware-accelerated encryption
                        encrypted, tag = await self.hardware_manager.encrypt_chunk(
                            current_data, key, layer.iv, layer.mode
                        )
                        
                        if tag is not None:
                            layer.tag = tag
                            current_data = layer.iv + tag + encrypted
                        else:
                            current_data = layer.iv + encrypted
                        continue
                    except Exception as e:
                        logger.warning(f"Hardware acceleration failed: {e}")
                        logger.info("Falling back to software encryption")
                
                # Fall back to software implementation
                def _encrypt() -> Tuple[bytes, Optional[bytes]]:
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(current_data) + padder.finalize()
                    
                    if self.use_simd:
                        # Use SIMD-accelerated encryption if available
                        try:
                            mode_str = 'GCM' if layer.mode == EncryptionMode.GCM else 'CBC'
                            encryptor = SIMDEncryptor(key, mode=mode_str, iv=layer.iv)
                            
                            if layer.mode == EncryptionMode.GCM:
                                return encryptor.encrypt(padded_data)
                            return encryptor.encrypt(padded_data), None
                        except Exception as e:
                            logger.warning(f"SIMD encryption failed: {e}")
                    
                    # Fallback to standard implementation
                    if layer.mode == EncryptionMode.GCM:
                        encryptor = Cipher(
                            algorithms.AES(key),
                            modes.GCM(layer.iv),
                            backend=default_backend()
                        ).encryptor()
                        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                        return ciphertext, encryptor.tag
                    else:  # CBC mode
                        encryptor = Cipher(
                            algorithms.AES(key),
                            modes.CBC(layer.iv),
                            backend=default_backend()
                        ).encryptor()
                        return encryptor.update(padded_data) + encryptor.finalize(), None
                
                # Execute encryption in worker pool
                encrypted, tag = await self.worker_pool.submit(_encrypt)
                
                # Store tag for GCM mode
                if tag is not None:
                    layer.tag = tag
                    current_data = layer.iv + tag + encrypted
                else:
                    current_data = layer.iv + encrypted
            
            processed_size += len(chunk_data)
            if progress_callback and original_size > 0:
                progress = min(1.0, processed_size / original_size)
                await progress_callback(int(processed_size), int(original_size))
            
            return current_data
        
        try:
            # Process the file in chunks
            await chunk_processor.process_file(
                input_path=str(input_path) if not hasattr(input_path, 'read') else input_path,
                output_path=str(output_path),
                process_func=process_chunk
            )
            
            # Get final size if we can
            try:
                encrypted_size = os.path.getsize(str(output_path))
            except (OSError, TypeError):
                encrypted_size = 0
            
            return EncryptionResult(
                data=None,  # Data was written directly to file
                metadata={
                    "layers": self.num_layers,
                    "original_size": original_size,
                    "encrypted_size": encrypted_size,
                    "output_path": str(output_path.absolute())
                },
                duration=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Error during file encryption: {e}")
            # Clean up output file if it exists
            try:
                if os.path.exists(str(output_path)):
                    os.remove(str(output_path))
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up after encryption failure: {cleanup_error}")
            
            raise RuntimeError(f"Encryption failed: {e}") from e
    
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
    
    async def decrypt(
        self, 
        encrypted_data: Union[bytes, str, BinaryIO, Path], 
        password: str,
        output_path: Optional[Union[str, Path]] = None
    ) -> EncryptionResult:
        """Decrypt data through all layers in reverse order.
        
        Args:
            encrypted_data: The data to decrypt (bytes, file path, or file-like object)
            password: The password used for encryption
            output_path: Optional path to save decrypted data (required for file input)
            
        Returns:
            EncryptionResult containing the decrypted data and metadata
        """
        start_time = time.time()
        
        # Handle different input types
        if isinstance(encrypted_data, (str, Path)):
            if not output_path:
                raise ValueError("output_path is required when data is a file path")
            return await self._decrypt_file(Path(encrypted_data), output_path, password)
            
        elif hasattr(encrypted_data, 'read'):  # File-like object
            if not output_path:
                raise ValueError("output_path is required when data is a file-like object")
            return await self._decrypt_file(encrypted_data, Path(output_path), password)
            
        # Process in-memory data
        current_data = encrypted_data
        for layer_idx in range(self.num_layers - 1, -1, -1):
            try:
                current_data = await self._decrypt_layer(current_data, layer_idx, password)
            except Exception as e:
                logger.error("Decryption failed at layer %d: %s", layer_idx, str(e))
                raise
        
        return EncryptionResult(
            data=current_data,
            metadata={
                "layers": self.num_layers,
                "encrypted_size": len(encrypted_data),
                "decrypted_size": len(current_data)
            },
            duration=time.time() - start_time
        )
        
    async def _decrypt_file(
        self,
        input_path: Union[str, Path, BinaryIO],
        output_path: Path,
        password: str
    ) -> EncryptionResult:
        """Decrypt a file in chunks."""
        chunk_processor = get_chunk_processor()
        
        # Track progress
        encrypted_size = os.path.getsize(str(input_path))
        processed_size = 0
        
        async def process_chunk(chunk_data: bytes, **_) -> bytes:
            """Process a single chunk through all decryption layers."""
            nonlocal processed_size
            current_data = chunk_data
            
            # Process in reverse order for decryption
            for layer_idx in range(self.num_layers - 1, -1, -1):
                current_data = await self._decrypt_layer(current_data, layer_idx, password)
                
            processed_size += len(chunk_data)
            progress = min(1.0, processed_size / encrypted_size)
            self._notify_progress(progress, f"Decrypting: {progress:.1%}")
            
            return current_data
        
        # Process the file in chunks
        await chunk_processor.process_file(
            input_path=str(input_path),
            output_path=str(output_path),
            process_func=process_chunk
        )
        
        return EncryptionResult(
            data=None,  # Data was written directly to file
            metadata={
                "layers": self.num_layers,
                "encrypted_size": encrypted_size,
                "decrypted_size": os.path.getsize(str(output_path)),
                "output_path": str(output_path.absolute())
            },
            duration=time.time() - start_time
        )
    
    async def close(self):
        """Clean up resources."""
        # Worker pool is managed globally, no need to shut it down here
        pass
        
    def __del__(self):
        """Clean up resources."""
        # Try to close properly if the event loop is running
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.close())
        except Exception:
            pass

class EncryptionPipeline:
    """High-level encryption pipeline with progress tracking and file handling."""
    
    def __init__(self, num_layers: int = 10, chunk_size: int = 4 * 1024 * 1024):
        """Initialize the encryption pipeline.
        
        Args:
            num_layers: Number of encryption layers to use
            chunk_size: Size of chunks for file processing (default: 4MB)
        """
        self.encryptor = MultiLayerEncryptor(num_layers=num_layers)
        self.chunk_size = chunk_size
        self.progress_callbacks = []
    
    async def process(
        self, 
        data: Union[bytes, str, Path, BinaryIO], 
        password: str, 
        encrypt: bool = True,
        output_path: Optional[Union[str, Path]] = None
    ) -> EncryptionResult:
        """Process data through the encryption/decryption pipeline.
        
        Args:
            data: Input data (bytes, file path, or file-like object)
            password: Password for encryption/decryption
            encrypt: If True, encrypt the data; if False, decrypt it
            output_path: Path to save output (required for file input/output)
            
        Returns:
            EncryptionResult with the processed data and metadata
        """
        try:
            if encrypt:
                result = await self.encryptor.encrypt(data, password, output_path=output_path, chunk_size=self.chunk_size)
            else:
                result = await self.encryptor.decrypt(data, password, output_path=output_path, chunk_size=self.chunk_size)
            
            self._notify_progress(1.0, "Completed")
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error("Pipeline error: %s", error_msg, exc_info=True)
            self._notify_progress(0.0, f"Error: {error_msg}")
            raise
    
    def add_progress_callback(self, callback):
        """Add a progress callback function."""
        self.progress_callbacks.append(callback)
    def _notify_progress(self, progress: float, status: str):
        """Notify all registered progress callbacks."""
        for callback in self.progress_callbacks:
            try:
                callback(progress, status)
            except Exception as e:
                logger.error("Error in progress callback: %s", str(e))

async def example():
    """Example usage of the encryption pipeline."""
    try:
        pipeline = EncryptionPipeline(num_layers=5)
        test_data = b"Hello, this is a test message!"
        password = "secure_password_123"
        
        print("Original:", test_data)
        
        # Encrypt
        print("\nEncrypting...")
        encrypted = await pipeline.encryptor.encrypt(test_data, password)
        print("Encrypted:", base64.b64encode(encrypted.data[:30]).decode() + "...")
        
        # Decrypt
        print("\nDecrypting...")
        decrypted = await pipeline.encryptor.decrypt(encrypted.data, password)
        print("Decrypted:", decrypted.data.decode())
        
        # Verify
        assert test_data == decrypted.data
        print("\nTest passed!")
        
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    asyncio.run(example())
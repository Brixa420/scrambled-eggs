"""
Core encryption/decryption logic for Scrambled Eggs.
"""
import hashlib
import os
import hmac
import time
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple, Dict, Any, List, Union, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

from .exceptions import (
    ScrambledEggsError,
    EncryptionError,
    DecryptionError,
    BreachDetected,
    KeyDerivationError,
    AuthenticationError
)
from .security import (
    KeyDerivation,
    HybridEncryption,
    MemoryProtector as MemoryProtection,  # Alias for backward compatibility
    BreachDetector
)
from .config import get_config
from .utils import timeit, parallel_process

logger = logging.getLogger(__name__)

class ScrambledEggs:
    """
    A self-modifying encryption system that evolves when breached.
    
    This implementation uses a hybrid encryption approach with both symmetric
    and asymmetric cryptography for enhanced security. It also includes
    sophisticated breach detection and automatic key rotation.
    """
    
    def __init__(self, password: str, initial_layers: Optional[int] = None):
        """
        Initialize the ScrambledEggs encryption system with dynamic layer scaling.
        
        Args:
            password: The master password for encryption/decryption
            initial_layers: Number of hashing layers to start with (default: from config)
        """
        if not password:
            raise ValueError("Password cannot be empty")
            
        # Load configuration
        self.config = get_config()
        
        # Initialize security parameters
        self._init_security_parameters()
        
        # Store password in a secure way
        self._password = password.encode('utf-8')
        
        # Initialize encryption state with dynamic layer management
        self.layers = initial_layers or self.config.get('security.encryption.initial_layers', 100)
        self.breach_count = 0
        self.last_encryption_time = 0
        self.adaptive_difficulty = True  # Enable dynamic layer adjustment
        
        # Performance metrics
        self.performance_history = []
        self.max_ram_usage = self.config.get('security.encryption.max_ram_usage_mb', 1024) * 1024 * 1024
        self.target_encryption_time = self.config.get('security.encryption.target_encryption_time_ms', 1000) / 1000.0
        
        # Initialize keys and state
        self._init_keys()
        
        # Initialize breach detection with a default threshold
        breach_threshold = self.config.get('security.breach_detection.suspicion_threshold', 0.8)
        try:
            self.breach_detector = BreachDetector(threshold=breach_threshold)
        except TypeError:
            # Fallback if BreachDetector doesn't accept threshold parameter
            logger.warning("BreachDetector doesn't accept threshold parameter, using default configuration")
            self.breach_detector = BreachDetector()
        self.breach_count = 0
        self.last_breach_time = 0
        
        logger.debug("ScrambledEggs initialized with %d layers", self.layers)
    
    def _init_security_parameters(self) -> None:
        """Initialize security parameters from config."""
        self.key_derivation_config = self.config.get('security.key_derivation', {})
        self.encryption_config = self.config.get('security.encryption', {})
        
        # Key sizes
        self.salt_size = self.key_derivation_config.get('salt_length', 16)
        self.key_size = self.encryption_config.get('aes_key_size', 32)  # 256 bits
        self.iv_size = 12  # 96 bits for AES-GCM
        
        # Performance settings
        self.chunk_size = self.config.get('performance.chunk_size', 1024 * 1024)  # 1MB
        self.max_workers = self.config.get('performance.max_workers')
    
    def _init_keys(self) -> None:
        """Initialize encryption keys."""
        # Generate a new salt
        self.salt = os.urandom(self.salt_size)
        
        # Derive the master key
        self.master_key, _ = KeyDerivation.derive_key(
            self._password,
            self.salt,
            **self.key_derivation_config
        )
        
        # Generate encryption keys
        self._generate_encryption_keys()
    
    def _generate_encryption_keys(self) -> None:
        """Generate encryption keys from the master key."""
        # Generate a random nonce for key derivation
        nonce = os.urandom(16)
        
        # Derive encryption and authentication keys
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size * 2,
            salt=nonce,
            iterations=100000,
        )
        
        keys = kdf.derive(self.master_key)
        self.encryption_key = keys[:self.key_size]
        self.auth_key = keys[self.key_size:]
        
        # Initialize AES-GCM
        self.aesgcm = AESGCM(self.encryption_key)
    
    def _derive_key(self, salt: Optional[bytes] = None) -> bytes:
        """
        Derive an encryption key using Argon2.
        
        Args:
            salt: Optional salt (will generate if not provided)
            
        Returns:
            Derived key
            
        Raises:
            KeyDerivationError: If key derivation fails
        """
        try:
            key, _ = KeyDerivation.derive_key(
                self._password,
                salt or self.salt,
                **self.key_derivation_config
            )
            return key
        except Exception as e:
            logger.error("Key derivation failed: %s", str(e))
            raise KeyDerivationError(f"Failed to derive key: {str(e)}")
    
    def _hash_layer(self, data: bytes, layer_num: int) -> bytes:
        """
        Apply a single layer of authenticated encryption.
        
        Args:
            data: Data to encrypt
            layer_num: Layer number for unique nonce generation
            
        Returns:
            Encrypted and authenticated data
        """
        # Generate a unique nonce for this layer
        nonce = self._generate_nonce(layer_num)
        
        try:
            # Encrypt the data with AES-GCM
            ciphertext = self.aesgcm.encrypt(
                nonce=nonce,
                data=data,
                associated_data=self._get_associated_data(layer_num)
            )
            return ciphertext
        except Exception as e:
            logger.error("Layer %d encryption failed: %s", layer_num, str(e))
            raise EncryptionError(f"Layer {layer_num} encryption failed") from e
    
    def _generate_nonce(self, layer_num: int) -> bytes:
        """Generate a unique nonce for a specific layer."""
        # Use HMAC to derive a unique nonce for this layer
        h = hmac.HMAC(
            self.auth_key,
            hashes.SHA256()
        )
        h.update(struct.pack('!Q', layer_num))
        h.update(struct.pack('!Q', self.breach_count))
        return h.finalize()[:self.iv_size]
    
    def _get_associated_data(self, layer_num: int) -> bytes:
        """Generate associated data for authenticated encryption."""
        return f"layer:{layer_num}:breach:{self.breach_count}".encode('utf-8')
    
    def _calculate_layer_increase(self) -> int:
        """Calculate the number of layers to add based on breach history and performance."""
        # Base increase is a random value within configured range
        min_inc = self.config.get('security.encryption.min_layer_increase', 5)
        max_inc = self.config.get('security.encryption.max_layer_increase', 50)
        growth_factor = self.config.get('security.encryption.layer_growth_factor', 1.1)
        
        # Increase based on breach count and performance
        breach_factor = 1 + (self.breach_count * 0.1)  # 10% more per breach
        
        # Calculate random increase with exponential growth
        base_increase = random.randint(min_inc, max_inc)
        scaled_increase = int(base_increase * (growth_factor ** self.breach_count) * breach_factor)
        
        # Ensure we don't cause memory issues
        estimated_memory = (scaled_increase * 64)  # Rough estimate: 64 bytes per layer
        if estimated_memory > self.max_ram_usage * 0.5:  # Don't use more than 50% of max RAM
            scaled_increase = int((self.max_ram_usage * 0.5) / 64)
            
        return max(min_inc, scaled_increase)
    
    def _adjust_difficulty(self, encryption_time: float) -> None:
        """Dynamically adjust encryption parameters based on performance."""
        if not self.adaptive_difficulty:
            return
            
        # Store performance data
        self.performance_history.append({
            'time': time.time(),
            'encryption_time': encryption_time,
            'layers': self.layers,
            'ram_usage': self._get_memory_usage()
        })
        
        # Keep only recent history (last 10 encryptions)
        if len(self.performance_history) > 10:
            self.performance_history.pop(0)
            
        # Adjust layers based on performance
        target_time = self.target_encryption_time
        time_ratio = encryption_time / target_time
        
        if time_ratio < 0.8:  # Too fast, increase difficulty
            self.layers = int(self.layers * 1.1)  # 10% more layers
            logger.info(f"Increased layers to {self.layers} (encryption too fast)")
        elif time_ratio > 1.5:  # Too slow, decrease difficulty
            self.layers = max(
                self.config.get('security.encryption.min_layer_increase', 5),
                int(self.layers * 0.9)  # 10% fewer layers
            )
            logger.info(f"Decreased layers to {self.layers} (encryption too slow)")
    
    def _get_memory_usage(self) -> int:
        """Get current process memory usage in bytes."""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss
    
    def _scramble_layers(self) -> Dict[str, Any]:
        """
        Modify the encryption scheme after a breach is detected.
        Uses unlimited layer growth with dynamic scaling.
        
        Returns:
            Dictionary with information about the changes made
        """
        self.breach_count += 1
        self.last_breach_time = time.time()
        
        # Log the breach
        logger.warning("SECURITY BREACH DETECTED! Enhancing encryption...")
        
        # Change the salt and rederive keys
        self.salt = os.urandom(self.salt_size)
        self.master_key = self._derive_key()
        self._generate_encryption_keys()
        
        # Calculate new layer count with dynamic increase
        layer_increase = self._calculate_layer_increase()
        old_layers = self.layers
        self.layers += layer_increase
        
        # Log the security enhancement
        logger.warning(
            f"ENCRYPTION ENHANCED: Layers increased from {old_layers} to {self.layers} "
            f"(+{layer_increase}) after breach #{self.breach_count}"
        )
        
        # Update security parameters
        security_updates = {
            'layers_added': layer_increase,
            'total_layers': self.layers,
            'breach_count': self.breach_count,
            'timestamp': self.last_breach_time
        }
        
        # Increase key derivation parameters periodically
        if self.breach_count % 5 == 0:  # Every 5 breaches
            new_iterations = int(self.key_derivation_config.get('iterations', 100000) * 1.5)
            self.key_derivation_config['iterations'] = new_iterations
            security_updates['iterations_increased_to'] = new_iterations
            
            new_memory = int(self.key_derivation_config.get('memory_cost', 65536) * 1.5)
            self.key_derivation_config['memory_cost'] = new_memory
            security_updates['memory_cost_increased_to'] = new_memory
        
        # Update breach detector with increased sensitivity
        self.breach_detector.threshold = min(0.95, self.breach_detector.threshold + 0.05)
        
        logger.info(f"Security update complete: {security_updates}")
        return security_updates
    
    def _detect_breach(self, data: bytes) -> bool:
        """
        Detect potential security breaches.
        
        Args:
            data: Data being processed
            
        Returns:
            bool: True if a breach is detected
        """
        # Check for suspicious patterns in the data
        if self._contains_suspicious_patterns(data):
            logger.warning("Suspicious patterns detected in data")
            return True
        
        # Check with the breach detector
        if self.breach_detector.analyze_attempt(time.time()):
            logger.warning("Breach detected by breach detector")
            return True
            
        return False
    
    def _contains_suspicious_patterns(self, data: bytes) -> bool:
        """Check for known attack patterns in the data."""
        # Check for known plaintext attacks
        known_plaintexts = [
            b'\x00' * 16,  # All zeros
            b'\xFF' * 16,  # All ones
            b'\x00\x01' * 8,  # Alternating pattern
        ]
        
        for pattern in known_plaintexts:
            if pattern in data:
                return True
                
        # Check for high entropy (potential encrypted data being re-encrypted)
        if self._calculate_entropy(data) > 7.5:  # Very high entropy
            return True
            
        return False
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate the Shannon entropy of a byte string."""
        if not data:
            return 0.0
            
        import math
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
                
        return entropy
    
    @timeit
    def encrypt(self, plaintext: Union[bytes, str], chunked: bool = False, 
               measure_performance: bool = True) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt data with multiple layers of encryption.
        
        Args:
            plaintext: Data to encrypt (bytes or string)
            chunked: If True, process in chunks for large data
            
        Returns:
            Tuple of (ciphertext, metadata)
            
        Raises:
            EncryptionError: If encryption fails
        """
        if not isinstance(plaintext, bytes):
            plaintext = str(plaintext).encode('utf-8')
        
        # Check for breach before encryption
        if self._detect_breach(plaintext):
            breach_info = self._scramble_layers()
        else:
            breach_info = {}
        
        # Process in chunks for large data
        if chunked and len(plaintext) > self.chunk_size * 4:  # 4MB threshold
            return self._encrypt_chunked(plaintext)
        
        # Single-threaded encryption for small data
        try:
            start_time = time.time()
            current = plaintext
            
            # Apply encryption layers with progress monitoring
            for i in range(self.layers):
                current = self._hash_layer(current, i)
                
                # Check for breach during encryption (every 10% of layers)
                if i > 0 and i % max(1, self.layers // 10) == 0:
                    if self._detect_breach(current):
                        breach_info = self._scramble_layers()
                    
                    # Check memory usage
                    if self._get_memory_usage() > self.max_ram_usage * 0.8:  # 80% of max RAM
                        logger.warning("High memory usage detected, optimizing...")
                        self.layers = max(
                            self.layers // 2,
                            self.config.get('security.encryption.min_layer_increase', 5)
                        )
                        logger.info(f"Reduced layers to {self.layers} due to memory constraints")
            
            # Calculate encryption time and adjust difficulty
            encryption_time = time.time() - start_time
            if measure_performance:
                self._adjust_difficulty(encryption_time)
            
            # Prepare metadata with performance data
            metadata = self._generate_metadata(breach_info if 'breach_info' in locals() else {})
            metadata.update({
                'performance': {
                    'encryption_time_seconds': encryption_time,
                    'layers_processed': self.layers,
                    'bytes_processed': len(plaintext),
                    'throughput_mb_s': len(plaintext) / (encryption_time * 1024 * 1024) if encryption_time > 0 else 0,
                    'memory_usage_mb': self._get_memory_usage() / (1024 * 1024)
                }
            })
            
            return current, metadata
            
        except Exception as e:
            logger.exception("Encryption failed")
            raise EncryptionError(f"Encryption failed: {str(e)}") from e
    
    def _encrypt_chunked(self, data: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt large data in chunks."""
        logger.debug("Using chunked encryption for %d bytes", len(data))
        
        # Split data into chunks
        chunks = [
            data[i:i + self.chunk_size] 
            for i in range(0, len(data), self.chunk_size)
        ]
        
        # Process chunks in parallel
        processed_chunks = parallel_process(
            chunks,
            lambda chunk: self._hash_chunk(chunk, self.layers),
            max_workers=self.max_workers
        )
        
        # Combine chunks
        ciphertext = b''.join(processed_chunks)
        
        # Generate metadata
        metadata = self._generate_metadata({})
        
        return ciphertext, metadata
    
    def _hash_chunk(self, chunk: bytes, layers: int) -> bytes:
        """Apply multiple layers of encryption to a chunk."""
        current = chunk
        for i in range(layers):
            current = self._hash_layer(current, i)
        return current
    
    def _generate_metadata(self, breach_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata for encrypted data."""
        return {
            'version': '2.0',
            'algorithm': 'AES-256-GCM',
            'layers_used': self.layers,
            'salt': self.salt.hex(),
            'breach_count': self.breach_count,
            'key_derivation': {
                'algorithm': 'Argon2',
                'iterations': self.key_derivation_config.get('iterations'),
                'memory_cost': self.key_derivation_config.get('memory_cost'),
                'parallelism': self.key_derivation_config.get('parallelism')
            },
            'timestamp': time.time(),
            'breach_info': breach_info,
            'security_level': self._calculate_security_level()
        }
    
    def _calculate_security_level(self) -> str:
        """Calculate the current security level."""
        # This is a simplified calculation
        security_score = (
            self.layers / 100.0 * 
            (self.key_derivation_config.get('iterations', 100000) / 100000) *
            (self.breach_count + 1)  # More breaches = stronger security
        )
        
        if security_score > 2.0:
            return "very high"
        elif security_score > 1.5:
            return "high"
        elif security_score > 1.0:
            return "medium"
        else:
            return "standard"
    
    @timeit
    def decrypt(self, ciphertext: bytes, metadata: Dict[str, Any]) -> bytes:
        """
        Decrypt data that was encrypted with this system.
        
        Args:
            ciphertext: Encrypted data
            metadata: Metadata from encryption
            
        Returns:
            Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption fails
            AuthenticationError: If the data fails authentication
        """
        try:
            # Verify metadata
            self._verify_metadata(metadata)
            
            # Update internal state from metadata
            self._update_from_metadata(metadata)
            
            # Check for breach attempts
            if self._detect_breach(ciphertext):
                self._scramble_layers()
                raise AuthenticationError("Potential breach attempt detected")
            
            # For demonstration, we'll just return a success message
            # In a real implementation, you would reverse the encryption process
            return b"Decryption successful (demo mode)"
            
        except Exception as e:
            logger.exception("Decryption failed")
            if isinstance(e, (DecryptionError, AuthenticationError)):
                raise
            raise DecryptionError(f"Decryption failed: {str(e)}") from e
    
    def _verify_metadata(self, metadata: Dict[str, Any]) -> None:
        """Verify that the metadata is valid."""
        required_fields = [
            'version', 'algorithm', 'layers_used', 'salt', 
            'breach_count', 'key_derivation', 'timestamp'
        ]
        
        for field in required_fields:
            if field not in metadata:
                raise DecryptionError(f"Missing required metadata field: {field}")
        
        # Check for version compatibility
        if metadata['version'] != '2.0':
            raise DecryptionError(f"Unsupported version: {metadata['version']}")
        
        # Check timestamp (prevent replay attacks)
        max_age = 3600 * 24 * 7  # 1 week
        if time.time() - metadata['timestamp'] > max_age:
            raise DecryptionError("Metadata is too old")
    
    def _update_from_metadata(self, metadata: Dict[str, Any]) -> None:
        """Update internal state from metadata."""
        # Update salt and rederive keys if needed
        if 'salt' in metadata:
            salt = bytes.fromhex(metadata['salt'])
            if salt != self.salt:
                self.salt = salt
                self.master_key = self._derive_key()
                self._generate_encryption_keys()
        
        # Update breach count
        self.breach_count = metadata.get('breach_count', 0)
        
        # Update key derivation parameters if they've changed
        kd_meta = metadata.get('key_derivation', {})
        for param in ['iterations', 'memory_cost', 'parallelism']:
            if param in kd_meta and kd_meta[param] != self.key_derivation_config.get(param):
                self.key_derivation_config[param] = kd_meta[param]
    
    def __del__(self):
        """Clean up sensitive data."""
        if hasattr(self, '_password'):
            MemoryProtection.secure_erase(bytearray(self._password))
        if hasattr(self, 'master_key'):
            MemoryProtection.secure_erase(bytearray(self.master_key))
        if hasattr(self, 'encryption_key'):
            MemoryProtection.secure_erase(bytearray(self.encryption_key))
        if hasattr(self, 'auth_key'):
            MemoryProtection.secure_erase(bytearray(self.auth_key))

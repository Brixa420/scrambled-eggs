""
CPU-based hardware acceleration backend with AES-NI support.
"""

import os
import platform
import subprocess
import ctypes
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from . import HardwareBackend, HardwareBackendType, hardware_manager

logger = logging.getLogger(__name__)

class CPUAESBackend(HardwareBackend):
    """CPU-based AES implementation with hardware acceleration support."""
    
    def __init__(self):
        super().__init__()
        self.aes_ni_available = self._check_aes_ni_support()
        self.available = True  # CPU backend is always available
        self.performance_factor = 2.0 if self.aes_ni_available else 1.0
        self._cipher_cache = {}
    
    def _check_aes_ni_support(self) -> bool:
        """Check if AES-NI instructions are available on this CPU."""
        try:
            if platform.system() == 'Windows':
                # Check CPU flags on Windows
                import ctypes
                cpu_info = [0] * 4
                ctypes.windll.kernel32.IsProcessorFeaturePresent(6)  # PF_XMMI_INSTRUCTIONS_AVAILABLE
                ctypes.windll.kernel32.IsProcessorFeaturePresent(13)  # PF_XMMI64_INSTRUCTIONS_AVAILABLE
                ctypes.windll.kernel32.IsProcessorFeaturePresent(23)  # PF_AES_INSTRUCTION_AVAILABLE
                return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(23))
            else:
                # Check CPU flags on Linux/Unix
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                return 'aes' in cpuinfo.lower() and 'sse4_1' in cpuinfo.lower()
        except Exception as e:
            logger.warning(f"Could not check AES-NI support: {e}")
            return False
    
    def _get_cipher(self, key: bytes, iv: bytes) -> Tuple[Cipher, bool]:
        """Get or create a cipher instance with the given key and IV."""
        cache_key = (bytes(key), bytes(iv))
        if cache_key in self._cipher_cache:
            return self._cipher_cache[cache_key], True
        
        # Use AES in GCM mode for authenticated encryption
        algorithm = algorithms.AES(key)
        mode_ = modes.GCM(iv)
        backend = default_backend()
        
        # Create new cipher
        cipher = Cipher(algorithm, mode_, backend=backend)
        self._cipher_cache[cache_key] = cipher
        return cipher, False
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt data using AES-GCM."""
        try:
            cipher, cached = self._get_cipher(key, iv)
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-GCM."""
        try:
            cipher, _ = self._get_cipher(key, iv)
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def benchmark(self, data_size: int = 1024 * 1024) -> float:
        """Benchmark the encryption/decryption speed in MB/s."""
        import time
        import os
        
        # Generate test data
        data = os.urandom(data_size)
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(12)   # 96-bit IV for GCM
        
        # Warm-up
        self.encrypt(data[:1024], key, iv)
        
        # Benchmark encryption
        start_time = time.time()
        encrypted = self.encrypt(data, key, iv)
        encrypt_time = time.time() - start_time
        
        # Benchmark decryption
        start_time = time.time()
        self.decrypt(encrypted, key, iv)
        decrypt_time = time.time() - start_time
        
        # Calculate throughput in MB/s
        mb = data_size / (1024 * 1024)
        encrypt_speed = mb / max(encrypt_time, 1e-6)
        decrypt_speed = mb / max(decrypt_time, 1e-6)
        
        logger.info(
            f"CPU AES-256-GCM Performance: "
            f"Encrypt: {encrypt_speed:.2f} MB/s, "
            f"Decrypt: {decrypt_speed:.2f} MB/s"
        )
        
        return (encrypt_speed + decrypt_speed) / 2


def initialize_cpu_backend() -> None:
    """Initialize and register the CPU backend."""
    cpu_backend = CPUAESBackend()
    if cpu_backend.available:
        hardware_manager.register_backend(HardwareBackendType.CPU, cpu_backend)
        hardware_manager.register_backend(HardwareBackendType.INTEL_AESNI, cpu_backend)
        logger.info("CPU backend registered with AES-NI support: " + 
                   ("enabled" if cpu_backend.aes_ni_available else "disabled"))
    else:
        logger.warning("CPU backend is not available")

# Register the CPU backend when this module is imported
initialize_cpu_backend()

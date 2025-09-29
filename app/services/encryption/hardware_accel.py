""
Hardware Acceleration Integration for Scrambled Eggs Encryption

This module provides a high-level interface for hardware-accelerated
encryption operations, automatically selecting the best available backend.
"""

import logging
from typing import Optional, Tuple, Dict, Any

from .hardware import (
    HardwareBackendType,
    hardware_manager,
    initialize_hardware,
    get_hardware_backend
)
from .hardware.cpu_backend import initialize_cpu_backend

# Try to import optional backends
try:
    from .hardware.cuda_backend import initialize_cuda_backend
    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False

try:
    from .hardware.opencl_backend import initialize_opencl_backend
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Initialize hardware backends
initialize_cpu_backend()

if CUDA_AVAILABLE:
    try:
        initialize_cuda_backend()
    except Exception as e:
        logger.warning(f"Failed to initialize CUDA backend: {e}")

if OPENCL_AVAILABLE:
    try:
        initialize_opencl_backend()
    except Exception as e:
        logger.warning(f"Failed to initialize OpenCL backend: {e}")

# Initialize hardware manager
initialize_hardware()


def get_available_backends() -> Dict[str, Dict[str, Any]]:
    """Get information about available hardware backends.
    
    Returns:
        Dictionary mapping backend names to their information
    """
    backends = {}
    
    for backend_type, backend in hardware_manager.get_available_backends().items():
        backends[backend_type.name] = {
            'type': backend_type,
            'performance_factor': backend.performance_factor,
            'description': backend.__class__.__name__
        }
        
        # Add backend-specific information
        if hasattr(backend, 'device') and hasattr(backend.device, 'name'):
            backends[backend_type.name]['device'] = backend.device.name
        elif hasattr(backend, 'aes_ni_available'):
            backends[backend_type.name]['aes_ni'] = backend.aes_ni_available
    
    return backends


def get_accelerated_encryptor(backend_type: Optional[str] = None):
    """Get an accelerated encryptor for the specified backend.
    
    Args:
        backend_type: Optional backend type ('cuda', 'opencl', 'cpu', 'auto')
        
    Returns:
        A callable encryptor function or None if no suitable backend is available
    """
    # Convert string to enum if needed
    if isinstance(backend_type, str):
        try:
            backend_type_enum = HardwareBackendType[backend_type.upper()]
        except KeyError:
            logger.warning(f"Unknown backend type: {backend_type}. Using auto-detection.")
            backend_type_enum = HardwareBackendType.AUTO
    else:
        backend_type_enum = backend_type or HardwareBackendType.AUTO
    
    # Get the best available backend
    backend = hardware_manager.get_backend(backend_type_enum)
    
    if backend is None:
        logger.warning("No suitable hardware acceleration backend found")
        return None
    
    logger.info(f"Using hardware backend: {backend.__class__.__name__}")
    
    # Return a simple encrypt/decrypt interface
    class AcceleratedEncryptor:
        """Wrapper for hardware-accelerated encryption operations."""
        
        def __init__(self, backend):
            self.backend = backend
            self.backend_type = backend_type_enum
            self.performance_factor = backend.performance_factor
        
        def encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
            """Encrypt data using the selected hardware backend."""
            return self.backend.encrypt(data, key, iv)
        
        def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
            """Decrypt data using the selected hardware backend."""
            return self.backend.decrypt(data, key, iv)
        
        def benchmark(self, data_size: int = 1024 * 1024) -> float:
            """Benchmark the encryption/decryption speed."""
            return self.backend.benchmark(data_size)
    
    return AcceleratedEncryptor(backend)


def benchmark_backends(data_size: int = 1024 * 1024) -> Dict[str, float]:
    """Benchmark all available backends.
    
    Args:
        data_size: Size of test data in bytes
        
    Returns:
        Dictionary mapping backend names to their benchmark scores (MB/s)
    """
    results = {}
    
    for backend_type, backend in hardware_manager.get_available_backends().items():
        try:
            speed = backend.benchmark(data_size)
            results[backend_type.name] = speed
        except Exception as e:
            logger.error(f"Benchmark failed for {backend_type.name}: {e}")
            results[backend_type.name] = 0.0
    
    return results


# Example usage
if __name__ == "__main__":
    import os
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Get available backends
    print("\nAvailable hardware backends:")
    for name, info in get_available_backends().items():
        print(f"- {name}: {info.get('description', 'N/A')}")
        if 'device' in info:
            print(f"  Device: {info['device']}")
        if 'aes_ni' in info:
            print(f"  AES-NI: {'Enabled' if info['aes_ni'] else 'Disabled'}")
    
    # Benchmark all backends
    print("\nRunning benchmarks...")
    results = benchmark_backends()
    
    print("\nBenchmark Results (MB/s):")
    for backend, speed in results.items():
        print(f"- {backend}: {speed:.2f} MB/s")
    
    # Test encryption/decryption
    print("\nTesting encryption/decryption...")
    encryptor = get_accelerated_encryptor()
    
    if encryptor:
        test_data = os.urandom(1024)  # 1KB test data
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(12)   # 96-bit IV for GCM
        
        try:
            encrypted = encryptor.encrypt(test_data, key, iv)
            decrypted = encryptor.decrypt(encrypted, key, iv)
            
            if decrypted == test_data:
                print("✓ Encryption/decryption successful")
            else:
                print("✗ Encryption/decryption failed: Data mismatch")
                
        except Exception as e:
            print(f"✗ Error during encryption/decryption: {e}")

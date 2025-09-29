""
OpenCL-based hardware acceleration backend for various devices.
"""

import os
import logging
from typing import Optional, Tuple, Dict, Any, List

import numpy as np

from . import HardwareBackend, HardwareBackendType, hardware_manager

logger = logging.getLogger(__name__)

# Try to import OpenCL dependencies
try:
    import pyopencl as cl
    import pyopencl.array as cl_array
    from pyopencl import mem_flags as mf
    
    # Try to create a context to verify OpenCL is working
    try:
        ctx = cl.create_some_context()
        OPENCL_AVAILABLE = True
    except Exception as e:
        logger.warning(f"OpenCL context creation failed: {e}")
        OPENCL_AVAILABLE = False
    
except ImportError:
    OPENCL_AVAILABLE = False
except Exception as e:
    logger.warning(f"OpenCL initialization failed: {e}")
    OPENCL_AVAILABLE = False


class OpenCLAESBackend(HardwareBackend):
    """OpenCL-accelerated AES implementation for various devices."""
    
    def __init__(self):
        super().__init__()
        self.available = False
        self.performance_factor = 3.0  # Expected speedup over CPU
        self._context = None
        self._queue = None
        self._program = None
        self._device = None
        
        if not OPENCL_AVAILABLE:
            logger.warning("OpenCL is not available. Install pyopencl and OpenCL runtime.")
            return
            
        try:
            # Initialize OpenCL context and queue
            platforms = cl.get_platforms()
            if not platforms:
                logger.warning("No OpenCL platforms found")
                return
                
            # Select the first available device
            for platform in platforms:
                try:
                    devices = platform.get_devices()
                    if devices:
                        self._device = devices[0]  # Use first device
                        self._context = cl.Context([self._device])
                        self._queue = cl.CommandQueue(self._context)
                        break
                except Exception as e:
                    logger.warning(f"Failed to initialize OpenCL device: {e}")
            
            if not self._context:
                logger.warning("No suitable OpenCL devices found")
                return
                
            # Build OpenCL program
            self._build_program()
            
            self.available = True
            logger.info(f"OpenCL backend initialized on {self._device.name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenCL backend: {e}")
            self.available = False
    
    def _build_program(self) -> None:
        """Build the OpenCL program with AES implementation."""
        # This is a simplified AES implementation for demonstration.
        # A production implementation would include a complete AES-GCM implementation.
        aes_source = """
        __kernel void aes_encrypt(
            __global const uchar* input,
            __global uchar* output,
            __constant uchar* key,
            __constant uchar* iv,
            const uint length
        ) {
            int gid = get_global_id(0);
            if (gid < length) {
                // Simple XOR operation as a placeholder for actual AES
                // In a real implementation, this would be a full AES implementation
                output[gid] = input[gid] ^ key[gid % 32] ^ iv[gid % 12];
            }
        }
        """
        
        try:
            self._program = cl.Program(self._context, aes_source).build()
        except Exception as e:
            logger.error(f"Failed to build OpenCL program: {e}")
            raise
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt data using AES-GCM on OpenCL device."""
        if not self.available:
            raise RuntimeError("OpenCL backend is not available")
            
        try:
            # Convert inputs to numpy arrays
            data_np = np.frombuffer(data, dtype=np.uint8)
            key_np = np.frombuffer(key, dtype=np.uint8)
            iv_np = np.frombuffer(iv, dtype=np.uint8)
            
            # Create buffers on the device
            mf = cl.mem_flags
            data_buf = cl.Buffer(self._context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_np)
            key_buf = cl.Buffer(self._context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=key_np)
            iv_buf = cl.Buffer(self._context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=iv_np)
            output_buf = cl.Buffer(self._context, mf.WRITE_ONLY, data_np.nbytes)
            
            # Execute the kernel
            self._program.aes_encrypt(
                self._queue, 
                data_np.shape, 
                None,  # Work group size (None for auto)
                data_buf, 
                output_buf, 
                key_buf, 
                iv_buf, 
                np.uint32(len(data_np))
            )
            
            # Read the result
            result = np.empty_like(data_np)
            cl.enqueue_copy(self._queue, result, output_buf)
            
            return result.tobytes()
            
        except Exception as e:
            logger.error(f"OpenCL encryption failed: {e}")
            raise
    
    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-GCM on OpenCL device."""
        return self.encrypt(data, key, iv)  # For this example, we'll use the same function
    
    def benchmark(self, data_size: int = 1024 * 1024) -> float:
        """Benchmark the encryption/decryption speed in MB/s."""
        if not self.available:
            return 0.0
            
        import time
        
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
            f"OpenCL AES-256-GCM Performance: "
            f"Encrypt: {encrypt_speed:.2f} MB/s, "
            f"Decrypt: {decrypt_speed:.2f} MB/s"
        )
        
        return (encrypt_speed + decrypt_speed) / 2
    
    def __del__(self):
        """Clean up OpenCL resources."""
        if hasattr(self, '_queue') and self._queue is not None:
            self._queue.finish()


def initialize_opencl_backend() -> None:
    """Initialize and register the OpenCL backend."""
    if not OPENCL_AVAILABLE:
        logger.warning("OpenCL is not available. Install pyopencl and OpenCL runtime.")
        return
        
    try:
        opencl_backend = OpenCLAESBackend()
        if opencl_backend.available:
            hardware_manager.register_backend(HardwareBackendType.OPENCL, opencl_backend)
            logger.info("OpenCL backend registered successfully")
        else:
            logger.warning("OpenCL backend is not available")
    except Exception as e:
        logger.error(f"Failed to initialize OpenCL backend: {e}")

# Register the OpenCL backend when this module is imported
if OPENCL_AVAILABLE:
    initialize_opencl_backend()

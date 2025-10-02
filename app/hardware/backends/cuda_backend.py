"""
CUDA backend for hardware acceleration.

This module provides GPU acceleration using NVIDIA CUDA.
"""

import logging
import os
import sys
from typing import List, Optional, Tuple, Dict, Any, Union

import numpy as np
from numpy.fft import fft as np_fft, ifft as np_ifft

from ...core.config import settings
from ..acceleration import (
    HardwareBackend,
    HardwareContext,
    BackendType,
    DeviceType,
    DeviceInfo
)

logger = logging.getLogger(__name__)

try:
    import cupy as cp
    from cupy.cuda import Device as CUDADevice
    from cupy.cuda import runtime as cuda_runtime
    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False
    logger.warning("CuPy not installed, CUDA backend will not be available")

class CUDABuffer:
    """Wrapper for CUDA device memory."""
    
    def __init__(self, shape, dtype=np.float32, device_id=0):
        self.shape = shape
        self.dtype = np.dtype(dtype)
        self.device_id = device_id
        self.ptr = None
        self.size = int(np.prod(shape)) * self.dtype.itemsize
        self._allocated = False
        
        # Allocate memory
        self.allocate()
    
    def allocate(self):
        """Allocate device memory."""
        if self._allocated:
            return
            
        with CUDADevice(self.device_id):
            self.ptr = cp.cuda.alloc(self.size)
            self._allocated = True
    
    def free(self):
        """Free device memory."""
        if not self._allocated:
            return
            
        with CUDADevice(self.device_id):
            if self.ptr is not None:
                self.ptr.free()
                self.ptr = None
        self._allocated = False
    
    def to_numpy(self):
        """Copy data to host as a NumPy array."""
        if not self._allocated or self.ptr is None:
            raise RuntimeError("Buffer not allocated")
            
        with CUDADevice(self.device_id):
            arr = cp.ndarray(self.size // self.dtype.itemsize, 
                           dtype=self.dtype,
                           memptr=cp.cuda.MemoryPointer(self.ptr.mem.ptr, 0))
            return cp.asnumpy(arr.reshape(self.shape))
    
    def from_numpy(self, arr):
        """Copy data from a NumPy array to device memory."""
        if not self._allocated or self.ptr is None:
            self.allocate()
            
        with CUDADevice(self.device_id):
            arr_gpu = cp.asarray(arr, dtype=self.dtype)
            self.ptr.copy_from_device(
                arr_gpu.data.ptr,
                arr_gpu.nbytes
            )
    
    def __del__(self):
        self.free()

class CUDAContext(HardwareContext):
    """CUDA implementation of HardwareContext."""
    
    def __init__(self, backend: 'CUDABackend', device: DeviceInfo):
        if not CUDA_AVAILABLE:
            raise RuntimeError("CUDA is not available. Please install CuPy with CUDA support.")
            
        super().__init__(backend, device)
        self._stream = None
        self._device_id = device.properties.get('device_id', 0)
        self._cuda_device = None
        self._default_stream = None
    
    def _ensure_device(self):
        """Ensure we're on the correct CUDA device."""
        if self._cuda_device is None:
            self._cuda_device = CUDADevice(self._device_id)
        
        if CUDADevice().id != self._device_id:
            self._cuda_device.use()
    
    def _get_stream(self):
        """Get the current CUDA stream."""
        self._ensure_device()
        if self._stream is None:
            self._stream = cp.cuda.Stream(non_blocking=True)
        return self._stream
    
    def activate(self):
        """Activate this context."""
        self._ensure_device()
        self._default_stream = cp.cuda.get_current_stream()
        self._stream = cp.cuda.Stream(non_blocking=True)
        self._stream.use()
        self._active = True
    
    def deactivate(self):
        """Deactivate this context."""
        if self._default_stream is not None:
            self._default_stream.use()
        self._active = False
    
    def array(self, data, dtype=None):
        """Create an array in CUDA device memory."""
        self._ensure_device()
        return cp.array(data, dtype=dtype, copy=False)
    
    def to_numpy(self, array) -> np.ndarray:
        """Convert an array to a NumPy array."""
        return cp.asnumpy(array)
    
    def zeros(self, shape, dtype=np.float32):
        """Create a zero-initialized array in CUDA device memory."""
        self._ensure_device()
        return cp.zeros(shape, dtype=dtype)
    
    def ones(self, shape, dtype=np.float32):
        """Create a one-initialized array in CUDA device memory."""
        self._ensure_device()
        return cp.ones(shape, dtype=dtype)
    
    def empty(self, shape, dtype=np.float32):
        """Create an uninitialized array in CUDA device memory."""
        self._ensure_device()
        return cp.empty(shape, dtype=dtype)
    
    def matmul(self, a, b):
        """Matrix multiplication using CUDA."""
        return cp.matmul(a, b)
    
    def fft(self, a):
        """Fast Fourier Transform using CUDA."""
        return cp.fft.fft(a)
    
    def ifft(self, a):
        """Inverse Fast Fourier Transform using CUDA."""
        return cp.fft.ifft(a)
    
    def encrypt(self, data, key):
        """Encrypt data using CUDA-accelerated operations."""
        # This is a placeholder implementation
        # In a real implementation, this would use CUDA kernels for encryption
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # Simple XOR encryption for demonstration
        key_bytes = key * (len(data) // len(key) + 1)
        encrypted = bytes(a ^ b for a, b in zip(data, key_bytes))
        return encrypted
    
    def decrypt(self, data, key):
        """Decrypt data using CUDA-accelerated operations."""
        # Decryption is the same as encryption for XOR
        return self.encrypt(data, key)
    
    def synchronize(self):
        """Synchronize all operations in this context."""
        if self._stream is not None:
            self._stream.synchronize()
        cp.cuda.Stream.null.synchronize()

class CUDABackend(HardwareBackend):
    """CUDA implementation of HardwareBackend."""
    
    def __init__(self):
        self._devices = self._detect_devices()
    
    @property
    def backend_type(self) -> BackendType:
        return BackendType.CUDA
    
    @property
    def is_available(self) -> bool:
        if not CUDA_AVAILABLE:
            return False
            
        try:
            return cuda_runtime.getDeviceCount() > 0
        except:
            return False
    
    def _detect_devices(self) -> List[DeviceInfo]:
        """Detect available CUDA devices."""
        if not self.is_available:
            return []
            
        devices = []
        try:
            device_count = cuda_runtime.getDeviceCount()
            
            for i in range(device_count):
                cuda_runtime.setDevice(i)
                
                # Get device properties
                name = cuda_runtime.getDeviceProperties(i)['name'].decode('utf-8')
                total_mem = cuda_runtime.memGetInfo()[1]  # Total device memory in bytes
                
                # Get compute capability
                major = cuda_runtime.getDeviceProperties(i)['major']
                minor = cuda_runtime.getDeviceProperties(i)['minor']
                compute_capability = (major, minor)
                
                # Get additional properties
                properties = {
                    'device_id': i,
                    'compute_capability': f"{major}.{minor}",
                    'multiprocessor_count': cuda_runtime.getDeviceProperties(i).get('multi_processor_count', 0),
                    'clock_rate': cuda_runtime.getDeviceProperties(i).get('clock_rate', 0),
                    'memory_clock_rate': cuda_runtime.getDeviceProperties(i).get('memory_clock_rate', 0),
                    'total_memory': total_mem,
                    'cuda_driver_version': cuda_runtime.driverGetVersion(),
                    'cuda_runtime_version': cuda_runtime.getVersion()
                }
                
                device = DeviceInfo(
                    name=f"CUDA: {name}",
                    device_type=DeviceType.GPU,
                    backend=BackendType.CUDA,
                    memory=total_mem,
                    compute_capability=compute_capability,
                    is_available=True,
                    properties=properties
                )
                devices.append(device)
                
        except Exception as e:
            logger.error(f"Error detecting CUDA devices: {e}")
            return []
            
        return devices
    
    def get_devices(self) -> List[DeviceInfo]:
        return self._devices
    
    def get_preferred_device(self) -> Optional[DeviceInfo]:
        if not self._devices:
            return None
            
        # Try to get the current device
        try:
            current_device = cuda_runtime.getDevice()
            for device in self._devices:
                if device.properties.get('device_id') == current_device:
                    return device
        except:
            pass
            
        # Fall back to the first available device
        return self._devices[0]
    
    def create_context(self, device: Optional[DeviceInfo] = None) -> CUDAContext:
        if not self._devices:
            raise RuntimeError("No CUDA devices available")
            
        if device is None:
            device = self.get_preferred_device()
        
        if device not in self._devices:
            raise ValueError(f"Device {device.name} not found")
            
        return CUDAContext(self, device)

# Register the backend
Backend = CUDABackend if CUDA_AVAILABLE else None

"""
CPU backend for hardware acceleration.

This module provides a fallback implementation using NumPy and native Python
for when no other hardware acceleration is available.
"""

import logging
import os
import platform
import sys
from typing import List, Optional, Tuple, Dict, Any

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

class CPUContext(HardwareContext):
    """CPU implementation of HardwareContext."""
    
    def __init__(self, backend: 'CPUBackend', device: DeviceInfo):
        super().__init__(backend, device)
        self._active = False
        self._stream = None
    
    def activate(self):
        """Activate this context."""
        self._active = True
        # Set thread affinity if needed
        if hasattr(os, 'sched_setaffinity') and hasattr(os, 'sched_getaffinity'):
            try:
                # Save current affinity
                self._saved_affinity = os.sched_getaffinity(0)
                # Set to use all available CPUs
                os.sched_setaffinity(0, range(os.cpu_count()))
            except Exception as e:
                logger.warning(f"Failed to set CPU affinity: {e}")
    
    def deactivate(self):
        """Deactivate this context."""
        self._active = False
        # Restore thread affinity if it was changed
        if hasattr(self, '_saved_affinity'):
            try:
                os.sched_setaffinity(0, self._saved_affinity)
            except Exception as e:
                logger.warning(f"Failed to restore CPU affinity: {e}")
    
    def array(self, data, dtype=None):
        """Create an array in device memory."""
        return np.array(data, dtype=dtype, copy=False)
    
    def to_numpy(self, array) -> np.ndarray:
        """Convert an array to a NumPy array."""
        return np.asarray(array)
    
    def zeros(self, shape, dtype=np.float32):
        """Create a zero-initialized array in device memory."""
        return np.zeros(shape, dtype=dtype)
    
    def ones(self, shape, dtype=np.float32):
        """Create a one-initialized array in device memory."""
        return np.ones(shape, dtype=dtype)
    
    def empty(self, shape, dtype=np.float32):
        """Create an uninitialized array in device memory."""
        return np.empty(shape, dtype=dtype)
    
    def matmul(self, a, b):
        """Matrix multiplication."""
        return np.matmul(a, b)
    
    def fft(self, a):
        """Fast Fourier Transform."""
        return np_fft(a)
    
    def ifft(self, a):
        """Inverse Fast Fourier Transform."""
        return np_ifft(a)
    
    def encrypt(self, data, key):
        """Encrypt data using CPU-accelerated operations."""
        # This is a placeholder implementation
        # In a real implementation, this would use a proper encryption algorithm
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # Simple XOR encryption for demonstration
        key_bytes = key * (len(data) // len(key) + 1)
        encrypted = bytes(a ^ b for a, b in zip(data, key_bytes))
        return encrypted
    
    def decrypt(self, data, key):
        """Decrypt data using CPU-accelerated operations."""
        # Decryption is the same as encryption for XOR
        return self.encrypt(data, key)
    
    def synchronize(self):
        """Synchronize all operations in this context."""
        pass  # No need to synchronize for CPU

class CPUBackend(HardwareBackend):
    """CPU implementation of HardwareBackend."""
    
    def __init__(self):
        self._devices = self._detect_devices()
    
    @property
    def backend_type(self) -> BackendType:
        return BackendType.CPU
    
    @property
    def is_available(self) -> bool:
        return True  # CPU is always available
    
    def _detect_devices(self) -> List[DeviceInfo]:
        """Detect available CPU devices."""
        try:
            import psutil
            cpu_count = psutil.cpu_count(logical=False) or os.cpu_count() or 1
            total_memory = psutil.virtual_memory().total
        except ImportError:
            cpu_count = os.cpu_count() or 1
            total_memory = 1024 * 1024 * 1024  # Default to 1GB if psutil not available
        
        device = DeviceInfo(
            name=f"CPU ({platform.processor() or 'Unknown'}, {cpu_count} cores)",
            device_type=DeviceType.CPU,
            backend=BackendType.CPU,
            memory=total_memory,
            compute_capability=None,
            is_available=True,
            properties={
                'cpu_count': cpu_count,
                'architecture': platform.machine(),
                'system': platform.system(),
                'python_version': platform.python_version(),
                'numpy_version': np.__version__
            }
        )
        
        return [device]
    
    def get_devices(self) -> List[DeviceInfo]:
        return self._devices
    
    def get_preferred_device(self) -> Optional[DeviceInfo]:
        return self._devices[0] if self._devices else None
    
    def create_context(self, device: Optional[DeviceInfo] = None) -> CPUContext:
        if device is None:
            device = self.get_preferred_device()
        
        if device not in self._devices:
            raise ValueError(f"Device {device.name} not found")
        
        return CPUContext(self, device)

# Register the backend
Backend = CPUBackend

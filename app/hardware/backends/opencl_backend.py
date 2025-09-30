"""
OpenCL backend for hardware acceleration.

This module provides GPU acceleration using OpenCL, which works on both
NVIDIA and AMD GPUs, as well as CPUs with OpenCL support.
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
    import pyopencl as cl
    import pyopencl.array as cl_array
    from pyopencl.tools import get_gl_sharing_context_properties
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False
    logger.warning("PyOpenCL not installed, OpenCL backend will not be available")

class OpenCLContext(HardwareContext):
    """OpenCL implementation of HardwareContext."""
    
    def __init__(self, backend: 'OpenCLBackend', device: DeviceInfo):
        if not OPENCL_AVAILABLE:
            raise RuntimeError("OpenCL is not available. Please install PyOpenCL.")
            
        super().__init__(backend, device)
        self._context = None
        self._queue = None
        self._device_id = device.properties.get('device_id')
        self._platform_id = device.properties.get('platform_id')
        self._initialize_context()
    
    def _initialize_context(self):
        """Initialize the OpenCL context and command queue."""
        if self._context is not None:
            return
            
        try:
            # Get the platform and device
            platform = cl.get_platforms()[self._platform_id]
            device = platform.get_devices()[self._device_id]
            
            # Create context and command queue
            self._context = cl.Context([device])
            self._queue = cl.CommandQueue(
                self._context,
                properties=cl.command_queue_properties.PROFILING_ENABLE
            )
            
            # Store device info
            self._device = device
            
        except Exception as e:
            logger.error(f"Error initializing OpenCL context: {e}")
            raise
    
    def activate(self):
        """Activate this context."""
        self._initialize_context()
        self._active = True
    
    def deactivate(self):
        """Deactivate this context."""
        self._active = False
    
    def array(self, data, dtype=None):
        """Create an array in OpenCL device memory."""
        self.activate()
        return cl_array.to_device(self._queue, data, dtype=dtype)
    
    def to_numpy(self, array) -> np.ndarray:
        """Convert an array to a NumPy array."""
        if hasattr(array, 'get'):
            return array.get()
        return np.asarray(array)
    
    def zeros(self, shape, dtype=np.float32):
        """Create a zero-initialized array in OpenCL device memory."""
        self.activate()
        return cl_array.zeros(self._queue, shape, dtype)
    
    def ones(self, shape, dtype=np.float32):
        """Create a one-initialized array in OpenCL device memory."""
        self.activate()
        return cl_array.ones(self._queue, shape, dtype)
    
    def empty(self, shape, dtype=np.float32):
        """Create an uninitialized array in OpenCL device memory."""
        self.activate()
        return cl_array.empty(self._queue, shape, dtype)
    
    def matmul(self, a, b):
        """Matrix multiplication using OpenCL."""
        self.activate()
        return cl_array.dot(a, b)
    
    def fft(self, a):
        """Fast Fourier Transform using OpenCL."""
        self.activate()
        # This is a simple implementation using numpy for demonstration
        # In a real implementation, you would use clFFT or another OpenCL FFT library
        fft_result = np_fft(a.get() if hasattr(a, 'get') else a)
        return cl_array.to_device(self._queue, fft_result)
    
    def ifft(self, a):
        """Inverse Fast Fourier Transform using OpenCL."""
        self.activate()
        # This is a simple implementation using numpy for demonstration
        ifft_result = np_ifft(a.get() if hasattr(a, 'get') else a)
        return cl_array.to_device(self._queue, ifft_result)
    
    def encrypt(self, data, key):
        """Encrypt data using OpenCL-accelerated operations."""
        # This is a placeholder implementation
        # In a real implementation, this would use OpenCL kernels for encryption
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # Simple XOR encryption for demonstration
        key_bytes = key * (len(data) // len(key) + 1)
        encrypted = bytes(a ^ b for a, b in zip(data, key_bytes))
        return encrypted
    
    def decrypt(self, data, key):
        """Decrypt data using OpenCL-accelerated operations."""
        # Decryption is the same as encryption for XOR
        return self.encrypt(data, key)
    
    def synchronize(self):
        """Synchronize all operations in this context."""
        if self._queue is not None:
            self._queue.finish()
    
    def __del__(self):
        """Clean up resources."""
        if hasattr(self, '_queue') and self._queue is not None:
            self._queue.finish()
        if hasattr(self, '_context') and self._context is not None:
            self._context = None

class OpenCLBackend(HardwareBackend):
    """OpenCL implementation of HardwareBackend."""
    
    def __init__(self):
        self._devices = self._detect_devices()
    
    @property
    def backend_type(self) -> BackendType:
        return BackendType.OPENCL
    
    @property
    def is_available(self) -> bool:
        if not OPENCL_AVAILABLE:
            return False
            
        try:
            return len(cl.get_platforms()) > 0
        except:
            return False
    
    def _detect_devices(self) -> List[DeviceInfo]:
        """Detect available OpenCL devices."""
        if not self.is_available:
            return []
            
        devices = []
        try:
            platforms = cl.get_platforms()
            
            for platform_id, platform in enumerate(platforms):
                platform_name = platform.name.strip()
                platform_vendor = platform.vendor.strip()
                
                for device_id, device in enumerate(platform.get_devices()):
                    # Determine device type
                    if device.type & cl.device_type.GPU:
                        device_type = DeviceType.GPU
                    elif device.type & cl.device_type.CPU:
                        device_type = DeviceType.CPU
                    elif device.type & cl.device_type.ACCELERATOR:
                        device_type = DeviceType.OTHER
                    else:
                        device_type = DeviceType.OTHER
                    
                    # Get device properties
                    device_name = f"{platform_name} - {device.name.strip()}"
                    total_mem = device.global_mem_size
                    
                    # Get compute units and clock frequency
                    compute_units = device.max_compute_units
                    clock_freq = device.max_clock_frequency
                    
                    # Get OpenCL version
                    version = device.version.strip().split()[-1]
                    
                    # Get device extensions
                    extensions = device.extensions.strip().split()
                    
                    properties = {
                        'platform_id': platform_id,
                        'device_id': device_id,
                        'platform_name': platform_name,
                        'platform_vendor': platform_vendor,
                        'compute_units': compute_units,
                        'clock_frequency': clock_freq,
                        'opencl_version': version,
                        'extensions': extensions,
                        'address_bits': device.address_bits,
                        'global_mem_size': device.global_mem_size,
                        'local_mem_size': device.local_mem_size,
                        'max_mem_alloc_size': device.max_mem_alloc_size,
                        'max_work_group_size': device.max_work_group_size,
                        'max_work_item_sizes': device.max_work_item_sizes,
                        'max_work_item_dimensions': device.max_work_item_dimensions,
                        'preferred_vector_width_float': device.preferred_vector_width_float,
                        'native_vector_width_float': device.native_vector_width_float,
                        'double_fp_config': getattr(device, 'double_fp_config', 0),
                        'single_fp_config': getattr(device, 'single_fp_config', 0),
                        'host_unified_memory': getattr(device, 'host_unified_memory', False),
                        'compiler_available': device.compiler_available,
                        'linker_available': getattr(device, 'linker_available', False),
                        'error_correction_support': device.error_correction_support,
                        'profiling_timer_resolution': device.profiling_timer_resolution,
                        'endian_little': device.endian_little,
                        'available': device.available,
                        'execution_capabilities': device.execution_capabilities,
                        'vendor_id': device.vendor_id,
                        'max_constant_args': device.max_constant_args,
                        'max_constant_buffer_size': device.max_constant_buffer_size,
                        'max_parameter_size': device.max_parameter_size,
                        'profiling_timer_resolution': device.profiling_timer_resolution,
                        'global_mem_cache_type': device.global_mem_cache_type,
                        'global_mem_cacheline_size': device.global_mem_cacheline_size,
                        'global_mem_cache_size': device.global_mem_cache_size,
                        'image_support': device.image_support,
                        'image2d_max_width': device.image2d_max_width,
                        'image2d_max_height': device.image2d_max_height,
                        'image3d_max_width': device.image3d_max_width,
                        'image3d_max_height': device.image3d_max_height,
                        'image3d_max_depth': device.image3d_max_depth,
                        'image_max_buffer_size': getattr(device, 'image_max_buffer_size', 0),
                        'image_max_array_size': getattr(device, 'image_max_array_size', 0),
                    }
                    
                    device_info = DeviceInfo(
                        name=device_name,
                        device_type=device_type,
                        backend=BackendType.OPENCL,
                        memory=total_mem,
                        compute_capability=None,  # Not applicable for OpenCL
                        is_available=device.available,
                        properties=properties
                    )
                    
                    devices.append(device_info)
                    
        except Exception as e:
            logger.error(f"Error detecting OpenCL devices: {e}")
            return []
            
        return devices
    
    def get_devices(self) -> List[DeviceInfo]:
        return self._devices
    
    def get_preferred_device(self) -> Optional[DeviceInfo]:
        if not self._devices:
            return None
            
        # Try to find a GPU first
        for device in self._devices:
            if device.device_type == DeviceType.GPU and device.is_available:
                return device
                
        # Fall back to the first available device
        for device in self._devices:
            if device.is_available:
                return device
                
        return self._devices[0] if self._devices else None
    
    def create_context(self, device: Optional[DeviceInfo] = None) -> OpenCLContext:
        if not self._devices:
            raise RuntimeError("No OpenCL devices available")
            
        if device is None:
            device = self.get_preferred_device()
        
        if device not in self._devices:
            raise ValueError(f"Device {device.name} not found")
            
        return OpenCLContext(self, device)

# Register the backend
Backend = OpenCLBackend if OPENCL_AVAILABLE else None

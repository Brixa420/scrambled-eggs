"""
Hardware acceleration module for Scrambled Eggs.

This module provides a unified interface for hardware-accelerated operations,
supporting multiple backends like CUDA, OpenCL, and Vulkan.
"""

import importlib
import logging
import os
import platform
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Type, TypeVar, Union, Any

import numpy as np

logger = logging.getLogger(__name__)

# Type variable for generic operations
T = TypeVar('T')

class BackendType(Enum):
    """Supported hardware acceleration backends."""
    AUTO = auto()
    CUDA = auto()
    OPENCL = auto()
    VULKAN = auto()
    METAL = auto()
    DIRECTML = auto()
    CPU = auto()

class DeviceType(Enum):
    """Types of hardware devices."""
    CPU = auto()
    GPU = auto()
    TPU = auto()
    VPU = auto()
    OTHER = auto()

@dataclass
class DeviceInfo:
    """Information about a hardware device."""
    name: str
    device_type: DeviceType
    backend: BackendType
    memory: int  # in bytes
    compute_capability: Optional[Tuple[int, int]] = None
    is_available: bool = True
    properties: Dict[str, Any] = None

    def __post_init__(self):
        if self.properties is None:
            self.properties = {}

class HardwareBackend(ABC):
    """Abstract base class for hardware acceleration backends."""
    
    @property
    @abstractmethod
    def backend_type(self) -> BackendType:
        """Return the type of this backend."""
        pass
    
    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available on the current system."""
        pass
    
    @abstractmethod
    def get_devices(self) -> List[DeviceInfo]:
        """Get a list of available devices for this backend."""
        pass
    
    @abstractmethod
    def get_preferred_device(self) -> Optional[DeviceInfo]:
        """Get the preferred device for this backend."""
        pass
    
    @abstractmethod
    def create_context(self, device: Optional[DeviceInfo] = None) -> 'HardwareContext':
        """Create a new hardware context."""
        pass

class HardwareContext(ABC):
    """Abstract base class for hardware acceleration contexts."""
    
    def __init__(self, backend: HardwareBackend, device: DeviceInfo):
        self.backend = backend
        self.device = device
        self._active = False
    
    def __enter__(self):
        self.activate()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.deactivate()
    
    @abstractmethod
    def activate(self):
        """Activate this context."""
        self._active = True
    
    @abstractmethod
    def deactivate(self):
        """Deactivate this context."""
        self._active = False
    
    @property
    def is_active(self) -> bool:
        """Check if this context is currently active."""
        return self._active
    
    @abstractmethod
    def array(self, data, dtype=None):
        """Create an array in device memory."""
        pass
    
    @abstractmethod
    def to_numpy(self, array) -> np.ndarray:
        """Convert an array to a NumPy array."""
        pass
    
    @abstractmethod
    def zeros(self, shape, dtype=np.float32):
        """Create a zero-initialized array in device memory."""
        pass
    
    @abstractmethod
    def matmul(self, a, b):
        """Matrix multiplication."""
        pass
    
    @abstractmethod
    def fft(self, a):
        """Fast Fourier Transform."""
        pass
    
    @abstractmethod
    def encrypt(self, data, key):
        """Encrypt data using hardware acceleration."""
        pass
    
    @abstractmethod
    def decrypt(self, data, key):
        """Decrypt data using hardware acceleration."""
        pass

class HardwareAccelerator:
    """Main class for hardware acceleration."""
    
    _instance = None
    _backends: Dict[BackendType, Type[HardwareBackend]] = {}
    _preferred_backend: Optional[BackendType] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize the hardware accelerator."""
        # Try to import available backends
        self._import_backends()
        
        # Set default preferred backend
        self._detect_preferred_backend()
    
    def _import_backends(self):
        """Import all available backends."""
        backend_modules = {
            BackendType.CUDA: 'app.hardware.backends.cuda_backend',
            BackendType.OPENCL: 'app.hardware.backends.opencl_backend',
            BackendType.VULKAN: 'app.hardware.backends.vulkan_backend',
            BackendType.METAL: 'app.hardware.backends.metal_backend',
            BackendType.DIRECTML: 'app.hardware.backends.directml_backend',
            BackendType.CPU: 'app.hardware.backends.cpu_backend',
        }
        
        for backend_type, module_name in backend_modules.items():
            try:
                module = importlib.import_module(module_name)
                self._backends[backend_type] = module.Backend
                logger.debug(f"Loaded {backend_type.name} backend")
            except (ImportError, AttributeError) as e:
                logger.debug(f"Could not load {backend_type.name} backend: {e}")
    
    def _detect_preferred_backend(self):
        """Detect the preferred backend based on available hardware."""
        # Check environment variable for preferred backend
        backend_env = os.environ.get('SCRAMBLED_EGGS_HW_BACKEND', '').upper()
        if backend_env:
            try:
                self._preferred_backend = BackendType[backend_env]
                logger.info(f"Using preferred backend from environment: {self._preferred_backend}")
                return
            except KeyError:
                logger.warning(f"Unknown backend in environment: {backend_env}")
        
        # Auto-detect best available backend
        for backend_type in [
            BackendType.CUDA,
            BackendType.METAL if platform.system() == 'Darwin' else None,
            BackendType.DIRECTML if platform.system() == 'Windows' else None,
            BackendType.VULKAN,
            BackendType.OPENCL,
            BackendType.CPU
        ]:
            if backend_type and backend_type in self._backends and self._backends[backend_type]().is_available:
                self._preferred_backend = backend_type
                logger.info(f"Auto-detected backend: {backend_type.name}")
                return
        
        # Fall back to CPU
        self._preferred_backend = BackendType.CPU
        logger.warning("No hardware acceleration backends available, falling back to CPU")
    
    def get_available_backends(self) -> List[BackendType]:
        """Get a list of available backends."""
        return [
            backend_type for backend_type, backend_cls in self._backends.items()
            if backend_cls().is_available
        ]
    
    def get_preferred_backend(self) -> Optional[BackendType]:
        """Get the preferred backend."""
        return self._preferred_backend
    
    def set_preferred_backend(self, backend_type: Union[BackendType, str]):
        """Set the preferred backend."""
        if isinstance(backend_type, str):
            try:
                backend_type = BackendType[backend_type.upper()]
            except KeyError as e:
                raise ValueError(f"Unknown backend: {backend_type}") from e
        
        if backend_type not in self._backends or not self._backends[backend_type]().is_available:
            raise ValueError(f"Backend {backend_type.name} is not available")
        
        self._preferred_backend = backend_type
        logger.info(f"Set preferred backend to {backend_type.name}")
    
    def get_backend_info(self, backend_type: Optional[BackendType] = None) -> Dict:
        """Get information about a backend."""
        if backend_type is None:
            backend_type = self._preferred_backend
        
        if backend_type not in self._backends:
            return {
                'available': False,
                'error': f"Backend {backend_type.name} not found"
            }
        
        backend = self._backends[backend_type]()
        devices = backend.get_devices()
        
        return {
            'name': backend_type.name,
            'available': backend.is_available,
            'devices': [{
                'name': device.name,
                'type': device.device_type.name,
                'memory': device.memory,
                'compute_capability': device.compute_capability,
                'properties': device.properties
            } for device in devices]
        }
    
    def create_context(self, backend_type: Optional[Union[BackendType, str]] = None) -> HardwareContext:
        """Create a new hardware context."""
        if backend_type is None:
            backend_type = self._preferred_backend
        elif isinstance(backend_type, str):
            backend_type = BackendType[backend_type.upper()]
        
        if backend_type not in self._backends:
            raise ValueError(f"Backend {backend_type.name} not found")
        
        backend = self._backends[backend_type]()
        if not backend.is_available:
            raise RuntimeError(f"Backend {backend_type.name} is not available")
        
        device = backend.get_preferred_device()
        if not device:
            raise RuntimeError(f"No devices available for backend {backend_type.name}")
        
        return backend.create_context(device)

# Global instance
accelerator = HardwareAccelerator()

# Helper functions
def is_available() -> bool:
    """Check if hardware acceleration is available."""
    return len(accelerator.get_available_backends()) > 0

def get_available_backends() -> List[BackendType]:
    """Get a list of available backends."""
    return accelerator.get_available_backends()

def get_preferred_backend() -> Optional[BackendType]:
    """Get the preferred backend."""
    return accelerator.get_preferred_backend()

def set_preferred_backend(backend_type: Union[BackendType, str]):
    """Set the preferred backend."""
    return accelerator.set_preferred_backend(backend_type)

def get_backend_info(backend_type: Optional[BackendType] = None) -> Dict:
    """Get information about a backend."""
    return accelerator.get_backend_info(backend_type)

# Initialize on import
if is_available():
    logger.info(f"Hardware acceleration available: {', '.join(b.name for b in get_available_backends())}")
    logger.info(f"Using backend: {get_preferred_backend().name if get_preferred_backend() else 'None'}")
else:
    logger.warning("No hardware acceleration backends available")

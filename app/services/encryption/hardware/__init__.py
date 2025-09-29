"""
Hardware Acceleration Module

This module provides hardware-accelerated cryptographic operations.
"""

from typing import Optional, Type, Dict, Any
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)

class HardwareBackendType(Enum):
    """Enumeration of supported hardware backends."""
    AUTO = auto()
    CPU = auto()
    CUDA = auto()
    OPENCL = auto()
    INTEL_AESNI = auto()
    
    @classmethod
    def from_string(cls, name: str) -> 'HardwareBackendType':
        """Convert string to HardwareBackendType."""
        try:
            return cls[name.upper()]
        except KeyError:
            raise ValueError(f"Unknown hardware backend: {name}")


class HardwareBackend:
    """Base class for hardware acceleration backends."""
    
    def __init__(self):
        self.initialized = False
        self.available = False
        self.performance_factor = 1.0  # Multiplier for expected performance
        
    def initialize(self) -> bool:
        """Initialize the hardware backend."""
        self.initialized = True
        return self.available
        
    def is_available(self) -> bool:
        """Check if the backend is available."""
        return self.available and self.initialized
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt data using hardware acceleration."""
        raise NotImplementedError("Encryption not implemented for this backend")
    
    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using hardware acceleration."""
        raise NotImplementedError("Decryption not implemented for this backend")
    
    def benchmark(self, data_size: int = 1024 * 1024) -> float:
        """Benchmark the backend's performance."""
        raise NotImplementedError("Benchmark not implemented for this backend")


class HardwareManager:
    """Manages hardware acceleration backends."""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._backends: Dict[HardwareBackendType, HardwareBackend] = {}
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self._backends = {}
            self._initialized = True
    
    def register_backend(self, backend_type: HardwareBackendType, backend: HardwareBackend) -> None:
        """Register a hardware backend."""
        self._backends[backend_type] = backend
    
    def get_backend(self, backend_type: HardwareBackendType = HardwareBackendType.AUTO) -> Optional[HardwareBackend]:
        """Get the best available backend."""
        if backend_type == HardwareBackendType.AUTO:
            # Try to find the best available backend
            for t in [HardwareBackendType.INTEL_AESNI, 
                     HardwareBackendType.CUDA, 
                     HardwareBackendType.OPENCL, 
                     HardwareBackendType.CPU]:
                if t in self._backends and self._backends[t].is_available():
                    return self._backends[t]
            return None
        
        return self._backends.get(backend_type)
    
    def get_available_backends(self) -> Dict[HardwareBackendType, HardwareBackend]:
        """Get all available backends."""
        return {t: b for t, b in self._backends.items() if b.is_available()}
    
    def initialize(self) -> None:
        """Initialize all registered backends."""
        for backend in self._backends.values():
            try:
                if backend.initialize():
                    logger.info(f"Initialized {backend.__class__.__name__} backend")
            except Exception as e:
                logger.warning(f"Failed to initialize {backend.__class__.__name__}: {str(e)}")


# Create a global hardware manager instance
hardware_manager = HardwareManager()


def get_hardware_backend(backend_type: HardwareBackendType = HardwareBackendType.AUTO) -> Optional[HardwareBackend]:
    """Helper function to get a hardware backend."""
    return hardware_manager.get_backend(backend_type)


def register_backend(backend_type: HardwareBackendType, backend: HardwareBackend) -> None:
    """Helper function to register a hardware backend."""
    hardware_manager.register_backend(backend_type, backend)


def initialize_hardware() -> None:
    """Initialize all hardware backends."""
    hardware_manager.initialize()

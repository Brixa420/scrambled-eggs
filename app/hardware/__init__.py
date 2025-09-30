"""
Hardware acceleration module for Scrambled Eggs.

This module provides hardware-accelerated operations for performance-critical tasks.
"""

from .acceleration import (
    is_available,
    get_available_backends,
    get_preferred_backend,
    set_preferred_backend,
    get_backend_info,
    HardwareAccelerator,
    BackendType,
    DeviceType
)

__all__ = [
    'is_available',
    'get_available_backends',
    'get_preferred_backend',
    'set_preferred_backend',
    'get_backend_info',
    'HardwareAccelerator',
    'BackendType',
    'DeviceType'
]

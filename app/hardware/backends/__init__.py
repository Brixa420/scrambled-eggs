"""
Hardware acceleration backends for Scrambled Eggs.

This package contains implementations of hardware acceleration backends
for different platforms and hardware.
"""

from typing import Dict, Type
from ..acceleration import HardwareBackend, HardwareContext, BackendType

# This will be populated by the individual backend modules
backends: Dict[BackendType, Type[HardwareBackend]] = {}

__all__ = ['backends']

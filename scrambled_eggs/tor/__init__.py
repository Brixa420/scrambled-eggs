"""
Tor Integration Module

This module provides functionality to integrate with the Tor network for
anonymous communication in the Scrambled Eggs P2P messaging application.
"""

__version__ = "1.0.0"

from .exceptions import (
    TorConfigurationError,
    TorConnectionError,
    TorError,
    TorServiceError,
    TorStartupError,
)
from .onion_service import OnionService, OnionServiceConfig

# Import key components to make them available at the package level
from .tor_manager import TorManager, TorState

__all__ = [
    "TorManager",
    "TorState",
    "OnionService",
    "OnionServiceConfig",
    "TorError",
    "TorConnectionError",
    "TorServiceError",
    "TorStartupError",
    "TorConfigurationError",
]

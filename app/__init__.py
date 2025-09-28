"""
Scrambled Eggs - Secure P2P Messaging

A secure, end-to-end encrypted P2P messaging and file sharing application
with self-modifying encryption that evolves when security is compromised.
"""

__version__ = "0.1.0"

# Core components
from .core.crypto import CryptoEngine
from .core.security import SecurityManager, SecurityPolicy

# Network components
from .network.p2p import P2PManager, ConnectionState

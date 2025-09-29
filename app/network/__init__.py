"""
Network Module

This module handles all network-related functionality including peer-to-peer communication.
"""

# Import key components for easier access
from .p2p import ConnectionState, P2PManager, Peer

__all__ = ["P2PManager", "ConnectionState", "Peer"]

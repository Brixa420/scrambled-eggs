"""
Network Module

This module handles all network-related functionality including peer-to-peer communication.
"""

# Import key components for easier access
from .p2p import P2PManager, ConnectionState, Peer

__all__ = ['P2PManager', 'ConnectionState', 'Peer']

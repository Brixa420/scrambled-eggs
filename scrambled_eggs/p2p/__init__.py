"""
P2P Module for Scrambled Eggs.

This package contains the peer-to-peer networking functionality for the
Scrambled Eggs application, including WebRTC connection management,
signaling, and data channel handling.
"""

__version__ = "1.1.0"

# Import key components to make them available at the package level
from .webrtc_manager import WebRTCManager, ConnectionState, ConnectionEvent
from .signaling import SignalingClient, SignalingMessage
from .data_channel import DataChannel, DataChannelEvent
from .exceptions import (
    P2PError, ConnectionError, SignalingError, 
    DataChannelError, PeerConnectionError
)

__all__ = [
    'WebRTCManager',
    'SignalingClient',
    'DataChannel',
    'ConnectionState',
    'ConnectionEvent',
    'DataChannelEvent',
    'SignalingMessage',
    'P2PError',
    'ConnectionError',
    'SignalingError',
    'DataChannelError',
    'PeerConnectionError'
]

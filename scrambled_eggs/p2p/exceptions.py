"""
P2P Exceptions
--------------
Custom exceptions for the P2P module.
"""

class P2PError(Exception):
    """Base class for all P2P-related exceptions."""
    pass


class ConnectionError(P2PError):
    """Raised when there's an error establishing or maintaining a connection."""
    pass


class SignalingError(P2PError):
    """Raised when there's an error with the signaling server."""
    pass


class DataChannelError(P2PError):
    """Raised when there's an error with a data channel."""
    pass


class PeerConnectionError(P2PError):
    """Raised when there's an error with a peer connection."""
    pass


class HandshakeError(P2PError):
    """Raised when there's an error during the handshake process."""
    pass


class AuthenticationError(P2PError):
    """Raised when authentication fails."""
    pass


class TimeoutError(P2PError):
    """Raised when an operation times out."""
    pass

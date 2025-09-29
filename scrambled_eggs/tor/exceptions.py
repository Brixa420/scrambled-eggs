"""
Tor Integration Exceptions

This module defines custom exceptions for the Tor integration in Scrambled Eggs.
"""


class TorError(Exception):
    """Base exception for all Tor-related errors."""

    pass


class TorConnectionError(TorError):
    """Raised when there's an error connecting to the Tor network."""

    pass


class TorServiceError(TorError):
    """Raised when there's an error with a Tor hidden service."""

    pass


class TorStartupError(TorError):
    """Raised when there's an error starting the Tor process."""

    pass


class TorConfigurationError(TorError):
    """Raised when there's an error in the Tor configuration."""

    pass


class TorAuthenticationError(TorError):
    """Raised when there's an error authenticating with the Tor control port."""

    pass


class TorTimeoutError(TorError):
    """Raised when a Tor operation times out."""

    pass


class TorCircuitError(TorError):
    """Raised when there's an error with a Tor circuit."""

    pass


class TorStreamError(TorError):
    """Raised when there's an error with a Tor stream."""

    pass


class TorDescriptorError(TorError):
    """Raised when there's an error with a hidden service descriptor."""

    pass


class TorKeyError(TorError):
    """Raised when there's an error with Tor keys."""

    pass


class TorProtocolError(TorError):
    """Raised when there's a protocol-level error with Tor."""

    pass

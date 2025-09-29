"""
Custom exceptions for the Scrambled Eggs encryption system.
"""


class ScrambledEggsError(Exception):
    """Base exception for all Scrambled Eggs errors."""

    pass


class EncryptionError(ScrambledEggsError):
    """Raised when encryption fails."""

    pass


class DecryptionError(ScrambledEggsError):
    """Raised when decryption fails."""

    pass


class BreachDetected(ScrambledEggsError):
    """Raised when a potential security breach is detected."""

    pass


class KeyDerivationError(ScrambledEggsError):
    """Raised when there's an error deriving encryption keys."""

    pass


class FileOperationError(ScrambledEggsError):
    """Raised for file operation related errors."""

    pass


class AuthenticationError(ScrambledEggsError):
    """Raised when authentication fails."""

    pass


class ConnectionError(ScrambledEggsError):
    """Raised when a connection error occurs."""

    pass

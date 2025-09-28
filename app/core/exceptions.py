"""
Custom exceptions for the Scrambled Eggs encryption system.
"""
from typing import Optional, Dict, Any


class EncryptionError(Exception):
    """Base exception for encryption-related errors."""
    
    def __init__(
        self,
        message: str = "An encryption error occurred",
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the exception.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
            details: Additional error details
        """
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the exception to a dictionary for serialization."""
        return {
            'error': self.__class__.__name__,
            'message': str(self.message),
            'code': self.error_code,
            'details': self.details
        }


class KeyManagementError(EncryptionError):
    """Raised when there's an error in key management operations."""
    
    def __init__(
        self,
        message: str = "Key management error",
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the exception."""
        super().__init__(
            message=message,
            error_code=error_code or "KEY_MANAGEMENT_ERROR",
            details=details
        )


class KeyNotFoundError(KeyManagementError):
    """Raised when a requested key is not found."""
    
    def __init__(self, key_id: str, details: Optional[Dict[str, Any]] = None):
        """Initialize the exception."""
        super().__init__(
            message=f"Encryption key not found: {key_id}",
            error_code="KEY_NOT_FOUND",
            details={"key_id": key_id, **(details or {})}
        )


class KeyRotationError(KeyManagementError):
    """Raised when there's an error during key rotation."""
    
    def __init__(
        self,
        key_id: str,
        message: str = "Key rotation failed",
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the exception."""
        super().__init__(
            message=f"Failed to rotate key {key_id}: {message}",
            error_code="KEY_ROTATION_FAILED",
            details={"key_id": key_id, **(details or {})}
        )


class EncryptionOperationError(EncryptionError):
    """Raised when an encryption or decryption operation fails."""
    
    def __init__(
        self,
        operation: str,
        message: str = "Encryption operation failed",
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the exception."""
        super().__init__(
            message=f"{operation} failed: {message}",
            error_code=f"{operation.upper()}_FAILED",
            details={"operation": operation, **(details or {})}
        )


class DecryptionError(EncryptionOperationError):
    """Raised specifically for decryption failures."""
    
    def __init__(
        self,
        message: str = "Decryption failed",
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the exception."""
        super().__init__(
            operation="decryption",
            message=message,
            details=details
        )


class IntegrityCheckError(DecryptionError):
    """Raised when data integrity check fails during decryption."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        """Initialize the exception."""
        super().__init__(
            message="Data integrity check failed",
            details={"cause": "Integrity check failed - data may have been tampered with", **(details or {})}
        )


class KeyAccessDeniedError(KeyManagementError):
    """Raised when access to a key is denied."""
    
    def __init__(self, key_id: str, reason: str = "Access denied"):
        """Initialize the exception."""
        super().__init__(
            message=f"Access to key {key_id} denied: {reason}",
            error_code="KEY_ACCESS_DENIED",
            details={"key_id": key_id, "reason": reason}
        )


class KeyExpiredError(KeyManagementError):
    """Raised when a key has expired."""
    
    def __init__(self, key_id: str, expiry_date: str):
        """Initialize the exception."""
        super().__init__(
            message=f"Key {key_id} expired on {expiry_date}",
            error_code="KEY_EXPIRED",
            details={"key_id": key_id, "expiry_date": expiry_date}
        )


class ConfigurationError(EncryptionError):
    """Raised when there's a configuration error."""
    
    def __init__(self, setting: str, message: str = "Invalid configuration"):
        """Initialize the exception."""
        super().__init__(
            message=f"{message}: {setting}",
            error_code="INVALID_CONFIGURATION",
            details={"setting": setting}
        )

"""
Exceptions for the content moderation system.
"""

class ModerationError(Exception):
    """Base exception for all moderation-related errors."""
    pass

class PolicyViolationError(ModerationError):
    """Raised when content violates moderation policies."""
    def __init__(self, message: str, violations: list = None, content_id: str = None):
        self.message = message
        self.violations = violations or []
        self.content_id = content_id
        super().__init__(self.message)

class ModelLoadingError(ModerationError):
    """Raised when there's an error loading a moderation model."""
    def __init__(self, model_name: str, reason: str):
        self.model_name = model_name
        self.reason = reason
        super().__init__(f"Failed to load model '{model_name}': {reason}")

class ContentProcessingError(ModerationError):
    """Raised when there's an error processing content."""
    def __init__(self, content_type: str, reason: str):
        self.content_type = content_type
        self.reason = reason
        super().__init__(f"Error processing {content_type}: {reason}")

class ConfigurationError(ModerationError):
    """Raised when there's a configuration error."""
    def __init__(self, setting: str, reason: str):
        self.setting = setting
        self.reason = reason
        super().__init__(f"Configuration error for '{setting}': {reason}")

class RateLimitExceeded(ModerationError):
    """Raised when API rate limits are exceeded."""
    def __init__(self, service: str, retry_after: int = None):
        self.service = service
        self.retry_after = retry_after
        message = f"Rate limit exceeded for {service}"
        if retry_after:
            message += f". Please try again in {retry_after} seconds"
        super().__init__(message)

class UnsupportedContentType(ModerationError):
    """Raised when an unsupported content type is provided."""
    def __init__(self, content_type: str, supported_types: list = None):
        self.content_type = content_type
        self.supported_types = supported_types or []
        message = f"Unsupported content type: {content_type}"
        if supported_types:
            message += f". Supported types: {', '.join(supported_types)}"
        super().__init__(message)

class ModelInferenceError(ModerationError):
    """Raised when there's an error during model inference."""
    def __init__(self, model_name: str, reason: str):
        self.model_name = model_name
        self.reason = reason
        super().__init__(f"Error in model '{model_name}' inference: {reason}")

class ContentTooLarge(ModerationError):
    """Raised when the content size exceeds allowed limits."""
    def __init__(self, content_type: str, size: int, max_size: int):
        self.content_type = content_type
        self.size = size
        self.max_size = max_size
        super().__init__(
            f"{content_type} size {size} exceeds maximum allowed size of {max_size} bytes"
        )

class AuthenticationError(ModerationError):
    """Raised when there's an authentication or authorization error."""
    def __init__(self, service: str, reason: str = "Authentication failed"):
        self.service = service
        self.reason = reason
        super().__init__(f"{service} authentication error: {reason}")

class DependencyError(ModerationError):
    """Raised when there's an error with a required dependency."""
    def __init__(self, dependency: str, reason: str):
        self.dependency = dependency
        self.reason = reason
        super().__init__(f"Dependency error for '{dependency}': {reason}")

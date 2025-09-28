"""
Encryption configuration for Scrambled Eggs.

This module provides configuration settings for the Scrambled Eggs encryption system,
including key rotation schedules, performance tuning, and monitoring options.
"""
import os
from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from pathlib import Path
# Import removed to prevent circular import - using string reference instead

class EncryptionLayer(str, Enum):
    """Supported encryption layers."""
    SCRAMBLED_EGGS = "scrambled_eggs"
    AES_256_GCM = "aes_256_gcm"

class KeyRotationSchedule(str, Enum):
    """Schedule for automatic key rotation."""
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    BIANNUALLY = "biannually"
    ANNUALLY = "annually"

@dataclass
class ScrambledEggsConfig:
    """Scrambled Eggs specific configuration."""
    # Key derivation parameters
    PBKDF2_ITERATIONS: int = 600000  # NIST recommends at least 600,000 for PBKDF2
    SCRYPT_N: int = 2**20  # CPU/memory cost parameter (higher = more secure but slower)
    SCRYPT_R: int = 8      # Block size parameter
    SCRYPT_P: int = 1      # Parallelization parameter
    
    # Encryption parameters
    SALT_SIZE: int = 32    # Size of salt in bytes
    KEY_SIZE: int = 32     # 256-bit keys
    IV_SIZE: int = 12      # 96-bit IV for GCM
    AUTH_TAG_SIZE: int = 16  # 128-bit authentication tag
    
    # Performance tuning
    CHUNK_SIZE: int = 64 * 1024  # 64KB chunks for file operations
    
    # Key derivation cache (in-memory)
    KEY_CACHE_SIZE: int = 100  # Number of derived keys to cache
    
    # Security parameters
    MIN_PASSWORD_LENGTH: int = 12
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_DURATION: int = 300  # seconds

@dataclass
class EncryptionConfig:
    """Configuration for encryption settings."""
    # Default encryption layer
    DEFAULT_ENCRYPTION_LAYER: EncryptionLayer = EncryptionLayer.SCRAMBLED_EGGS
    
    # Key management
    KEY_ROTATION_SCHEDULE: KeyRotationSchedule = KeyRotationSchedule.QUARTERLY
    KEY_HISTORY_SIZE: int = 3  # Number of previous keys to keep
    
    # Key storage (override in production with secure storage)
    KEY_STORAGE_PATH: str = os.path.join('data', 'keys')
    
    # Monitoring and logging
    ENABLE_METRICS: bool = True
    LOG_ENCRYPTION_OPS: bool = True
    LOG_LEVEL: str = 'INFO'
    
    # Migration settings
    MIGRATION_BATCH_SIZE: int = 100  # For batch processing during migrations
    
    # Scrambled Eggs specific configuration
    SCRAMBLED_EGGS: ScrambledEggsConfig = field(default_factory=ScrambledEggsConfig)
    
    # Performance settings
    CHUNK_SIZE: int = 64 * 1024  # 64KB chunks for file operations
    
    # Security settings
    ENFORCE_STRONG_PASSWORDS: bool = True
    REQUIRE_HARDWARE_SECURITY_MODULE: bool = False
    
    # Audit logging
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_FILE: str = 'logs/encryption_audit.log'

# Create a default configuration instance
config = EncryptionConfig()

def update_config(env_prefix: str = 'ENCRYPTION_') -> None:
    """
    Update configuration from environment variables.
    
    Args:
        env_prefix: Prefix for environment variables
    """
    import os
    from dotenv import load_dotenv
    from typing import get_origin, get_args, Any, Type, TypeVar, Union
    
    load_dotenv()
    
    def parse_value(value: str, field_type: Type) -> Any:
        """Parse a string value to the appropriate type."""
        if value is None:
            return None
            
        origin = get_origin(field_type)
        
        # Handle Optional[Type] types
        if origin is Union and type(None) in get_args(field_type):
            field_type = next(arg for arg in get_args(field_type) if arg is not type(None))
            origin = get_origin(field_type)
        
        # Handle enum types
        if hasattr(field_type, '__origin__') and field_type.__origin__ is type(KeyRotationSchedule):
            return KeyRotationSchedule(value.lower())
        elif field_type is EncryptionLayer:
            return EncryptionLayer[value.upper()]
        # Handle boolean values
        elif field_type is bool:
            return value.lower() in ('true', '1', 'yes')
        # Handle integer values
        elif field_type is int:
            return int(value)
        # Handle float values
        elif field_type is float:
            return float(value)
        # Handle list of strings
        elif origin is list:
            return [item.strip() for item in value.split(',')]
        # Default case - return as string
        return str(value)
    
    # Update configuration from environment variables
    def update_nested_config(config_obj: Any, prefix: str = '') -> None:
        """Recursively update configuration from environment variables."""
        for field_name, field_info in config_obj.__dataclass_fields__.items():
            env_var = f"{env_prefix}{prefix}{field_name.upper()}"
            
            # Handle nested dataclasses
            if hasattr(field_info.type, '__dataclass_fields__'):
                update_nested_config(
                    getattr(config_obj, field_name),
                    prefix=f"{field_name.upper()}_"
                )
                continue
                
            # Skip if environment variable not set
            if env_var not in os.environ:
                continue
                
            # Parse and set the value
            value = os.environ[env_var]
            field_type = field_info.type
            
            try:
                parsed_value = parse_value(value, field_type)
                setattr(config_obj, field_name, parsed_value)
            except (ValueError, KeyError) as e:
                import logging
                logging.warning(
                    f"Failed to parse {env_var}: {value} as {field_type}. Error: {e}"
                )
    
    # Update the main config
    update_nested_config(config)
    
    # Ensure key storage path exists
    os.makedirs(config.KEY_STORAGE_PATH, exist_ok=True, mode=0o700)
    
    # Ensure audit log directory exists
    if config.AUDIT_LOG_ENABLED and config.AUDIT_LOG_FILE:
        log_dir = os.path.dirname(config.AUDIT_LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True, mode=0o750)

# Initialize the configuration on import
update_config()

# Function to get the crypto instance to avoid circular imports
_crypto_instance = None

def get_crypto():
    global _crypto_instance
    if _crypto_instance is None:
        # Use a lazy import to avoid circular imports
        from app.services.encryption.scrambled_eggs_crypto import ScrambledEggsCrypto
        _crypto_instance = ScrambledEggsCrypto()
    return _crypto_instance()

"""
Configuration manager for Scrambled Eggs application.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

class Config:
    """Simple configuration class that acts like a dictionary."""
    
    def __init__(self, *args, **kwargs):
        self._data = dict(*args, **kwargs)
    
    def get(self, key, default=None):
        """Get a configuration value by key."""
        return self._data.get(key, default)
    
    def __getitem__(self, key):
        return self._data[key]
    
    def __setitem__(self, key, value):
        self._data[key] = value
    
    def __contains__(self, key):
        return key in self._data
    
    def update(self, *args, **kwargs):
        """Update the configuration with new values."""
        self._data.update(*args, **kwargs)
    
    def to_dict(self):
        """Convert the configuration to a dictionary."""
        return self._data.copy()

@dataclass
class NetworkConfig:
    """Network configuration settings."""
    enable_tor: bool = True
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_data_dir: Optional[str] = None
    signaling_server: str = "wss://signaling.scrambled-eggs.dev"
    stun_servers: list = field(default_factory=lambda: [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
        "stun:stun2.l.google.com:19302"
    ])
    turn_servers: list = field(default_factory=list)

@dataclass
class SecurityConfig:
    """Security configuration settings."""
    enable_end_to_end_encryption: bool = True
    enable_forward_secrecy: bool = True
    enable_message_verification: bool = True
    key_rotation_interval: int = 7 * 24 * 60 * 60  # 1 week in seconds
    max_message_size_mb: int = 100  # 100MB
    require_contact_verification: bool = True

@dataclass
class UIConfig:
    """User interface configuration."""
    theme: str = "dark"  # 'light' or 'dark'
    font_size: int = 12
    show_typing_indicators: bool = True
    show_read_receipts: bool = True
    show_online_status: bool = True
    language: str = "en_US"
    enable_animations: bool = True

@dataclass
class StorageConfig:
    """Storage configuration settings."""
    data_dir: str = str(Path.home() / ".scrambled-eggs")
    message_history_days: int = 90  # Keep 90 days of message history
    max_storage_mb: int = 1024  # 1GB max storage
    encrypt_local_storage: bool = True
    backup_enabled: bool = True
    backup_dir: str = str(Path.home() / "ScrambledEggsBackups")

class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize the configuration manager."""
        # Set default config file if not specified
        if config_file is None:
            self.config_dir = Path.home() / ".config" / "scrambled-eggs"
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self.config_file = self.config_dir / "config.json"
        else:
            self.config_file = Path(config_file)
            self.config_dir = self.config_file.parent
        
        # Initialize default configuration
        self.network = NetworkConfig()
        self.security = SecurityConfig()
        self.ui = UIConfig()
        self.storage = StorageConfig()
        
        # Custom settings
        self._custom_settings: Dict[str, Any] = {}
        
        # Load configuration if file exists
        self.load()
    
    def load(self) -> bool:
        """Load configuration from file."""
        if not self.config_file.exists():
            logger.info(f"Config file not found, using defaults: {self.config_file}")
            return False
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Update configuration from file
            if 'network' in data:
                self.network = NetworkConfig(**data['network'])
            if 'security' in data:
                self.security = SecurityConfig(**data['security'])
            if 'ui' in data:
                self.ui = UIConfig(**data['ui'])
            if 'storage' in data:
                self.storage = StorageConfig(**data['storage'])
            if 'custom' in data:
                self._custom_settings = data['custom']
                
            logger.info(f"Configuration loaded from {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
    def save(self) -> bool:
        """Save configuration to file."""
        try:
            # Ensure config directory exists
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Prepare data for serialization
            data = {
                'network': asdict(self.network),
                'security': asdict(self.security),
                'ui': asdict(self.ui),
                'storage': asdict(self.storage),
                'custom': self._custom_settings
            }
            
            # Write to file
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot notation."""
        try:
            # Check custom settings first
            if key in self._custom_settings:
                return self._custom_settings[key]
                
            # Check main configuration sections
            parts = key.split('.')
            if len(parts) == 2:
                section, prop = parts
                if hasattr(self, section):
                    section_obj = getattr(self, section)
                    if hasattr(section_obj, prop):
                        return getattr(section_obj, prop)
            
            return default
            
        except Exception as e:
            logger.warning(f"Error getting config value '{key}': {e}")
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """Set a configuration value by dot notation."""
        try:
            # Check if this is a custom setting
            if key.startswith('custom.'):
                self._custom_settings[key[7:]] = value
                return True
                
            # Update main configuration
            parts = key.split('.')
            if len(parts) == 2:
                section, prop = parts
                if hasattr(self, section):
                    section_obj = getattr(self, section)
                    if hasattr(section_obj, prop):
                        # Get the type of the current value to convert the new value
                        current_value = getattr(section_obj, prop)
                        if current_value is not None:
                            value_type = type(current_value)
                            try:
                                # Convert to the correct type
                                if value_type == bool:
                                    if isinstance(value, str):
                                        value = value.lower() in ('true', '1', 'yes', 'y')
                                    else:
                                        value = bool(value)
                                else:
                                    value = value_type(value)
                            except (ValueError, TypeError):
                                logger.warning(f"Could not convert {value} to {value_type.__name__}")
                                return False
                        
                        setattr(section_obj, prop, value)
                        return True
            
            # If we get here, the key wasn't found in the main config
            # Store it as a custom setting
            self._custom_settings[key] = value
            return True
            
        except Exception as e:
            logger.error(f"Error setting config value '{key}': {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            'network': asdict(self.network),
            'security': asdict(self.security),
            'ui': asdict(self.ui),
            'storage': asdict(self.storage),
            'custom': self._custom_settings
        }
    
    def __str__(self) -> str:
        """String representation of the configuration."""
        import pprint
        return pprint.pformat(self.to_dict(), indent=2)


# Global configuration instance
_config: Optional[ConfigManager] = None

def get_config(config_file: Optional[str] = None) -> ConfigManager:
    """Get or create the global configuration instance."""
    global _config
    if _config is None:
        _config = ConfigManager(config_file)
    return _config


def init_config(config_file: Optional[str] = None, **kwargs) -> ConfigManager:
    """Initialize the global configuration with custom settings."""
    global _config
    _config = ConfigManager(config_file)
    
    # Apply any custom settings
    for key, value in kwargs.items():
        _config.set(key, value)
    
    # Save the configuration
    _config.save()
    
    return _config

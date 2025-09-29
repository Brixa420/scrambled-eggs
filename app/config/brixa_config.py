"""
Brixa Configuration Manager
Handles application-wide configuration and component initialization.
"""
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from app.file_transfer.secure_file_sharing import SecureFileSharing
from app.network.tor_integration import TorManager
from app.p2p.p2p_manager import P2PManager
from app.security.scrambled_eggs_crypto import ClippyAI, ScrambledEggsCrypto


class BrixaConfig:
    """Manages Brixa's configuration and core components."""
    
    def __init__(self, config_path: str = None):
        """Initialize Brixa configuration."""
        self.config_path = Path(config_path or self._get_default_config_path())
        self.config = self._load_config()
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.crypto: Optional[ScrambledEggsCrypto] = None
        self.clippy: Optional[ClippyAI] = None
        self.p2p_manager: Optional[P2PManager] = None
        self.tor_manager: Optional[TorManager] = None
        self.file_sharing: Optional[SecureFileSharing] = None
        
        # Initialize components
        self._init_components()
    
    def _get_default_config_path(self) -> Path:
        """Get the default configuration file path."""
        config_dir = Path.home() / ".config" / "brixa"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "config.json"
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        defaults = {
            "tor": {
                "enabled": True,
                "control_port": 9051,
                "socks_port": 9050,
                "data_dir": str(Path.home() / ".brixa" / "tor"),
            },
            "p2p": {
                "ice_servers": [
                    {"urls": ["stun:stun.l.google.com:19302"]}
                ],
                "enable_ipv6": True,
            },
            "security": {
                "min_key_derivation_iterations": 600000,
                "max_key_derivation_iterations": 2000000,
            },
            "storage": {
                "downloads_dir": str(Path.home() / "Downloads" / "Brixa"),
                "temp_dir": str(Path.home() / ".brixa" / "temp"),
            },
            "ui": {
                "theme": "dark",
                "font_size": 12,
                "show_advanced": False,
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return self._merge_dicts(defaults, json.load(f))
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
                
        return defaults
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
    
    def _init_components(self):
        """Initialize core components."""
        # Initialize Tor manager if enabled
        if self.config['tor']['enabled']:
            self.tor_manager = TorManager(
                tor_control_port=self.config['tor']['control_port'],
                tor_socks_port=self.config['tor']['socks_port'],
                tor_data_dir=self.config['tor']['data_dir']
            )
        
        # Initialize encryption
        self.crypto = ScrambledEggsCrypto()
        self.clippy = ClippyAI()
        
        # Initialize P2P manager
        self.p2p_manager = P2PManager(self.config['p2p'])
        
        # Initialize file sharing
        self.file_sharing = SecureFileSharing(
            p2p_manager=self.p2p_manager,
            storage_dir=self.config['storage']['downloads_dir']
        )
    
    def _merge_dicts(self, dict1: Dict, dict2: Dict) -> Dict:
        """Recursively merge two dictionaries."""
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_dicts(result[key], value)
            else:
                result[key] = value
        return result
    
    def get_component(self, component_name: str) -> Any:
        """Get a component by name."""
        components = {
            'crypto': self.crypto,
            'clippy': self.clippy,
            'p2p': self.p2p_manager,
            'tor': self.tor_manager,
            'file_sharing': self.file_sharing,
        }
        return components.get(component_name)
    
    def __getitem__(self, key: str) -> Any:
        """Get configuration value using dict-like access."""n        return self.config[key]
    
    def __setitem__(self, key: str, value: Any):
        """Set configuration value using dict-like access."""
        self.config[key] = value
        self.save_config()

# Global configuration instance
config = BrixaConfig()

def get_config() -> BrixaConfig:
    """Get the global configuration instance."""
    return config

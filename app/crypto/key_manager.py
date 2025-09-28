"""
Key Management for Scrambled Eggs

This module provides secure key generation, storage, and management
for the Scrambled Eggs encryption system.
"""
import os
import json
import base64
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class KeyManager:
    """Manages encryption keys for the Scrambled Eggs application."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the key manager with configuration."""
        self.config = self._load_config(config_path)
        self._ensure_directories()
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._load_keys()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        default_config = {
            'key_dir': 'data/keys',
            'current_key_id': None,
            'key_rotation_days': 90,
            'key_history_size': 3,
            'key_length': 32,  # 256 bits
            'salt_length': 16,
            'pbkdf2_iterations': 100000
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _ensure_directories(self) -> None:
        """Ensure all required directories exist."""
        os.makedirs(self.config['key_dir'], exist_ok=True, mode=0o700)
    
    def _get_key_path(self, key_id: str) -> str:
        """Get the filesystem path for a key."""
        return os.path.join(self.config['key_dir'], f"{key_id}.key")
    
    def _generate_key_id(self) -> str:
        """Generate a unique key ID."""
        return f"key_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
    
    def _load_keys(self) -> None:
        """Load all keys from the key directory."""
        key_dir = Path(self.config['key_dir'])
        self._keys = {}
        
        for key_file in key_dir.glob('*.key'):
            try:
                with open(key_file, 'r') as f:
                    key_data = json.load(f)
                    self._keys[key_data['id']] = key_data
            except Exception as e:
                logger.error(f"Failed to load key from {key_file}: {e}")
    
    def generate_key(self, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a new encryption key.
        
        Args:
            password: Optional password to derive the key from.
            
        Returns:
            Dictionary containing the key metadata.
        """
        key_id = self._generate_key_id()
        salt = os.urandom(self.config['salt_length'])
        
        if password:
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config['key_length'],
                salt=salt,
                iterations=self.config['pbkdf2_iterations'],
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            key_source = 'password'
        else:
            # Generate random key
            key = os.urandom(self.config['key_length'])
            key_source = 'random'
        
        # Prepare key metadata
        key_data = {
            'id': key_id,
            'created_at': datetime.utcnow().isoformat(),
            'key': base64.urlsafe_b64encode(key).decode('utf-8'),
            'salt': base64.urlsafe_b64encode(salt).decode('utf-8') if password else None,
            'key_source': key_source,
            'key_length': self.config['key_length'] * 8,  # in bits
            'is_active': True,
            'tags': ['generated']
        }
        
        # Save the key
        self._save_key(key_data)
        self._keys[key_id] = key_data
        
        # Set as current key if none exists
        if not self.config['current_key_id']:
            self.set_current_key(key_id)
        
        return key_data
    
    def _save_key(self, key_data: Dict[str, Any]) -> None:
        """Save a key to disk."""
        key_path = self._get_key_path(key_data['id'])
        with open(key_path, 'w') as f:
            json.dump(key_data, f, indent=2)
        os.chmod(key_path, 0o600)  # Restrict permissions
    
    def set_current_key(self, key_id: str) -> bool:
        """Set the current active key."""
        if key_id not in self._keys:
            logger.error(f"Key {key_id} not found")
            return False
        
        # Update current key in config
        self.config['current_key_id'] = key_id
        self._keys[key_id]['is_active'] = True
        self._keys[key_id]['last_used'] = datetime.utcnow().isoformat()
        
        # Update key file
        self._save_key(self._keys[key_id])
        
        logger.info(f"Set current key to {key_id}")
        return True
    
    def get_current_key(self) -> Optional[Dict[str, Any]]:
        """Get the current active key."""
        if not self.config['current_key_id']:
            return None
        return self._keys.get(self.config['current_key_id'])
    
    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get a key by ID."""
        return self._keys.get(key_id)
    
    def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """List all available keys."""
        return self._keys.copy()
    
    def rotate_keys(self) -> Dict[str, Any]:
        """
        Rotate to a new key and manage key history.
        
        Returns:
            Dictionary with information about the rotation.
        """
        old_key_id = self.config['current_key_id']
        new_key = self.generate_key()
        
        # Update key metadata
        if old_key_id and old_key_id in self._keys:
            self._keys[old_key_id]['is_active'] = False
            self._keys[old_key_id]['rotated_at'] = datetime.utcnow().isoformat()
            self._save_key(self._keys[old_key_id])
        
        self.set_current_key(new_key['id'])
        
        # Clean up old keys if we have too many
        self._cleanup_old_keys()
        
        return {
            'old_key_id': old_key_id,
            'new_key_id': new_key['id'],
            'message': 'Key rotation completed successfully'
        }
    
    def _cleanup_old_keys(self) -> None:
        """Remove old keys beyond the history limit."""
        if not self.config.get('key_history_size'):
            return
        
        # Sort keys by creation date (oldest first)
        sorted_keys = sorted(
            self._keys.values(),
            key=lambda x: x.get('created_at', '')
        )
        
        # Keep only the most recent N keys
        keys_to_keep = sorted_keys[-self.config['key_history_size']:]
        keys_to_remove = set(self._keys.keys()) - {k['id'] for k in keys_to_keep}
        
        # Remove old keys
        for key_id in keys_to_remove:
            key_path = self._get_key_path(key_id)
            try:
                os.remove(key_path)
                del self._keys[key_id]
                logger.info(f"Removed old key: {key_id}")
            except Exception as e:
                logger.error(f"Failed to remove key {key_id}: {e}")

# Create a singleton instance
key_manager = KeyManager()

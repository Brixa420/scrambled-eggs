"""
Key Manager

Handles secure storage and retrieval of cryptographic keys.
"""
import os
import json
import logging
from typing import Dict, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict, field

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

@dataclass
class KeyEntry:
    """Represents a key entry in the key store."""
    key_id: str
    key_data: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: time.time())
    expires_at: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert key entry to a dictionary."""
        return {
            'key_id': self.key_id,
            'key_data': self.key_data.hex(),
            'metadata': self.metadata,
            'created_at': self.created_at,
            'expires_at': self.expires_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyEntry':
        """Create a key entry from a dictionary."""
        return cls(
            key_id=data['key_id'],
            key_data=bytes.fromhex(data['key_data']),
            metadata=data.get('metadata', {}),
            created_at=data.get('created_at', time.time()),
            expires_at=data.get('expires_at')
        )

class KeyManager:
    """Manages cryptographic keys and their secure storage."""
    
    def __init__(self, storage_path: Optional[str] = None, master_key: Optional[bytes] = None):
        """
        Initialize the key manager.
        
        Args:
            storage_path: Path to store key files (default: ~/.scrambled_eggs/keys)
            master_key: Optional master key for encryption (default: generate new)
        """
        # Set up storage path
        if storage_path is None:
            self.storage_path = os.path.join(Path.home(), '.scrambled_eggs', 'keys')
        else:
            self.storage_path = storage_path
            
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Initialize master key
        self.master_key = master_key or self._load_or_generate_master_key()
        self.cipher_suite = Fernet(Fernet.generate_key() if self.master_key is None else self.master_key)
        
        # In-memory key cache
        self._key_cache: Dict[str, KeyEntry] = {}
        
        logger.info(f"KeyManager initialized with storage at {self.storage_path}")
    
    def _get_key_path(self, key_id: str) -> str:
        """Get the file path for a key."""
        return os.path.join(self.storage_path, f"{key_id}.key")
    
    def _load_or_generate_master_key(self) -> bytes:
        """Load or generate the master key."""
        master_key_path = os.path.join(self.storage_path, 'master.key')
        
        if os.path.exists(master_key_path):
            try:
                with open(master_key_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to load master key: {e}")
                raise RuntimeError("Failed to load master key")
        else:
            # Generate a new master key
            master_key = Fernet.generate_key()
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(master_key_path), exist_ok=True)
            
            # Save the master key
            try:
                with open(master_key_path, 'wb') as f:
                    f.write(master_key)
                
                # Set restrictive permissions (Unix-like systems)
                try:
                    os.chmod(master_key_path, 0o600)
                except (AttributeError, NotImplementedError):
                    pass  # Not supported on this platform
                
                logger.info("Generated new master key")
                return master_key
                
            except Exception as e:
                logger.error(f"Failed to save master key: {e}")
                raise RuntimeError("Failed to generate master key")
    
    def _encrypt_key_data(self, data: bytes) -> bytes:
        """Encrypt key data."""
        return self.cipher_suite.encrypt(data)
    
    def _decrypt_key_data(self, data: bytes) -> bytes:
        """Decrypt key data."""
        return self.cipher_suite.decrypt(data)
    
    def store_key(self, key_entry: KeyEntry) -> None:
        """
        Store a key in the key store.
        
        Args:
            key_entry: Key entry to store
        """
        # Update cache
        self._key_cache[key_entry.key_id] = key_entry
        
        # Prepare data for storage
        key_data = json.dumps(key_entry.to_dict()).encode('utf-8')
        encrypted_data = self._encrypt_key_data(key_data)
        
        # Write to file
        key_path = self._get_key_path(key_entry.key_id)
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            
            # Write to a temporary file first
            temp_path = f"{key_path}.tmp"
            with open(temp_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Atomic rename on POSIX systems, may not be atomic on Windows
            if os.path.exists(key_path):
                os.replace(temp_path, key_path)
            else:
                os.rename(temp_path, key_path)
            
            # Set restrictive permissions (Unix-like systems)
            try:
                os.chmod(key_path, 0o600)
            except (AttributeError, NotImplementedError):
                pass  # Not supported on this platform
                
        except Exception as e:
            logger.error(f"Failed to store key {key_entry.key_id}: {e}")
            # Clean up temp file if it exists
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:  # noqa
                    pass
            raise
    
    def load_key(self, key_id: str) -> Optional[KeyEntry]:
        """
        Load a key from the key store.
        
        Args:
            key_id: ID of the key to load
            
        Returns:
            Loaded key entry or None if not found
        """
        # Check cache first
        if key_id in self._key_cache:
            return self._key_cache[key_id]
        
        key_path = self._get_key_path(key_id)
        
        if not os.path.exists(key_path):
            return None
            
        try:
            # Read and decrypt the key data
            with open(key_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._decrypt_key_data(encrypted_data)
            key_dict = json.loads(decrypted_data.decode('utf-8'))
            
            # Create and cache the key entry
            key_entry = KeyEntry.from_dict(key_dict)
            self._key_cache[key_id] = key_entry
            
            return key_entry
            
        except Exception as e:
            logger.error(f"Failed to load key {key_id}: {e}")
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from the key store.
        
        Args:
            key_id: ID of the key to delete
            
        Returns:
            True if the key was deleted, False otherwise
        """
        # Remove from cache
        if key_id in self._key_cache:
            del self._key_cache[key_id]
        
        # Delete the key file
        key_path = self._get_key_path(key_id)
        
        try:
            if os.path.exists(key_path):
                os.unlink(key_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """
        List all keys in the key store.
        
        Returns:
            Dictionary mapping key IDs to their metadata
        """
        keys = {}
        
        try:
            for filename in os.listdir(self.storage_path):
                if not filename.endswith('.key') or filename == 'master.key':
                    continue
                    
                key_id = filename[:-4]  # Remove .key extension
                key_entry = self.load_key(key_id)
                
                if key_entry:
                    keys[key_id] = {
                        'created_at': key_entry.created_at,
                        'expires_at': key_entry.expires_at,
                        'metadata': key_entry.metadata
                    }
        except Exception as e:
            logger.error(f"Failed to list keys: {e}")
        
        return keys
    
    def generate_key(
        self, 
        key_id: str, 
        key_size: int = 32, 
        metadata: Optional[Dict[str, Any]] = None,
        expires_in: Optional[float] = None
    ) -> KeyEntry:
        """
        Generate a new cryptographic key.
        
        Args:
            key_id: Unique identifier for the key
            key_size: Size of the key in bytes
            metadata: Optional metadata to associate with the key
            expires_in: Optional TTL in seconds for the key
            
        Returns:
            The generated key entry
        """
        # Generate random bytes
        key_data = os.urandom(key_size)
        
        # Create key entry
        key_entry = KeyEntry(
            key_id=key_id,
            key_data=key_data,
            metadata=metadata or {},
            expires_at=(time.time() + expires_in) if expires_in else None
        )
        
        # Store the key
        self.store_key(key_entry)
        
        return key_entry

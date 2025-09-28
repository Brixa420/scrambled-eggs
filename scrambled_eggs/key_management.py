"""
Key Management System for Scrambled Eggs.
Handles generation, storage, and sharing of encryption keys for multiple users.
"""
import os
import json
import logging
import base64
import hashlib
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum, auto
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature, InvalidKey

logger = logging.getLogger(__name__)

class KeyType(Enum):
    """Types of keys in the system."""
    MASTER = auto()
    DATA_ENCRYPTION = auto()
    FILE_ENCRYPTION = auto()
    SHARED = auto()

@dataclass
class User:
    """Represents a user in the system."""
    user_id: str
    public_key: bytes
    private_key: Optional[bytes] = None  # Encrypted with user's password
    attributes: Dict = field(default_factory=dict)
    key_derivation_params: Dict = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: time.time())
    last_accessed: float = field(default_factory=lambda: time.time())

@dataclass
class KeyMetadata:
    """Metadata for an encryption key."""
    key_id: str
    key_type: KeyType
    owner_id: str
    created_at: float
    expires_at: Optional[float] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    is_compromised: bool = False
    usage_count: int = 0
    last_used: Optional[float] = None

class KeyManager:
    """Manages cryptographic keys for multiple users."""
    
    def __init__(self, storage_path: Optional[str] = None):
        """Initialize the key manager.
        
        Args:
            storage_path: Directory to store key files. If None, uses ~/.scrambled_eggs/keys
        """
        self.storage_path = Path(storage_path) if storage_path else Path.home() / ".scrambled_eggs" / "keys"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache of keys
        self._users: Dict[str, User] = {}
        self._key_metadata: Dict[str, KeyMetadata] = {}
        self._key_cache: Dict[str, bytes] = {}
        
        # Load existing keys if any
        self._load_keys()
    
    def _load_keys(self):
        """Load keys from disk."""
        try:
            # Load users
            users_file = self.storage_path / "users.json"
            if users_file.exists():
                with open(users_file, 'r') as f:
                    users_data = json.load(f)
                    for user_id, user_data in users_data.items():
                        self._users[user_id] = User(
                            user_id=user_id,
                            public_key=base64.b64decode(user_data['public_key']),
                            private_key=base64.b64decode(user_data['private_key']) if user_data['private_key'] else None,
                            attributes=user_data.get('attributes', {}),
                            key_derivation_params=user_data.get('key_derivation_params', {})
                        )
            
            # Load key metadata
            metadata_file = self.storage_path / "key_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    for key_id, meta in metadata.items():
                        self._key_metadata[key_id] = KeyMetadata(
                            key_id=key_id,
                            key_type=KeyType[meta['key_type']],
                            owner_id=meta['owner_id'],
                            created_at=meta['created_at'],
                            expires_at=meta.get('expires_at'),
                            description=meta.get('description', ''),
                            tags=meta.get('tags', []),
                            is_compromised=meta.get('is_compromised', False),
                            usage_count=meta.get('usage_count', 0),
                            last_used=meta.get('last_used')
                        )
                        
        except Exception as e:
            logger.error(f"Error loading keys: {e}")
            # If there's an error, we'll start with empty key stores
            self._users = {}
            self._key_metadata = {}
    
    def _save_keys(self):
        """Save keys to disk."""
        try:
            # Save users
            users_file = self.storage_path / "users.json"
            users_data = {}
            for user_id, user in self._users.items():
                users_data[user_id] = {
                    'public_key': base64.b64encode(user.public_key).decode('utf-8'),
                    'private_key': base64.b64encode(user.private_key).decode('utf-8') if user.private_key else None,
                    'attributes': user.attributes,
                    'key_derivation_params': user.key_derivation_params,
                    'created_at': user.created_at,
                    'last_accessed': user.last_accessed
                }
            
            with open(users_file, 'w') as f:
                json.dump(users_data, f, indent=2)
            
            # Save key metadata
            metadata_file = self.storage_path / "key_metadata.json"
            metadata = {}
            for key_id, meta in self._key_metadata.items():
                metadata[key_id] = {
                    'key_type': meta.key_type.name,
                    'owner_id': meta.owner_id,
                    'created_at': meta.created_at,
                    'expires_at': meta.expires_at,
                    'description': meta.description,
                    'tags': meta.tags,
                    'is_compromised': meta.is_compromised,
                    'usage_count': meta.usage_count,
                    'last_used': meta.last_used
                }
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving keys: {e}")
            raise
    
    def create_user(self, user_id: str, password: str, attributes: Optional[Dict] = None) -> User:
        """Create a new user with a key pair.
        
        Args:
            user_id: Unique identifier for the user
            password: User's password for encrypting the private key
            attributes: Optional user attributes (name, email, etc.)
            
        Returns:
            The created User object
        """
        if user_id in self._users:
            raise ValueError(f"User {user_id} already exists")
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Serialize public key
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Serialize and encrypt private key with password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        # Create user
        user = User(
            user_id=user_id,
            public_key=public_key,
            private_key=private_key_pem,
            attributes=attributes or {},
            key_derivation_params={
                'algorithm': 'PBKDF2-HMAC-SHA256',
                'iterations': 600000,
                'salt': os.urandom(16).hex()
            }
        )
        
        self._users[user_id] = user
        self._save_keys()
        
        return user
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get a user by ID."""
        return self._users.get(user_id)
    
    def generate_key(self, key_type: KeyType, owner_id: str, **kwargs) -> Tuple[str, bytes]:
        """Generate a new encryption key.
        
        Args:
            key_type: Type of key to generate
            owner_id: ID of the user who owns this key
            **kwargs: Additional key parameters (size, algorithm, etc.)
            
        Returns:
            Tuple of (key_id, key_bytes)
        """
        if owner_id not in self._users:
            raise ValueError(f"User {owner_id} does not exist")
        
        # Generate key based on type
        if key_type == KeyType.DATA_ENCRYPTION:
            key = os.urandom(32)  # 256-bit key for AES-256
        elif key_type == KeyType.FILE_ENCRYPTION:
            key = os.urandom(32)  # 256-bit key for file encryption
        elif key_type == KeyType.SHARED:
            key = os.urandom(32)  # 256-bit key for shared data
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Create key metadata
        key_id = hashlib.sha256(key).hexdigest()
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            owner_id=owner_id,
            created_at=time.time(),
            description=kwargs.get('description', ''),
            tags=kwargs.get('tags', [])
        )
        
        # Store key and metadata
        self._key_metadata[key_id] = metadata
        self._key_cache[key_id] = key
        self._save_keys()
        
        return key_id, key
    
    def get_key(self, key_id: str, user_id: Optional[str] = None) -> Optional[bytes]:
        """Get a key by ID, with optional access control.
        
        Args:
            key_id: ID of the key to retrieve
            user_id: Optional user ID for access control
            
        Returns:
            The key bytes if accessible, None otherwise
        """
        # Check if key exists and is not compromised
        metadata = self._key_metadata.get(key_id)
        if not metadata or metadata.is_compromised:
            return None
        
        # Check access control
        if user_id and metadata.owner_id != user_id:
            # Check if the key is shared with this user
            if not self._is_key_shared_with(key_id, user_id):
                return None
        
        # Update key usage stats
        metadata.usage_count += 1
        metadata.last_used = time.time()
        self._save_keys()
        
        # Return from cache or storage
        if key_id in self._key_cache:
            return self._key_cache[key_id]
        
        # In a real implementation, we would load the key from secure storage here
        # For this example, we'll just return None
        return None
    
    def _is_key_shared_with(self, key_id: str, user_id: str) -> bool:
        """Check if a key is shared with a specific user."""
        # In a real implementation, this would check a sharing database
        # For this example, we'll just return False
        return False
    
    def share_key(self, key_id: str, from_user_id: str, to_user_id: str, 
                 permission: str = 'read') -> bool:
        """Share a key with another user.
        
        Args:
            key_id: ID of the key to share
            from_user_id: User ID of the key owner
            to_user_id: User ID to share the key with
            permission: Permission level ('read', 'write', 'admin')
            
        Returns:
            True if sharing was successful, False otherwise
        """
        # Verify key exists and is owned by from_user_id
        if key_id not in self._key_metadata:
            return False
            
        if self._key_metadata[key_id].owner_id != from_user_id:
            return False
            
        # Verify target user exists
        if to_user_id not in self._users:
            return False
        
        # In a real implementation, we would store the sharing information
        # For this example, we'll just log it
        logger.info(f"Key {key_id} shared from {from_user_id} to {to_user_id} with {permission} permission")
        return True
    
    def revoke_key_share(self, key_id: str, owner_id: str, user_id: str) -> bool:
        """Revoke a previously shared key."""
        # Verify key exists and is owned by owner_id
        if key_id not in self._key_metadata:
            return False
            
        if self._key_metadata[key_id].owner_id != owner_id:
            return False
        
        # In a real implementation, we would update the sharing database
        # For this example, we'll just log it
        logger.info(f"Key {key_id} share revoked for user {user_id} by {owner_id}")
        return True
    
    def rotate_key(self, key_id: str, user_id: str) -> Optional[Tuple[str, bytes]]:
        """Rotate (replace) a key with a new one.
        
        Args:
            key_id: ID of the key to rotate
            user_id: ID of the user requesting the rotation
            
        Returns:
            Tuple of (new_key_id, new_key_bytes) if successful, None otherwise
        """
        # Verify key exists and user has permission
        if key_id not in self._key_metadata:
            return None
            
        metadata = self._key_metadata[key_id]
        if metadata.owner_id != user_id:
            return None
        
        # Mark old key as compromised
        metadata.is_compromised = True
        
        # Generate new key of the same type
        new_key_id, new_key = self.generate_key(
            key_type=metadata.key_type,
            owner_id=user_id,
            description=f"Rotated from {key_id}",
            tags=metadata.tags
        )
        
        # In a real implementation, we would re-encrypt data with the new key
        # For this example, we'll just return the new key
        return new_key_id, new_key
    
    def delete_key(self, key_id: str, user_id: str) -> bool:
        """Permanently delete a key."""
        # Verify key exists and is owned by user
        if key_id not in self._key_metadata:
            return False
            
        if self._key_metadata[key_id].owner_id != user_id:
            return False
        
        # Remove key from metadata and cache
        del self._key_metadata[key_id]
        if key_id in self._key_cache:
            del self._key_cache[key_id]
        
        self._save_keys()
        return True

# Example usage
if __name__ == "__main__":
    import getpass
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a key manager
    key_manager = KeyManager()
    
    # Create a test user
    user_id = "test_user"
    password = getpass.getpass(f"Enter password for {user_id}: ")
    
    if not key_manager.get_user(user_id):
        print(f"Creating user {user_id}...")
        user = key_manager.create_user(user_id, password, {"email": "test@example.com"})
        print(f"Created user {user_id} with public key: {user.public_key.decode()}")
    
    # Generate a test key
    key_id, key = key_manager.generate_key(
        key_type=KeyType.DATA_ENCRYPTION,
        owner_id=user_id,
        description="Test encryption key",
        tags=["test", "encryption"]
    )
    print(f"Generated key {key_id} for user {user_id}")
    
    # Retrieve the key
    retrieved_key = key_manager.get_key(key_id, user_id)
    print(f"Retrieved key: {retrieved_key == key}")
    
    # Try to access key with wrong user
    print(f"Unauthorized access: {key_manager.get_key(key_id, 'wrong_user') is None}")
    
    # Rotate the key
    new_key_id, new_key = key_manager.rotate_key(key_id, user_id)
    print(f"Rotated key {key_id} to {new_key_id}")
    
    # Delete the keys
    key_manager.delete_key(new_key_id, user_id)
    print(f"Deleted key {new_key_id}")

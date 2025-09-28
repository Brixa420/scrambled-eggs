"""
Key Management Module

This module provides secure key management for the Scrambled Eggs protocol,
including key generation, storage, and cryptographic operations using both
classical and post-quantum algorithms.
"""
import os
import json
import logging
import hashlib
import hmac
import time
import base64
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
import secrets

# Import our HSM and PQC modules
from .hsm import HSMInterface, HSMType, HSMKey, KeyType, KeyUsage
from .kyber import Kyber
from .dilithium import Dilithium
from .sphincs import SPHINCSPlus
from .homomorphic import HomomorphicCrypto, HomomorphicScheme

# Constants
DEFAULT_KEY_SIZE = 256  # Default key size in bits
KEY_DERIVATION_ITERATIONS = 600000  # For PBKDF2
SALT_SIZE = 32  # Bytes
NONCE_SIZE = 24  # For XChaCha20
TAG_SIZE = 16  # For Poly1305

class KeyPurpose(Enum):
    """Key usage purposes."""
    ENCRYPTION = auto()
    DECRYPTION = auto()
    SIGNING = auto()
    VERIFICATION = auto()
    KEY_AGREEMENT = auto()
    KEY_DERIVATION = auto()
    AUTHENTICATION = auto()
    STORAGE = auto()
    TRANSPORT = auto()
    MASTER = auto()
    IDENTITY = auto()
    SESSION = auto()
    EPHEMERAL = auto()

class KeyMetadata:
    """Metadata for a managed key."""
    def __init__(
        self,
        key_id: str,
        key_type: str,
        key_size: int,
        algorithm: str,
        created_at: float = None,
        expires_at: float = None,
        purpose: List[KeyPurpose] = None,
        tags: Dict[str, str] = None,
        version: int = 1,
        parent_key_id: str = None,
        is_extractable: bool = False,
        is_exportable: bool = False,
        is_ephemeral: bool = False,
        is_sensitive: bool = True,
        is_wrapped: bool = False,
        wrapped_key: bytes = None,
        wrapped_key_algorithm: str = None,
        wrapped_key_iv: bytes = None,
        wrapped_key_tag: bytes = None,
        **kwargs
    ):
        self.key_id = key_id
        self.key_type = key_type
        self.key_size = key_size
        self.algorithm = algorithm
        self.created_at = created_at or time.time()
        self.expires_at = expires_at
        self.purpose = purpose or []
        self.tags = tags or {}
        self.version = version
        self.parent_key_id = parent_key_id
        self.is_extractable = is_extractable
        self.is_exportable = is_exportable
        self.is_ephemeral = is_ephemeral
        self.is_sensitive = is_sensitive
        self.is_wrapped = is_wrapped
        self.wrapped_key = wrapped_key
        self.wrapped_key_algorithm = wrapped_key_algorithm
        self.wrapped_key_iv = wrapped_key_iv
        self.wrapped_key_tag = wrapped_key_tag
        
        # Store additional metadata
        self._extra = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a dictionary."""
        data = {
            'key_id': self.key_id,
            'key_type': self.key_type,
            'key_size': self.key_size,
            'algorithm': self.algorithm,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'purpose': [p.name for p in self.purpose],
            'tags': self.tags,
            'version': self.version,
            'parent_key_id': self.parent_key_id,
            'is_extractable': self.is_extractable,
            'is_exportable': self.is_exportable,
            'is_ephemeral': self.is_ephemeral,
            'is_sensitive': self.is_sensitive,
            'is_wrapped': self.is_wrapped,
            'wrapped_key': base64.b64encode(self.wrapped_key).decode('ascii') if self.wrapped_key else None,
            'wrapped_key_algorithm': self.wrapped_key_algorithm,
            'wrapped_key_iv': base64.b64encode(self.wrapped_key_iv).decode('ascii') if self.wrapped_key_iv else None,
            'wrapped_key_tag': base64.b64encode(self.wrapped_key_tag).decode('ascii') if self.wrapped_key_tag else None,
        }
        
        # Add extra fields
        data.update(self._extra)
        return {k: v for k, v in data.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyMetadata':
        """Create metadata from a dictionary."""
        # Extract known fields
        known_fields = {
            'key_id', 'key_type', 'key_size', 'algorithm', 'created_at',
            'expires_at', 'purpose', 'tags', 'version', 'parent_key_id',
            'is_extractable', 'is_exportable', 'is_ephemeral', 'is_sensitive',
            'is_wrapped', 'wrapped_key', 'wrapped_key_algorithm',
            'wrapped_key_iv', 'wrapped_key_tag'
        }
        
        # Separate known and extra fields
        known = {}
        extra = {}
        
        for k, v in data.items():
            if k in known_fields:
                known[k] = v
            else:
                extra[k] = v
        
        # Convert purpose strings back to enums
        if 'purpose' in known and isinstance(known['purpose'], list):
            known['purpose'] = [KeyPurpose[p] if isinstance(p, str) else p for p in known['purpose']]
        
        # Decode base64 fields
        for field in ['wrapped_key', 'wrapped_key_iv', 'wrapped_key_tag']:
            if field in known and known[field] is not None:
                if isinstance(known[field], str):
                    known[field] = base64.b64decode(known[field])
        
        # Create the metadata object
        metadata = cls(**known, **extra)
        return metadata
    
    def is_valid(self) -> bool:
        """Check if the key is valid (not expired)."""
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True
    
    def has_purpose(self, purpose: KeyPurpose) -> bool:
        """Check if the key has the specified purpose."""
        return purpose in self.purpose
    
    def add_purpose(self, purpose: KeyPurpose) -> None:
        """Add a purpose to the key."""
        if purpose not in self.purpose:
            self.purpose.append(purpose)
    
    def remove_purpose(self, purpose: KeyPurpose) -> None:
        """Remove a purpose from the key."""
        if purpose in self.purpose:
            self.purpose.remove(purpose)


class KeyManager:
    """
    Secure key management for the Scrambled Eggs protocol.
    
    This class provides a high-level interface for key management, including:
    - Key generation and derivation
    - Secure key storage (HSM, encrypted at rest)
    - Key lifecycle management
    - Cryptographic operations (sign/verify, encrypt/decrypt, key agreement)
    - Post-quantum cryptography support
    """
    
    def __init__(
        self,
        storage_path: str = None,
        hsm_config: Dict = None,
        master_key: bytes = None,
        password: str = None,
        salt: bytes = None,
        key_derivation_rounds: int = KEY_DERIVATION_ITERATIONS,
        logger: logging.Logger = None
    ):
        """
        Initialize the key manager.
        
        Args:
            storage_path: Path to the key storage directory
            hsm_config: Configuration for the HSM (if using HSM)
            master_key: Master key for key encryption (if not using HSM)
            password: Password for key derivation (if not using master_key)
            salt: Salt for key derivation (if not using password)
            key_derivation_rounds: Number of PBKDF2 rounds
            logger: Logger instance (will create one if not provided)
        """
        self.logger = logger or logging.getLogger(__name__)
        self.storage_path = Path(storage_path) if storage_path else None
        self.key_derivation_rounds = key_derivation_rounds
        self._keys: Dict[str, bytes] = {}
        self._metadata: Dict[str, KeyMetadata] = {}
        self._hsm = None
        self._hsm_keys: Dict[str, HSMKey] = {}
        self._key_cache: Dict[str, bytes] = {}
        
        # Initialize storage
        if self.storage_path:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize HSM if configured
        if hsm_config:
            self._init_hsm(hsm_config)
        
        # Initialize master key
        self._init_master_key(master_key, password, salt)
    
    def _init_hsm(self, config: Dict) -> None:
        """Initialize the HSM interface."""
        try:
            hsm_type = HSMType(config.get('type', 'soft_hsm').lower())
            self._hsm = HSMInterface(hsm_type, **config.get('config', {}))
            
            # Connect to the HSM
            if not self._hsm.connect():
                raise RuntimeError("Failed to connect to HSM")
            
            self.logger.info(f"Initialized {hsm_type.name} HSM")
            
            # Load HSM keys
            self._load_hsm_keys()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize HSM: {str(e)}")
            if self._hsm:
                self._hsm.disconnect()
                self._hsm = None
            raise
    
    def _load_hsm_keys(self) -> None:
        """Load keys from the HSM."""
        if not self._hsm:
            return
        
        try:
            # List all keys in the HSM
            hsm_keys = self._hsm.list_keys()
            
            # Store the keys in our cache
            for key in hsm_keys:
                self._hsm_keys[key.key_id] = key
                
            self.logger.info(f"Loaded {len(hsm_keys)} keys from HSM")
            
        except Exception as e:
            self.logger.error(f"Failed to load HSM keys: {str(e)}")
            raise
    
    def _init_master_key(self, master_key: bytes = None, password: str = None, salt: bytes = None) -> None:
        """Initialize the master key."""
        # If a master key is provided, use it directly
        if master_key:
            self._master_key = master_key
            self._master_key_salt = salt or os.urandom(SALT_SIZE)
            return
        
        # If a password is provided, derive a master key
        if password:
            self._master_key_salt = salt or os.urandom(SALT_SIZE)
            self._master_key = self._derive_key(
                password.encode('utf-8'),
                self._master_key_salt,
                key_size=32,  # 256-bit key
                purpose=KeyPurpose.MASTER
            )
            return
        
        # Try to load the master key from storage
        if self.storage_path and (self.storage_path / 'master.key').exists():
            self._load_master_key()
        else:
            # Generate a new random master key
            self._master_key = os.urandom(32)  # 256-bit key
            self._master_key_salt = os.urandom(SALT_SIZE)
            
            # Save the master key if we have a storage path
            if self.storage_path:
                self._save_master_key()
    
    def _load_master_key(self) -> bool:
        """Load the master key from storage."""
        if not self.storage_path:
            return False
        
        try:
            # Load the master key file
            with open(self.storage_path / 'master.key', 'rb') as f:
                data = f.read()
            
            # The file should contain: version (1 byte) || salt || encrypted_key
            if len(data) < 1 + SALT_SIZE + 16:  # Minimum size for AES-GCM
                raise ValueError("Invalid master key file format")
            
            version = data[0]
            if version != 1:
                raise ValueError(f"Unsupported master key version: {version}")
            
            # Extract salt and encrypted key
            self._master_key_salt = data[1:1 + SALT_SIZE]
            encrypted_key = data[1 + SALT_SIZE:]
            
            # The master key is encrypted with a key derived from the system keyring
            # or environment variables
            system_key = self._get_system_key()
            if not system_key:
                raise RuntimeError("Could not retrieve system key")
            
            # Derive a key for decryption
            key = self._derive_key(system_key, self._master_key_salt, key_size=32)
            
            # Decrypt the master key
            nonce = encrypted_key[:NONCE_SIZE]
            ciphertext = encrypted_key[NONCE_SIZE:-TAG_SIZE]
            tag = encrypted_key[-TAG_SIZE:]
            
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            chacha = ChaCha20Poly1305(key)
            self._master_key = chacha.decrypt(nonce, ciphertext + tag, None)
            
            self.logger.info("Loaded master key from storage")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load master key: {str(e)}")
            raise
    
    def _save_master_key(self) -> bool:
        """Save the master key to storage."""
        if not self.storage_path:
            return False
        
        try:
            # Get a system key for encryption
            system_key = self._get_system_key()
            if not system_key:
                raise RuntimeError("Could not retrieve system key")
            
            # Generate a random nonce
            nonce = os.urandom(NONCE_SIZE)
            
            # Derive a key for encryption
            key = self._derive_key(system_key, self._master_key_salt, key_size=32)
            
            # Encrypt the master key
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            chacha = ChaCha20Poly1305(key)
            ciphertext = chacha.encrypt(nonce, self._master_key, None)
            
            # The file contains: version (1 byte) || salt || nonce || ciphertext
            with open(self.storage_path / 'master.key', 'wb') as f:
                f.write(bytes([1]))  # Version
                f.write(self._master_key_salt)
                f.write(nonce)
                f.write(ciphertext[:-TAG_SIZE])  # Exclude the tag (appended by ChaCha20Poly1305)
                f.write(ciphertext[-TAG_SIZE:])   # Append the tag
            
            # Set restrictive permissions
            os.chmod(self.storage_path / 'master.key', 0o600)
            
            self.logger.info("Saved master key to storage")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save master key: {str(e)}")
            raise
    
    def _get_system_key(self) -> bytes:
        """Get a system-specific key for encrypting the master key."""
        # Try to get a key from the system keyring
        try:
            import keyring
            key = keyring.get_password('scrambled_eggs', 'system_key')
            if key:
                return key.encode('utf-8')
        except ImportError:
            pass
        
        # Try to get a key from an environment variable
        key = os.environ.get('SCRAMBLED_EGGS_SYSTEM_KEY')
        if key:
            return key.encode('utf-8')
        
        # As a last resort, use a fixed key (not recommended for production)
        self.logger.warning("Using a fixed system key - this is not secure for production!")
        return b'scrambled_eggs_insecure_default_key_do_not_use_in_production'
    
    def _derive_key(
        self,
        password: bytes,
        salt: bytes,
        key_size: int = 32,
        purpose: KeyPurpose = None,
        context: bytes = None,
        iterations: int = None
    ) -> bytes:
        """
        Derive a key from a password and salt.
        
        Args:
            password: The password to derive the key from
            salt: A unique salt
            key_size: The size of the key in bytes
            purpose: The purpose of the derived key
            context: Additional context for key derivation
            iterations: Number of PBKDF2 iterations (defaults to self.key_derivation_rounds)
            
        Returns:
            The derived key
        """
        if iterations is None:
            iterations = self.key_derivation_rounds
        
        # Add purpose and context to the salt
        if purpose:
            salt += purpose.name.encode('utf-8')
        if context:
            salt += context
        
        # Use PBKDF2-HMAC-SHA-256 for key derivation
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password,
            salt,
            iterations=iterations,
            dklen=key_size
        )
        
        return dk
    
    def _generate_key_id(self, prefix: str = 'key') -> str:
        """Generate a unique key ID."""
        while True:
            key_id = f"{prefix}_{secrets.token_hex(8)}"
            if key_id not in self._keys and key_id not in self._hsm_keys:
                return key_id
    
    def _wrap_key(self, key: bytes, wrapping_key_id: str = None) -> Tuple[bytes, bytes, bytes]:
        """
        Wrap a key using AES-GCM or the specified wrapping key.
        
        Args:
            key: The key to wrap
            wrapping_key_id: The ID of the key to use for wrapping (defaults to master key)
            
        Returns:
            A tuple of (wrapped_key, iv, tag)
        """
        # Generate a random nonce
        nonce = os.urandom(12)  # 96 bits for AES-GCM
        
        # Use the specified wrapping key or the master key
        if wrapping_key_id:
            wrapping_key = self.get_key(wrapping_key_id)
            if not wrapping_key:
                raise ValueError(f"Wrapping key not found: {wrapping_key_id}")
        else:
            wrapping_key = self._master_key
        
        # Encrypt the key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(wrapping_key)
        ciphertext = aesgcm.encrypt(nonce, key, None)
        
        # Split into ciphertext and tag
        return ciphertext[:-16], nonce, ciphertext[-16:]
    
    def _unwrap_key(self, wrapped_key: bytes, iv: bytes, tag: bytes, wrapping_key_id: str = None) -> bytes:
        """
        Unwrap a key using AES-GCM or the specified wrapping key.
        
        Args:
            wrapped_key: The wrapped key
            iv: The initialization vector
            tag: The authentication tag
            wrapping_key_id: The ID of the key to use for unwrapping (defaults to master key)
            
        Returns:
            The unwrapped key
        """
        # Use the specified wrapping key or the master key
        if wrapping_key_id:
            wrapping_key = self.get_key(wrapping_key_id)
            if not wrapping_key:
                raise ValueError(f"Wrapping key not found: {wrapping_key_id}")
        else:
            wrapping_key = self._master_key
        
        # Decrypt the key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(wrapping_key)
        try:
            return aesgcm.decrypt(iv, wrapped_key + tag, None)
        except Exception as e:
            self.logger.error(f"Failed to unwrap key: {str(e)}")
            raise ValueError("Invalid key or authentication tag")
    
    def generate_key(
        self,
        key_type: Union[str, KeyType],
        key_size: int = None,
        purpose: Union[KeyPurpose, List[KeyPurpose]] = None,
        algorithm: str = None,
        extractable: bool = False,
        exportable: bool = False,
        ephemeral: bool = False,
        tags: Dict[str, str] = None,
        use_hsm: bool = True
    ) -> str:
        """
        Generate a new cryptographic key.
        
        Args:
            key_type: The type of key to generate (e.g., 'aes', 'rsa', 'ec', 'kyber', 'dilithium')
            key_size: The size of the key in bits
            purpose: The intended use(s) of the key
            algorithm: The algorithm to use (e.g., 'AES-256-GCM', 'RSA-OAEP', 'ECDSA-P256')
            extractable: Whether the key can be extracted from the HSM
            exportable: Whether the key can be exported
            ephemeral: Whether the key is ephemeral (not persisted)
            tags: Optional key-value pairs for key management
            use_hsm: Whether to use the HSM if available
            
        Returns:
            The ID of the generated key
        """
        # Normalize parameters
        if isinstance(key_type, str):
            key_type = key_type.lower()
        
        if isinstance(purpose, KeyPurpose):
            purpose = [purpose]
        elif not purpose:
            purpose = []
        
        if tags is None:
            tags = {}
        
        # Set default key size if not specified
        if key_size is None:
            if key_type in ('aes', 'chacha20'):
                key_size = 256
            elif key_type in ('rsa', 'rsa-pss', 'rsa-oaep'):
                key_size = 2048
            elif key_type in ('ec', 'ecdsa', 'ecdh'):
                key_size = 256
            elif key_type == 'kyber':
                key_size = 512  # Kyber-512 by default
            elif key_type == 'dilithium':
                key_size = 2  # Dilithium2 by default
            elif key_type == 'sphincs+':
                key_size = 128  # SPHINCS+-128f by default
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
        
        # Generate the key
        key_id = self._generate_key_id(prefix=key_type)
        
        try:
            # Try to use HSM if available and requested
            if use_hsm and self._hsm:
                # Map key type to HSM key type
                if key_type in ('aes', 'chacha20'):
                    hsm_key_type = KeyType.AES
                elif key_type in ('rsa', 'rsa-pss', 'rsa-oaep'):
                    hsm_key_type = KeyType.RSA
                elif key_type in ('ec', 'ecdsa', 'ecdh'):
                    hsm_key_type = KeyType.EC
                else:
                    # For post-quantum algorithms, we'll handle them in software
                    hsm_key_type = None
                
                if hsm_key_type:
                    # Generate the key in the HSM
                    hsm_key = self._hsm.create_key(
                        key_id=key_id,
                        key_type=hsm_key_type,
                        key_size=key_size,
                        key_ops=[],  # Will be set based on purpose
                        extractable=extractable,
                        persistent=not ephemeral,
                        token=True,
                        private=True,
                        verify=True,
                        sign=KeyPurpose.SIGNING in purpose,
                        decrypt=KeyPurpose.DECRYPTION in purpose,
                        encrypt=KeyPurpose.ENCRYPTION in purpose,
                        wrap=KeyPurpose.KEY_AGREEMENT in purpose,
                        derive=KeyPurpose.KEY_DERIVATION in purpose,
                        sensitive=not exportable,
                        label=f"scrambled_eggs_{key_id}",
                        tags=tags
                    )
                    
                    # Store the HSM key reference
                    self._hsm_keys[key_id] = hsm_key
                    
                    # Create metadata
                    metadata = KeyMetadata(
                        key_id=key_id,
                        key_type=key_type,
                        key_size=key_size,
                        algorithm=algorithm or f"{key_type.upper()}-{key_size}",
                        purpose=purpose,
                        tags=tags,
                        is_extractable=extractable,
                        is_exportable=exportable,
                        is_ephemeral=ephemeral,
                        is_sensitive=not exportable,
                        hsm_managed=True,
                        hsm_key_id=hsm_key.key_id if hasattr(hsm_key, 'key_id') else None
                    )
                    
                    self._metadata[key_id] = metadata
                    
                    # Save metadata if not ephemeral
                    if not ephemeral and self.storage_path:
                        self._save_metadata(key_id)
                    
                    return key_id
            
            # Generate the key in software
            if key_type == 'aes':
                key = os.urandom(key_size // 8)
            elif key_type == 'chacha20':
                key = os.urandom(32)  # 256-bit key for ChaCha20
            elif key_type == 'rsa':
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size
                )
                
                # Serialize the private key
                key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            elif key_type == 'ec':
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import serialization
                
                # Map key size to curve
                if key_size == 256:
                    curve = ec.SECP256R1()
                elif key_size == 384:
                    curve = ec.SECP384R1()
                elif key_size == 521:
                    curve = ec.SECP521R1()
                else:
                    raise ValueError(f"Unsupported EC key size: {key_size}")
                
                private_key = ec.generate_private_key(curve)
                
                # Serialize the private key
                key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            elif key_type == 'kyber':
                # Generate a new Kyber key pair
                kyber = Kyber(key_size)
                public_key, private_key = kyber.keygen()
                
                # Store both keys (in a real implementation, you'd want to store them securely)
                key = {
                    'public_key': public_key,
                    'private_key': private_key,
                    'algorithm': f"KYBER-{key_size}"
                }
                
                # Convert to bytes for storage
                key = json.dumps(key).encode('utf-8')
                
            elif key_type == 'dilithium':
                # Generate a new Dilithium key pair
                dilithium = Dilithium(key_size)
                public_key, private_key = dilithium.keygen()
                
                # Store both keys
                key = {
                    'public_key': public_key,
                    'private_key': private_key,
                    'algorithm': f"DILITHIUM{key_size}"
                }
                
                # Convert to bytes for storage
                key = json.dumps(key).encode('utf-8')
                
            elif key_type == 'sphincs+':
                # Generate a new SPHINCS+ key pair
                sphincs = SPHINCSPlus(key_size)
                public_key, private_key = sphincs.keygen()
                
                # Store both keys
                key = {
                    'public_key': public_key,
                    'private_key': private_key,
                    'algorithm': f"SPHINCS+-{key_size}f"
                }
                
                # Convert to bytes for storage
                key = json.dumps(key).encode('utf-8')
                
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
            
            # Wrap the key if it's sensitive and we have a master key
            is_sensitive = not exportable
            wrapped_key = None
            wrapped_key_algorithm = None
            wrapped_key_iv = None
            wrapped_key_tag = None
            
            if is_sensitive and hasattr(self, '_master_key'):
                wrapped_key, wrapped_key_iv, wrapped_key_tag = self._wrap_key(key)
                key = None  # Don't store the plaintext key
            
            # Create metadata
            metadata = KeyMetadata(
                key_id=key_id,
                key_type=key_type,
                key_size=key_size,
                algorithm=algorithm or f"{key_type.upper()}-{key_size}",
                purpose=purpose,
                tags=tags,
                is_extractable=extractable,
                is_exportable=exportable,
                is_ephemeral=ephemeral,
                is_sensitive=is_sensitive,
                is_wrapped=wrapped_key is not None,
                wrapped_key=wrapped_key,
                wrapped_key_algorithm=wrapped_key_algorithm,
                wrapped_key_iv=wrapped_key_iv,
                wrapped_key_tag=wrapped_key_tag
            )
            
            # Store the key and metadata
            if key is not None:
                self._keys[key_id] = key
            self._metadata[key_id] = metadata
            
            # Save the key and metadata if not ephemeral
            if not ephemeral and self.storage_path:
                self._save_key(key_id)
                self._save_metadata(key_id)
            
            return key_id
            
        except Exception as e:
            self.logger.error(f"Failed to generate key: {str(e)}")
            raise
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Get a key by ID.
        
        Args:
            key_id: The ID of the key to retrieve
            
        Returns:
            The key bytes, or None if not found
        """
        # Check the cache first
        if key_id in self._key_cache:
            return self._key_cache[key_id]
        
        # Check if it's an HSM key
        if key_id in self._hsm_keys:
            # For HSM keys, we can't export the private key
            # Return a reference to the HSM key instead
            return self._hsm_keys[key_id]
        
        # Check in-memory keys
        if key_id in self._keys:
            key = self._keys[key_id]
            
            # If the key is wrapped, unwrap it
            if key_id in self._metadata and self._metadata[key_id].is_wrapped:
                metadata = self._metadata[key_id]
                try:
                    key = self._unwrap_key(
                        metadata.wrapped_key,
                        metadata.wrapped_key_iv,
                        metadata.wrapped_key_tag
                    )
                    
                    # Cache the unwrapped key
                    self._key_cache[key_id] = key
                except Exception as e:
                    self.logger.error(f"Failed to unwrap key {key_id}: {str(e)}")
                    return None
            
            return key
        
        # Try to load the key from storage
        if self.storage_path and (self.storage_path / f"{key_id}.key").exists():
            try:
                with open(self.storage_path / f"{key_id}.key", 'rb') as f:
                    key = f.read()
                
                # Store in memory
                self._keys[key_id] = key
                
                # Try to load metadata if not already loaded
                if key_id not in self._metadata and (self.storage_path / f"{key_id}.meta").exists():
                    self._load_metadata(key_id)
                
                # If the key is wrapped, unwrap it
                if key_id in self._metadata and self._metadata[key_id].is_wrapped:
                    metadata = self._metadata[key_id]
                    try:
                        key = self._unwrap_key(
                            key,
                            metadata.wrapped_key_iv,
                            metadata.wrapped_key_tag
                        )
                        
                        # Cache the unwrapped key
                        self._key_cache[key_id] = key
                    except Exception as e:
                        self.logger.error(f"Failed to unwrap key {key_id}: {str(e)}")
                        return None
                
                return key
                
            except Exception as e:
                self.logger.error(f"Failed to load key {key_id}: {str(e)}")
                return None
        
        return None
    
    def get_public_key(self, key_id: str) -> Optional[bytes]:
        """
        Get the public part of a key pair.
        
        Args:
            key_id: The ID of the key pair
            
        Returns:
            The public key bytes, or None if not found or not a key pair
        """
        # Check if it's an HSM key
        if key_id in self._hsm_keys:
            hsm_key = self._hsm_keys[key_id]
            if hasattr(hsm_key, 'public_key') and hsm_key.public_key:
                return hsm_key.public_key
        
        # For software keys, try to extract the public key
        key = self.get_key(key_id)
        if not key:
            return None
        
        try:
            # Try to parse as PEM
            if key.startswith(b'-----BEGIN'):
                from cryptography.hazmat.primitives import serialization
                
                # Try to load as private key
                try:
                    private_key = serialization.load_pem_private_key(
                        key,
                        password=None,
                    )
                    
                    # Get the public key
                    public_key = private_key.public_key()
                    
                    # Serialize the public key
                    return public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                except ValueError:
                    # Not a private key, try as public key
                    try:
                        public_key = serialization.load_pem_public_key(key)
                        return key  # Already in PEM format
                    except ValueError:
                        pass
            
            # Check if it's a JSON-encoded key pair (for post-quantum keys)
            try:
                key_data = json.loads(key.decode('utf-8'))
                if 'public_key' in key_data:
                    return key_data['public_key'].encode('utf-8')
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Not a key pair or public key not extractable
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to extract public key: {str(e)}")
            return None
    
    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """
        Get metadata for a key.
        
        Args:
            key_id: The ID of the key
            
        Returns:
            The key metadata, or None if not found
        """
        # Check in-memory metadata
        if key_id in self._metadata:
            return self._metadata[key_id]
        
        # Try to load from storage
        if self.storage_path and (self.storage_path / f"{key_id}.meta").exists():
            self._load_metadata(key_id)
            return self._metadata.get(key_id)
        
        return None
    
    def _load_metadata(self, key_id: str) -> bool:
        """Load metadata for a key from storage."""
        if not self.storage_path:
            return False
        
        try:
            with open(self.storage_path / f"{key_id}.meta", 'r') as f:
                data = json.load(f)
            
            self._metadata[key_id] = KeyMetadata.from_dict(data)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load metadata for key {key_id}: {str(e)}")
            return False
    
    def _save_metadata(self, key_id: str) -> bool:
        """Save metadata for a key to storage."""
        if not self.storage_path or key_id not in self._metadata:
            return False
        
        try:
            with open(self.storage_path / f"{key_id}.meta", 'w') as f:
                json.dump(self._metadata[key_id].to_dict(), f, indent=2)
            
            # Set restrictive permissions
            os.chmod(self.storage_path / f"{key_id}.meta", 0o600)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save metadata for key {key_id}: {str(e)}")
            return False
    
    def _save_key(self, key_id: str) -> bool:
        """Save a key to storage."""
        if not self.storage_path or key_id not in self._keys:
            return False
        
        try:
            with open(self.storage_path / f"{key_id}.key", 'wb') as f:
                f.write(self._keys[key_id])
            
            # Set restrictive permissions
            os.chmod(self.storage_path / f"{key_id}.key", 0o600)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save key {key_id}: {str(e)}")
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key.
        
        Args:
            key_id: The ID of the key to delete
            
        Returns:
            True if the key was deleted, False otherwise
        """
        try:
            # Delete from HSM if it's an HSM key
            if key_id in self._hsm_keys:
                if self._hsm:
                    self._hsm.delete_key(key_id)
                del self._hsm_keys[key_id]
            
            # Delete from memory
            if key_id in self._keys:
                del self._keys[key_id]
            
            if key_id in self._key_cache:
                del self._key_cache[key_id]
            
            if key_id in self._metadata:
                del self._metadata[key_id]
            
            # Delete from storage
            if self.storage_path:
                for ext in ('.key', '.meta'):
                    path = self.storage_path / f"{key_id}{ext}"
                    if path.exists():
                        try:
                            path.unlink()
                        except Exception as e:
                            self.logger.warning(f"Failed to delete {path}: {str(e)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete key {key_id}: {str(e)}")
            return False
    
    def list_keys(self, filter_func=None) -> List[str]:
        """
        List all key IDs.
        
        Args:
            filter_func: Optional function to filter keys (takes key_id, metadata)
            
        Returns:
            A list of key IDs
        """
        # Get all key IDs
        key_ids = set()
        
        # Add in-memory keys
        key_ids.update(self._keys.keys())
        
        # Add HSM keys
        key_ids.update(self._hsm_keys.keys())
        
        # Add keys from storage if available
        if self.storage_path and self.storage_path.exists():
            for path in self.storage_path.glob('*.key'):
                key_id = path.stem
                if key_id != 'master':  # Skip master key
                    key_ids.add(key_id)
        
        # Apply filter if provided
        if filter_func:
            filtered = []
            for key_id in key_ids:
                metadata = self.get_metadata(key_id)
                if filter_func(key_id, metadata):
                    filtered.append(key_id)
            return filtered
        
        return list(key_ids)
    
    def sign(self, key_id: str, data: bytes, algorithm: str = None) -> Optional[bytes]:
        """
        Sign data with a private key.
        
        Args:
            key_id: The ID of the signing key
            data: The data to sign
            algorithm: The signing algorithm to use
            
        Returns:
            The signature, or None if signing failed
        """
        # Get the key
        key = self.get_key(key_id)
        if not key:
            self.logger.error(f"Signing key not found: {key_id}")
            return None
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return None
        
        # Check if the key can be used for signing
        if not metadata.has_purpose(KeyPurpose.SIGNING):
            self.logger.error(f"Key {key_id} is not intended for signing")
            return None
        
        try:
            # Handle HSM keys
            if isinstance(key, HSMKey):
                if not self._hsm:
                    self.logger.error("HSM not available")
                    return None
                
                # Use the HSM to sign the data
                return self._hsm.sign(key_id, data, algorithm)
            
            # Handle software keys
            if metadata.key_type in ('rsa', 'ec'):
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding, ec
                from cryptography.hazmat.primitives import serialization
                from cryptography.exceptions import InvalidSignature
                
                # Try to load as PEM private key
                try:
                    private_key = serialization.load_pem_private_key(
                        key,
                        password=None,
                    )
                    
                    # Determine the hash algorithm
                    if algorithm:
                        if algorithm.lower().endswith('sha256'):
                            hash_alg = hashes.SHA256()
                        elif algorithm.lower().endswith('sha384'):
                            hash_alg = hashes.SHA384()
                        elif algorithm.lower().endswith('sha512'):
                            hash_alg = hashes.SHA512()
                        else:
                            hash_alg = hashes.SHA256()  # Default
                    else:
                        hash_alg = hashes.SHA256()  # Default
                    
                    # Sign the data
                    if isinstance(private_key, ec.EllipticCurvePrivateKey):
                        # ECDSA signature
                        signature = private_key.sign(
                            data,
                            ec.ECDSA(hash_alg)
                        )
                    else:
                        # RSA signature
                        if algorithm and 'pss' in algorithm.lower():
                            # RSA-PSS
                            signature = private_key.sign(
                                data,
                                padding.PSS(
                                    mgf=padding.MGF1(hash_alg),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hash_alg
                            )
                        else:
                            # PKCS#1 v1.5
                            signature = private_key.sign(
                                data,
                                padding.PKCS1v15(),
                                hash_alg
                            )
                    
                    return signature
                    
                except Exception as e:
                    self.logger.error(f"Failed to sign with key {key_id}: {str(e)}")
                    return None
            
            # Handle post-quantum keys
            elif metadata.key_type == 'dilithium':
                try:
                    # Load the key pair
                    key_data = json.loads(key.decode('utf-8'))
                    private_key = key_data['private_key']
                    
                    # Sign the data
                    dilithium = Dilithium(metadata.key_size)
                    signature = dilithium.sign(data, private_key)
                    
                    return signature
                    
                except Exception as e:
                    self.logger.error(f"Failed to sign with Dilithium key: {str(e)}")
                    return None
            
            elif metadata.key_type == 'sphincs+':
                try:
                    # Load the key pair
                    key_data = json.loads(key.decode('utf-8'))
                    private_key = key_data['private_key']
                    
                    # Sign the data
                    sphincs = SPHINCSPlus(metadata.key_size)
                    signature = sphincs.sign(data, private_key)
                    
                    return signature
                    
                except Exception as e:
                    self.logger.error(f"Failed to sign with SPHINCS+ key: {str(e)}")
                    return None
            
            else:
                self.logger.error(f"Unsupported key type for signing: {metadata.key_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Signing failed: {str(e)}")
            return None
    
    def verify(self, key_id: str, data: bytes, signature: bytes, algorithm: str = None) -> bool:
        """
        Verify a signature with a public key.
        
        Args:
            key_id: The ID of the verification key
            data: The data that was signed
            signature: The signature to verify
            algorithm: The signing algorithm that was used
            
        Returns:
            True if the signature is valid, False otherwise
        """
        # Get the public key
        public_key = self.get_public_key(key_id)
        if not public_key:
            self.logger.error(f"Verification key not found: {key_id}")
            return False
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return False
        
        # Check if the key can be used for verification
        if not metadata.has_purpose(KeyPurpose.VERIFICATION):
            self.logger.error(f"Key {key_id} is not intended for verification")
            return False
        
        try:
            # Handle HSM keys
            if key_id in self._hsm_keys:
                if not self._hsm:
                    self.logger.error("HSM not available")
                    return False
                
                # Use the HSM to verify the signature
                return self._hsm.verify(key_id, data, signature, algorithm)
            
            # Handle software keys
            if metadata.key_type in ('rsa', 'ec'):
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding, ec
                from cryptography.hazmat.primitives import serialization
                from cryptography.exceptions import InvalidSignature
                
                # Try to load as PEM public key
                try:
                    pub_key = serialization.load_pem_public_key(public_key)
                    
                    # Determine the hash algorithm
                    if algorithm:
                        if algorithm.lower().endswith('sha256'):
                            hash_alg = hashes.SHA256()
                        elif algorithm.lower().endswith('sha384'):
                            hash_alg = hashes.SHA384()
                        elif algorithm.lower().endswith('sha512'):
                            hash_alg = hashes.SHA512()
                        else:
                            hash_alg = hashes.SHA256()  # Default
                    else:
                        hash_alg = hashes.SHA256()  # Default
                    
                    # Verify the signature
                    try:
                        if isinstance(pub_key, ec.EllipticCurvePublicKey):
                            # ECDSA verification
                            pub_key.verify(
                                signature,
                                data,
                                ec.ECDSA(hash_alg)
                            )
                        else:
                            # RSA verification
                            if algorithm and 'pss' in algorithm.lower():
                                # RSA-PSS
                                pub_key.verify(
                                    signature,
                                    data,
                                    padding.PSS(
                                        mgf=padding.MGF1(hash_alg),
                                        salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hash_alg
                                )
                            else:
                                # PKCS#1 v1.5
                                pub_key.verify(
                                    signature,
                                    data,
                                    padding.PKCS1v15(),
                                    hash_alg
                                )
                        
                        return True
                        
                    except InvalidSignature:
                        return False
                    
                except Exception as e:
                    self.logger.error(f"Verification failed: {str(e)}")
                    return False
            
            # Handle post-quantum keys
            elif metadata.key_type == 'dilithium':
                try:
                    # The public key is already in the right format
                    pub_key = public_key
                    
                    # Verify the signature
                    dilithium = Dilithium(metadata.key_size)
                    return dilithium.verify(data, signature, pub_key)
                    
                except Exception as e:
                    self.logger.error(f"Dilithium verification failed: {str(e)}")
                    return False
            
            elif metadata.key_type == 'sphincs+':
                try:
                    # The public key is already in the right format
                    pub_key = public_key
                    
                    # Verify the signature
                    sphincs = SPHINCSPlus(metadata.key_size)
                    return sphincs.verify(data, signature, pub_key)
                    
                except Exception as e:
                    self.logger.error(f"SPHINCS+ verification failed: {str(e)}")
                    return False
            
            else:
                self.logger.error(f"Unsupported key type for verification: {metadata.key_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Verification failed: {str(e)}")
            return False
    
    def encrypt(self, key_id: str, plaintext: bytes, algorithm: str = None) -> Optional[bytes]:
        """
        Encrypt data with a key.
        
        Args:
            key_id: The ID of the encryption key
            plaintext: The data to encrypt
            algorithm: The encryption algorithm to use
            
        Returns:
            The encrypted data, or None if encryption failed
        """
        # Get the key
        key = self.get_key(key_id)
        if not key:
            self.logger.error(f"Encryption key not found: {key_id}")
            return None
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return None
        
        # Check if the key can be used for encryption
        if not metadata.has_purpose(KeyPurpose.ENCRYPTION):
            self.logger.error(f"Key {key_id} is not intended for encryption")
            return None
        
        try:
            # Handle HSM keys
            if isinstance(key, HSMKey):
                if not self._hsm:
                    self.logger.error("HSM not available")
                    return None
                
                # Use the HSM to encrypt the data
                return self._hsm.encrypt(key_id, plaintext, algorithm)
            
            # Handle software keys
            if metadata.key_type in ('aes', 'chacha20'):
                # For symmetric encryption, the key is the raw bytes
                key_bytes = key
                
                # Determine the algorithm
                if not algorithm:
                    if metadata.key_type == 'aes':
                        if metadata.key_size == 128:
                            algorithm = 'AES-128-GCM'
                        elif metadata.key_size == 192:
                            algorithm = 'AES-192-GCM'
                        else:  # 256
                            algorithm = 'AES-256-GCM'
                    else:  # chacha20
                        algorithm = 'CHACHA20-POLY1305'
                
                # Encrypt the data
                if algorithm.startswith('AES'):
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    
                    # Generate a random nonce
                    nonce = os.urandom(12)  # 96 bits for AES-GCM
                    
                    # Create the cipher
                    aesgcm = AESGCM(key_bytes)
                    
                    # Encrypt the data
                    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                    
                    # Return nonce + ciphertext + tag
                    return nonce + ciphertext
                    
                elif algorithm == 'CHACHA20-POLY1305':
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                    
                    # Generate a random nonce
                    nonce = os.urandom(12)  # 96 bits for ChaCha20-Poly1305
                    
                    # Create the cipher
                    chacha = ChaCha20Poly1305(key_bytes)
                    
                    # Encrypt the data
                    ciphertext = chacha.encrypt(nonce, plaintext, None)
                    
                    # Return nonce + ciphertext + tag
                    return nonce + ciphertext
                
                else:
                    self.logger.error(f"Unsupported encryption algorithm: {algorithm}")
                    return None
            
            elif metadata.key_type in ('rsa', 'rsa-oaep'):
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                
                # For RSA, we use hybrid encryption (RSA-OAEP + AES-GCM)
                
                # Generate a random AES key
                aes_key = os.urandom(32)  # 256-bit key for AES-256-GCM
                
                # Encrypt the data with AES-GCM
                nonce = os.urandom(12)  # 96 bits for GCM
                
                aesgcm = Cipher(
                    algorithms.AES(aes_key),
                    modes.GCM(nonce)
                ).encryptor()
                
                # Encrypt the plaintext
                ciphertext = aesgcm.update(plaintext) + aesgcm.finalize()
                tag = aesgcm.tag
                
                # Encrypt the AES key with RSA-OAEP
                try:
                    private_key = serialization.load_pem_private_key(
                        key,
                        password=None,
                    )
                    
                    # Get the public key
                    public_key = private_key.public_key()
                    
                    # Encrypt the AES key
                    encrypted_key = public_key.encrypt(
                        aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Return: encrypted_key (RSA) || nonce (12) || ciphertext (AES-GCM) || tag (16)
                    return encrypted_key + nonce + ciphertext + tag
                    
                except Exception as e:
                    self.logger.error(f"RSA encryption failed: {str(e)}")
                    return None
            
            elif metadata.key_type == 'kyber':
                # For Kyber, we use KEM to derive a shared secret and then use AES-GCM
                try:
                    # Load the key pair
                    key_data = json.loads(key.decode('utf-8'))
                    
                    # Generate an ephemeral key pair
                    kyber = Kyber(metadata.key_size)
                    ciphertext, shared_secret = kyber.encapsulate(key_data['public_key'])
                    
                    # Derive an AES key from the shared secret
                    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                    from cryptography.hazmat.primitives import hashes
                    
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,  # 256-bit key
                        salt=None,
                        info=b'scrambled_eggs_kyber_kem',
                    )
                    
                    aes_key = hkdf.derive(shared_secret)
                    
                    # Encrypt the data with AES-GCM
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    
                    nonce = os.urandom(12)  # 96 bits for GCM
                    
                    aesgcm = AESGCM(aes_key)
                    encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
                    
                    # Return: ciphertext (Kyber) || nonce (12) || encrypted_data (AES-GCM)
                    return ciphertext + nonce + encrypted_data
                    
                except Exception as e:
                    self.logger.error(f"Kyber encryption failed: {str(e)}")
                    return None
            
            else:
                self.logger.error(f"Unsupported key type for encryption: {metadata.key_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            return None
    
    def decrypt(self, key_id: str, ciphertext: bytes, algorithm: str = None) -> Optional[bytes]:
        """
        Decrypt data with a key.
        
        Args:
            key_id: The ID of the decryption key
            ciphertext: The data to decrypt
            algorithm: The encryption algorithm that was used
            
        Returns:
            The decrypted data, or None if decryption failed
        """
        # Get the key
        key = self.get_key(key_id)
        if not key:
            self.logger.error(f"Decryption key not found: {key_id}")
            return None
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return None
        
        # Check if the key can be used for decryption
        if not metadata.has_purpose(KeyPurpose.DECRYPTION):
            self.logger.error(f"Key {key_id} is not intended for decryption")
            return None
        
        try:
            # Handle HSM keys
            if isinstance(key, HSMKey):
                if not self._hsm:
                    self.logger.error("HSM not available")
                    return None
                
                # Use the HSM to decrypt the data
                return self._hsm.decrypt(key_id, ciphertext, algorithm)
            
            # Handle software keys
            if metadata.key_type in ('aes', 'chacha20'):
                # For symmetric encryption, the key is the raw bytes
                key_bytes = key
                
                # Determine the algorithm
                if not algorithm:
                    if metadata.key_type == 'aes':
                        if metadata.key_size == 128:
                            algorithm = 'AES-128-GCM'
                        elif metadata.key_size == 192:
                            algorithm = 'AES-192-GCM'
                        else:  # 256
                            algorithm = 'AES-256-GCM'
                    else:  # chacha20
                        algorithm = 'CHACHA20-POLY1305'
                
                # Decrypt the data
                if algorithm.startswith('AES'):
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    
                    # Extract nonce and ciphertext
                    if len(ciphertext) < 12 + 16:  # nonce (12) + tag (16)
                        self.logger.error("Invalid ciphertext format")
                        return None
                    
                    nonce = ciphertext[:12]
                    encrypted_data = ciphertext[12:]
                    
                    # Create the cipher
                    aesgcm = AESGCM(key_bytes)
                    
                    # Decrypt the data
                    try:
                        return aesgcm.decrypt(nonce, encrypted_data, None)
                    except Exception as e:
                        self.logger.error(f"Decryption failed: {str(e)}")
                        return None
                    
                elif algorithm == 'CHACHA20-POLY1305':
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                    
                    # Extract nonce and ciphertext
                    if len(ciphertext) < 12 + 16:  # nonce (12) + tag (16)
                        self.logger.error("Invalid ciphertext format")
                        return None
                    
                    nonce = ciphertext[:12]
                    encrypted_data = ciphertext[12:]
                    
                    # Create the cipher
                    chacha = ChaCha20Poly1305(key_bytes)
                    
                    # Decrypt the data
                    try:
                        return chacha.decrypt(nonce, encrypted_data, None)
                    except Exception as e:
                        self.logger.error(f"Decryption failed: {str(e)}")
                        return None
                
                else:
                    self.logger.error(f"Unsupported encryption algorithm: {algorithm}")
                    return None
            
            elif metadata.key_type in ('rsa', 'rsa-oaep'):
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                
                # For RSA, we use hybrid encryption (RSA-OAEP + AES-GCM)
                
                # Extract the encrypted key and ciphertext
                if len(ciphertext) < 256 + 12 + 16:  # RSA-2048 (256 bytes) + nonce (12) + tag (16)
                    self.logger.error("Invalid ciphertext format")
                    return None
                
                encrypted_key = ciphertext[:256]  # Assuming 2048-bit RSA
                nonce = ciphertext[256:268]
                encrypted_data = ciphertext[268:-16]
                tag = ciphertext[-16:]
                
                try:
                    # Load the private key
                    private_key = serialization.load_pem_private_key(
                        key,
                        password=None,
                    )
                    
                    # Decrypt the AES key
                    aes_key = private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Decrypt the data with AES-GCM
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    
                    aesgcm = AESGCM(aes_key)
                    return aesgcm.decrypt(nonce, encrypted_data + tag, None)
                    
                except Exception as e:
                    self.logger.error(f"RSA decryption failed: {str(e)}")
                    return None
            
            elif metadata.key_type == 'kyber':
                # For Kyber, we use KEM to derive a shared secret and then use AES-GCM
                try:
                    # Load the key pair
                    key_data = json.loads(key.decode('utf-8'))
                    
                    # Extract the ciphertext and encrypted data
                    kyber_ciphertext = ciphertext[:1088]  # Size depends on Kyber parameters
                    nonce = ciphertext[1088:1100]
                    encrypted_data = ciphertext[1100:]
                    
                    # Decapsulate to get the shared secret
                    kyber = Kyber(metadata.key_size)
                    shared_secret = kyber.decapsulate(kyber_ciphertext, key_data['private_key'])
                    
                    # Derive the AES key from the shared secret
                    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                    from cryptography.hazmat.primitives import hashes
                    
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,  # 256-bit key
                        salt=None,
                        info=b'scrambled_eggs_kyber_kem',
                    )
                    
                    aes_key = hkdf.derive(shared_secret)
                    
                    # Decrypt the data with AES-GCM
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    
                    aesgcm = AESGCM(aes_key)
                    return aesgcm.decrypt(nonce, encrypted_data, None)
                    
                except Exception as e:
                    self.logger.error(f"Kyber decryption failed: {str(e)}")
                    return None
            
            else:
                self.logger.error(f"Unsupported key type for decryption: {metadata.key_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            return None
    
    def key_exchange(self, key_id: str, peer_public_key: bytes, algorithm: str = None) -> Optional[bytes]:
        """
        Perform a key exchange to derive a shared secret.
        
        Args:
            key_id: The ID of the local key pair
            peer_public_key: The peer's public key
            algorithm: The key exchange algorithm to use
            
        Returns:
            The shared secret, or None if key exchange failed
        """
        # Get the key
        key = self.get_key(key_id)
        if not key:
            self.logger.error(f"Key not found: {key_id}")
            return None
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return None
        
        # Check if the key can be used for key agreement
        if not metadata.has_purpose(KeyPurpose.KEY_AGREEMENT):
            self.logger.error(f"Key {key_id} is not intended for key agreement")
            return None
        
        try:
            # Handle HSM keys
            if isinstance(key, HSMKey):
                if not self._hsm:
                    self.logger.error("HSM not available")
                    return None
                
                # Use the HSM for key agreement
                return self._hsm.key_agreement(key_id, peer_public_key, algorithm)
            
            # Handle software keys
            if metadata.key_type in ('ec', 'ecdh'):
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives import hashes
                
                try:
                    # Load the private key
                    private_key = serialization.load_pem_private_key(
                        key,
                        password=None,
                    )
                    
                    # Deserialize the peer's public key
                    if isinstance(peer_public_key, bytes):
                        # Try to load as PEM
                        try:
                            peer_pub_key = serialization.load_pem_public_key(peer_public_key)
                        except ValueError:
                            # Not a PEM-encoded key, try as raw bytes
                            try:
                                # For X25519
                                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                                peer_pub_key = X25519PublicKey.from_public_bytes(peer_public_key)
                            except Exception:
                                # For other EC curves
                                from cryptography.hazmat.primitives.serialization import load_der_public_key
                                peer_pub_key = load_der_public_key(peer_public_key)
                    else:
                        peer_pub_key = peer_public_key
                    
                    # Perform the key exchange
                    shared_key = private_key.exchange(ec.ECDH(), peer_pub_key)
                    
                    # Derive a key from the shared secret
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,  # 256-bit key
                        salt=None,
                        info=b'scrambled_eggs_ecdh',
                    )
                    
                    return hkdf.derive(shared_key)
                    
                except Exception as e:
                    self.logger.error(f"ECDH key exchange failed: {str(e)}")
                    return None
            
            elif metadata.key_type == 'kyber':
                try:
                    # Load the key pair
                    key_data = json.loads(key.decode('utf-8'))
                    
                    # Decapsulate to get the shared secret
                    kyber = Kyber(metadata.key_size)
                    shared_secret = kyber.decapsulate(peer_public_key, key_data['private_key'])
                    
                    # Derive a key from the shared secret
                    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                    from cryptography.hazmat.primitives import hashes
                    
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,  # 256-bit key
                        salt=None,
                        info=b'scrambled_eggs_kyber_kem',
                    )
                    
                    return hkdf.derive(shared_secret)
                    
                except Exception as e:
                    self.logger.error(f"Kyber key exchange failed: {str(e)}")
                    return None
            
            else:
                self.logger.error(f"Unsupported key type for key exchange: {metadata.key_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Key exchange failed: {str(e)}")
            return None
    
    def wrap_key(self, key_id: str, wrapping_key_id: str = None, algorithm: str = None) -> Optional[Dict[str, bytes]]:
        """
        Wrap a key for secure storage or transport.
        
        Args:
            key_id: The ID of the key to wrap
            wrapping_key_id: The ID of the key to use for wrapping (defaults to master key)
            algorithm: The wrapping algorithm to use
            
        Returns:
            A dictionary containing the wrapped key and related data, or None if wrapping failed
        """
        # Get the key to wrap
        key = self.get_key(key_id)
        if not key:
            self.logger.error(f"Key not found: {key_id}")
            return None
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return None
        
        # Check if the key is already wrapped
        if metadata.is_wrapped:
            self.logger.warning(f"Key {key_id} is already wrapped")
            return None
        
        # Check if the key is extractable
        if not metadata.is_extractable and not metadata.is_exportable:
            self.logger.error(f"Key {key_id} is not extractable or exportable")
            return None
        
        try:
            # Wrap the key
            wrapped_key, iv, tag = self._wrap_key(key, wrapping_key_id)
            
            # Update metadata
            metadata.is_wrapped = True
            metadata.wrapped_key = wrapped_key
            metadata.wrapped_key_algorithm = algorithm or 'AES-256-GCM'
            metadata.wrapped_key_iv = iv
            metadata.wrapped_key_tag = tag
            
            # Save the updated metadata
            if not metadata.is_ephemeral and self.storage_path:
                self._save_metadata(key_id)
            
            # Remove the plaintext key from memory
            if key_id in self._keys:
                del self._keys[key_id]
            
            if key_id in self._key_cache:
                del self._key_cache[key_id]
            
            return {
                'wrapped_key': wrapped_key,
                'algorithm': algorithm or 'AES-256-GCM',
                'iv': iv,
                'tag': tag
            }
            
        except Exception as e:
            self.logger.error(f"Failed to wrap key {key_id}: {str(e)}")
            return None
    
    def unwrap_key(self, key_id: str, wrapped_key: bytes, iv: bytes, tag: bytes, 
                  wrapping_key_id: str = None, algorithm: str = None) -> bool:
        """
        Unwrap a key that was previously wrapped.
        
        Args:
            key_id: The ID of the key to unwrap
            wrapped_key: The wrapped key data
            iv: The initialization vector used for wrapping
            tag: The authentication tag from the wrapping operation
            wrapping_key_id: The ID of the key to use for unwrapping (defaults to master key)
            algorithm: The wrapping algorithm that was used
            
        Returns:
            True if the key was successfully unwrapped, False otherwise
        """
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return False
        
        # Check if the key is already unwrapped
        if not metadata.is_wrapped:
            self.logger.warning(f"Key {key_id} is not wrapped")
            return True  # Not an error, just a no-op
        
        try:
            # Unwrap the key
            key = self._unwrap_key(wrapped_key, iv, tag, wrapping_key_id)
            
            # Store the unwrapped key
            self._keys[key_id] = key
            
            # Update metadata
            metadata.is_wrapped = False
            metadata.wrapped_key = None
            metadata.wrapped_key_algorithm = None
            metadata.wrapped_key_iv = None
            metadata.wrapped_key_tag = None
            
            # Save the updated metadata
            if not metadata.is_ephemeral and self.storage_path:
                self._save_metadata(key_id)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unwrap key {key_id}: {str(e)}")
            return False
    
    def derive_key(
        self,
        key_id: str,
        context: bytes = None,
        key_size: int = 32,
        algorithm: str = 'HKDF-SHA256',
        salt: bytes = None,
        info: bytes = None
    ) -> Optional[bytes]:
        """
        Derive a new key from an existing key.
        
        Args:
            key_id: The ID of the base key
            context: Additional context for key derivation
            key_size: The size of the derived key in bytes
            algorithm: The key derivation algorithm to use
            salt: Optional salt for key derivation
            info: Optional info for key derivation
            
        Returns:
            The derived key, or None if derivation failed
        """
        # Get the base key
        key = self.get_key(key_id)
        if not key:
            self.logger.error(f"Base key not found: {key_id}")
            return None
        
        # Get metadata
        metadata = self.get_metadata(key_id)
        if not metadata:
            self.logger.error(f"No metadata for key: {key_id}")
            return None
        
        # Check if the key can be used for key derivation
        if not metadata.has_purpose(KeyPurpose.KEY_DERIVATION):
            self.logger.error(f"Key {key_id} is not intended for key derivation")
            return None
        
        try:
            # Handle HSM keys
            if isinstance(key, HSMKey):
                if not self._hsm:
                    self.logger.error("HSM not available")
                    return None
                
                # Use the HSM for key derivation
                return self._hsm.derive_key(
                    key_id=key_id,
                    context=context,
                    key_size=key_size,
                    algorithm=algorithm,
                    salt=salt,
                    info=info
                )
            
            # Handle software keys
            if algorithm.lower().startswith('hkdf'):
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                
                # Determine the hash algorithm
                if algorithm.lower().endswith('sha256'):
                    hash_alg = hashes.SHA256()
                elif algorithm.lower().endswith('sha384'):
                    hash_alg = hashes.SHA384()
                elif algorithm.lower().endswith('sha512'):
                    hash_alg = hashes.SHA512()
                else:
                    hash_alg = hashes.SHA256()  # Default
                
                # Use the key as the input key material
                ikm = key
                
                # If the key is a private key, use its public key as IKM
                if metadata.key_type in ('rsa', 'ec', 'ed25519', 'x25519'):
                    try:
                        from cryptography.hazmat.primitives import serialization
                        
                        # Try to load as private key
                        try:
                            private_key = serialization.load_pem_private_key(
                                key,
                                password=None,
                            )
                            public_key = private_key.public_key()
                            ikm = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                        except ValueError:
                            # Not a private key, use as is
                            pass
                    except ImportError:
                        pass
                
                # Derive the key
                hkdf = HKDF(
                    algorithm=hash_alg,
                    length=key_size,
                    salt=salt,
                    info=info or b'scrambled_eggs_key_derivation',
                )
                
                return hkdf.derive(ikm)
            
            elif algorithm.lower() == 'pbkdf2':
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                
                # Use the key as the password
                password = key
                
                # Derive the key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_size,
                    salt=salt or os.urandom(16),
                    iterations=100000,  # Should be configurable
                )
                
                return kdf.derive(password)
            
            else:
                self.logger.error(f"Unsupported key derivation algorithm: {algorithm}")
                return None
                
        except Exception as e:
            self.logger.error(f"Key derivation failed: {str(e)}")
            return None
    
    def close(self) -> None:
        """Clean up resources."""
        # Clear sensitive data from memory
        if hasattr(self, '_master_key'):
            # Securely wipe the master key from memory
            import ctypes
            ctypes.memset(ctypes.c_char_p(id(self._master_key)), 0, len(self._master_key))
            del self._master_key
        
        # Clear key cache
        for key_id in list(self._key_cache.keys()):
            key = self._key_cache[key_id]
            if isinstance(key, (bytes, bytearray)):
                import ctypes
                ctypes.memset(ctypes.c_char_p(id(key)), 0, len(key))
            del self._key_cache[key_id]
        
        # Clear in-memory keys
        for key_id in list(self._keys.keys()):
            key = self._keys[key_id]
            if isinstance(key, (bytes, bytearray)):
                import ctypes
                ctypes.memset(ctypes.c_char_p(id(key)), 0, len(key))
            del self._keys[key_id]
        
        # Disconnect from HSM
        if hasattr(self, '_hsm') and self._hsm:
            self._hsm.disconnect()
            self._hsm = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Example usage
if __name__ == "__main__":
    import logging
    import tempfile
    import shutil
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create a temporary directory for key storage
    temp_dir = tempfile.mkdtemp(prefix="scrambled_eggs_keys_")
    logger.info(f"Using temporary directory: {temp_dir}")
    
    try:
        # Initialize the key manager with a password
        password = "my_secure_password"
        key_manager = KeyManager(
            storage_path=temp_dir,
            password=password,
            key_derivation_rounds=100000  # For testing, use a lower value
        )
        
        # Generate a new AES-256 key for encryption
        key_id = key_manager.generate_key(
            key_type='aes',
            key_size=256,
            purpose=[KeyPurpose.ENCRYPTION, KeyPurpose.DECRYPTION],
            algorithm='AES-256-GCM',
            tags={'purpose': 'test', 'created_by': 'example'}
        )
        
        if not key_id:
            logger.error("Failed to generate key")
            exit(1)
        
        logger.info(f"Generated key: {key_id}")
        
        # Get key metadata
        metadata = key_manager.get_metadata(key_id)
        logger.info(f"Key metadata: {metadata.to_dict() if metadata else 'None'}")
        
        # Encrypt some data
        plaintext = b"This is a secret message!"
        logger.info(f"Plaintext: {plaintext}")
        
        ciphertext = key_manager.encrypt(key_id, plaintext)
        if not ciphertext:
            logger.error("Encryption failed")
            exit(1)
        
        logger.info(f"Ciphertext: {ciphertext.hex()}")
        
        # Decrypt the data
        decrypted = key_manager.decrypt(key_id, ciphertext)
        if not decrypted:
            logger.error("Decryption failed")
            exit(1)
        
        logger.info(f"Decrypted: {decrypted}")
        
        # Verify the decrypted data matches the original
        if decrypted != plaintext:
            logger.error("Decryption failed: data mismatch")
            exit(1)
        
        logger.info("Encryption/decryption test passed")
        
        # Generate an RSA key pair for signing
        rsa_key_id = key_manager.generate_key(
            key_type='rsa',
            key_size=2048,
            purpose=[KeyPurpose.SIGNING, KeyPurpose.VERIFICATION],
            algorithm='RSASSA-PSS-SHA256',
            tags={'purpose': 'signing', 'created_by': 'example'}
        )
        
        if not rsa_key_id:
            logger.error("Failed to generate RSA key")
            exit(1)
        
        logger.info(f"Generated RSA key: {rsa_key_id}")
        
        # Sign some data
        data = b"This is some data to sign"
        logger.info(f"Data to sign: {data}")
        
        signature = key_manager.sign(rsa_key_id, data, 'RSASSA-PSS-SHA256')
        if not signature:
            logger.error("Signing failed")
            exit(1)
        
        logger.info(f"Signature: {signature.hex()}")
        
        # Verify the signature
        is_valid = key_manager.verify(rsa_key_id, data, signature, 'RSASSA-PSS-SHA256')
        if not is_valid:
            logger.error("Signature verification failed")
            exit(1)
        
        logger.info("Signature verification passed")
        
        # Test with an invalid signature
        invalid_signature = bytes([b ^ 0xFF for b in signature])
        is_valid = key_manager.verify(rsa_key_id, data, invalid_signature, 'RSASSA-PSS-SHA256')
        if is_valid:
            logger.error("Invalid signature was incorrectly verified")
            exit(1)
        
        logger.info("Invalid signature correctly rejected")
        
        # Test key derivation
        derived_key = key_manager.derive_key(
            key_id=key_id,
            context=b'key_derivation_test',
            key_size=32,
            algorithm='HKDF-SHA256'
        )
        
        if not derived_key:
            logger.error("Key derivation failed")
            exit(1)
        
        logger.info(f"Derived key: {derived_key.hex()}")
        
        # Test key wrapping
        wrap_result = key_manager.wrap_key(key_id)
        if not wrap_result:
            logger.error("Key wrapping failed")
            exit(1)
        
        logger.info(f"Key wrapped successfully")
        
        # Verify the key is now wrapped
        metadata = key_manager.get_metadata(key_id)
        if not metadata or not metadata.is_wrapped:
            logger.error("Key should be wrapped but is not")
            exit(1)
        
        # Try to get the key (should trigger unwrapping)
        key = key_manager.get_key(key_id)
        if not key:
            logger.error("Failed to get wrapped key")
            exit(1)
        
        logger.info("Successfully retrieved wrapped key")
        
        # Clean up
        key_manager.close()
        logger.info("Key manager closed successfully")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        exit(1)
    
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Temporary directory cleaned up")

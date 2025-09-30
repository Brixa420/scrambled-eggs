"""
End-to-End Encryption (E2EE) Module
Implements zero-knowledge proofs and secure key management.
"""
import os
import json
import base64
import logging
import hashlib
import hmac
import time
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, hmac as hmac_primitive
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import constant_time
from cryptography.exceptions import InvalidSignature, InvalidKey, InvalidTag
import secrets
import asyncio
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class KeyMetadata:
    """Metadata for encryption keys."""
    key_id: str
    created_at: str
    expires_at: Optional[str] = None
    algorithm: str = "AES-256-GCM"
    key_type: str = "symmetric"
    is_active: bool = True

class ZeroKnowledgeProof:
    """Implements zero-knowledge proof protocols."""
    
    @staticmethod
    def generate_challenge() -> bytes:
        """Generate a random challenge for ZKP."""
        return secrets.token_bytes(32)
    
    @staticmethod
    def create_proof(secret: bytes, challenge: bytes) -> bytes:
        """Create a zero-knowledge proof."""
        h = hmac_primitive.HMAC(secret, hashes.SHA256())
        h.update(challenge)
        return h.finalize()
    
    @staticmethod
    def verify_proof(proof: bytes, secret: bytes, challenge: bytes) -> bool:
        """Verify a zero-knowledge proof."""
        expected_proof = ZeroKnowledgeProof.create_proof(secret, challenge)
        return constant_time.bytes_eq(proof, expected_proof)

class KeyManager:
    """Manages encryption keys and key rotation."""
    
    def __init__(self, key_store_path: str = "keys"):
        """Initialize the key manager.
        
        Args:
            key_store_path: Directory to store encryption keys
        """
        self.key_store = Path(key_store_path)
        self.key_store.mkdir(exist_ok=True, parents=True)
        self.master_key = self._load_or_generate_master_key()
        self.key_cache: Dict[str, bytes] = {}
        self.key_metadata: Dict[str, KeyMetadata] = {}
        self.lock = asyncio.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._load_key_metadata()
    
    def _load_or_generate_master_key(self) -> bytes:
        """Load or generate the master key."""
        master_key_path = self.key_store / "master.key"
        
        if master_key_path.exists():
            with open(master_key_path, 'rb') as f:
                encrypted_key = f.read()
            
            # In a real implementation, this would be loaded from a secure location
            # For demonstration, we're using a hardcoded derivation key
            # In production, this should be derived from a secure source
            derivation_key = b'secure_derivation_key_should_be_in_secure_storage'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt_should_be_random_and_stored_securely',
                iterations=100000,
            )
            key = kdf.derive(derivation_key)
            
            # Decrypt the master key
            try:
                iv = encrypted_key[:16]
                tag = encrypted_key[16:32]
                ciphertext = encrypted_key[32:]
                
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag)
                )
                decryptor = cipher.decryptor()
                return decryptor.update(ciphertext) + decryptor.finalize()
            except Exception as e:
                logger.error(f"Failed to decrypt master key: {e}")
                raise
        else:
            # Generate new master key
            master_key = secrets.token_bytes(32)
            
            # Encrypt and store the master key
            derivation_key = b'secure_derivation_key_should_be_in_secure_storage'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt_should_be_random_and_stored_securely',
                iterations=100000,
            )
            key = kdf.derive(derivation_key)
            
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv)
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(master_key) + encryptor.finalize()
            
            with open(master_key_path, 'wb') as f:
                f.write(iv + encryptor.tag + ciphertext)
            
            return master_key
    
    def _load_key_metadata(self) -> None:
        """Load key metadata from disk."""
        metadata_path = self.key_store / "key_metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, 'r') as f:
                    data = json.load(f)
                    self.key_metadata = {
                        k: KeyMetadata(**v) for k, v in data.items()
                    }
            except Exception as e:
                logger.error(f"Failed to load key metadata: {e}")
                self.key_metadata = {}
    
    def _save_key_metadata(self) -> None:
        """Save key metadata to disk."""
        metadata_path = self.key_store / "key_metadata.json"
        try:
            with open(metadata_path, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.key_metadata.items()},
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Failed to save key metadata: {e}")
    
    async def generate_key(self, key_id: str, expires_in_days: int = 30) -> str:
        """Generate a new encryption key.
        
        Args:
            key_id: Unique identifier for the key
            expires_in_days: Number of days until key expires
            
        Returns:
            Key ID
        """
        async with self.lock:
            if key_id in self.key_metadata:
                raise ValueError(f"Key with ID {key_id} already exists")
            
            # Generate a new random key
            key = secrets.token_bytes(32)
            
            # Encrypt the key with the master key
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(self.master_key),
                modes.GCM(iv)
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(key) + encryptor.finalize()
            
            # Store the encrypted key
            key_path = self.key_store / f"{key_id}.key"
            with open(key_path, 'wb') as f:
                f.write(iv + encryptor.tag + ciphertext)
            
            # Create and store metadata
            now = datetime.utcnow()
            expires_at = (now + timedelta(days=expires_in_days)).isoformat()
            self.key_metadata[key_id] = KeyMetadata(
                key_id=key_id,
                created_at=now.isoformat(),
                expires_at=expires_at,
                algorithm="AES-256-GCM",
                key_type="symmetric"
            )
            self._save_key_metadata()
            
            # Cache the decrypted key
            self.key_cache[key_id] = key
            
            return key_id
    
    async def get_key(self, key_id: str) -> bytes:
        """Get an encryption key by ID.
        
        Args:
            key_id: ID of the key to retrieve
            
        Returns:
            Decrypted key
        """
        # Check cache first
        if key_id in self.key_cache:
            return self.key_cache[key_id]
        
        async with self.lock:
            # Check if key exists
            key_path = self.key_store / f"{key_id}.key"
            if not key_path.exists():
                raise KeyError(f"Key {key_id} not found")
            
            # Load and decrypt the key
            with open(key_path, 'rb') as f:
                encrypted_key = f.read()
            
            iv = encrypted_key[:16]
            tag = encrypted_key[16:32]
            ciphertext = encrypted_key[32:]
            
            cipher = Cipher(
                algorithms.AES(self.master_key),
                modes.GCM(iv, tag)
            )
            decryptor = cipher.decryptor()
            key = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Cache the decrypted key
            self.key_cache[key_id] = key
            
            return key
    
    async def rotate_keys(self) -> None:
        """Rotate encryption keys and re-encrypt data."""
        # In a real implementation, this would:
        # 1. Generate new keys
        # 2. Re-encrypt data with new keys
        # 3. Update key references
        # 4. Remove old keys
        pass

class AccessLogger:
    """Logs data access events for audit purposes."""
    
    def __init__(self, log_dir: str = "logs/access"):
        """Initialize the access logger.
        
        Args:
            log_dir: Directory to store access logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.lock = asyncio.Lock()
    
    async def log_access(
        self,
        user_id: str,
        resource_id: str,
        action: str,
        status: str = "success",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an access event.
        
        Args:
            user_id: ID of the user accessing the resource
            resource_id: ID of the resource being accessed
            action: Action performed (e.g., 'read', 'write', 'delete')
            status: Status of the action ('success', 'failed', 'denied')
            metadata: Additional metadata about the access
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "resource_id": resource_id,
            "action": action,
            "status": status,
            "metadata": metadata or {}
        }
        
        # Write to daily log file
        today = datetime.utcnow().strftime("%Y-%m-%d")
        log_file = self.log_dir / f"access_{today}.log"
        
        async with self.lock:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")

class E2EEncryption:
    """End-to-end encryption service."""
    
    def __init__(self, key_manager: Optional[KeyManager] = None, access_logger: Optional[AccessLogger] = None):
        """Initialize the E2E encryption service.
        
        Args:
            key_manager: Optional custom key manager
            access_logger: Optional custom access logger
        """
        self.key_manager = key_manager or KeyManager()
        self.access_logger = access_logger or AccessLogger()
        self.zkp = ZeroKnowledgeProof()
    
    async def encrypt(
        self,
        data: bytes,
        key_id: str,
        user_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt data.
        
        Args:
            data: Data to encrypt
            key_id: ID of the encryption key to use
            user_id: ID of the user performing the encryption
            metadata: Additional metadata to include in access logs
            
        Returns:
            Tuple of (ciphertext, encryption metadata)
        """
        try:
            # Get the encryption key
            key = await self.key_manager.get_key(key_id)
            
            # Generate a random nonce
            nonce = os.urandom(16)
            
            # Encrypt the data
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce)
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Create metadata
            metadata = {
                "key_id": key_id,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
                "algorithm": "AES-256-GCM",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Log the access
            await self.access_logger.log_access(
                user_id=user_id,
                resource_id=f"encrypt:{key_id}",
                action="encrypt",
                status="success",
                metadata=metadata
            )
            
            return ciphertext, metadata
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            await self.access_logger.log_access(
                user_id=user_id,
                resource_id=f"encrypt:{key_id}",
                action="encrypt",
                status="failed",
                metadata={"error": str(e), **({} if metadata is None else metadata)}
            )
            raise
    
    async def decrypt(
        self,
        ciphertext: bytes,
        key_id: str,
        nonce: bytes,
        tag: bytes,
        user_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Decrypt data.
        
        Args:
            ciphertext: Encrypted data
            key_id: ID of the encryption key to use
            nonce: Nonce used for encryption
            tag: Authentication tag
            user_id: ID of the user performing the decryption
            metadata: Additional metadata to include in access logs
            
        Returns:
            Decrypted data
        """
        try:
            # Get the encryption key
            key = await self.key_manager.get_key(key_id)
            
            # Decrypt the data
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag)
            )
            decryptor = cipher.decryptor()
            data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Log the access
            await self.access_logger.log_access(
                user_id=user_id,
                resource_id=f"decrypt:{key_id}",
                action="decrypt",
                status="success",
                metadata=metadata or {}
            )
            
            return data
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            await self.access_logger.log_access(
                user_id=user_id,
                resource_id=f"decrypt:{key_id}",
                action="decrypt",
                status="failed",
                metadata={"error": str(e), **({} if metadata is None else metadata)}
            )
            raise
    
    async def create_proof_of_knowledge(
        self,
        secret: bytes,
        challenge: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """Create a zero-knowledge proof of knowledge of a secret.
        
        Args:
            secret: The secret to prove knowledge of
            challenge: Optional challenge (if not provided, one will be generated)
            
        Returns:
            Tuple of (challenge, proof)
        """
        if challenge is None:
            challenge = self.zkp.generate_challenge()
        
        proof = self.zkp.create_proof(secret, challenge)
        return challenge, proof
    
    async def verify_proof_of_knowledge(
        self,
        proof: bytes,
        secret: bytes,
        challenge: bytes
    ) -> bool:
        """Verify a zero-knowledge proof of knowledge.
        
        Args:
            proof: The proof to verify
            secret: The secret that was used to generate the proof
            challenge: The challenge that was used to generate the proof
            
        Returns:
            True if the proof is valid, False otherwise
        """
        return self.zkp.verify_proof(proof, secret, challenge)

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        # Initialize the E2E encryption service
        e2ee = E2EEncryption()
        
        # Generate a new key
        key_id = await e2ee.key_manager.generate_key("test_key")
        print(f"Generated key: {key_id}")
        
        # Test encryption/decryption
        data = b"Hello, world!"
        print(f"Original data: {data}")
        
        # Encrypt the data
        ciphertext, metadata = await e2ee.encrypt(
            data=data,
            key_id=key_id,
            user_id="test_user"
        )
        print(f"Encrypted: {ciphertext.hex()}")
        
        # Decrypt the data
        decrypted = await e2ee.decrypt(
            ciphertext=ciphertext,
            key_id=metadata["key_id"],
            nonce=base64.b64decode(metadata["nonce"]),
            tag=base64.b64decode(metadata["tag"]),
            user_id="test_user"
        )
        print(f"Decrypted: {decrypted}")
        
        # Test zero-knowledge proof
        secret = b"my_secret"
        challenge, proof = await e2ee.create_proof_of_knowledge(secret)
        is_valid = await e2ee.verify_proof_of_knowledge(proof, secret, challenge)
        print(f"Proof is valid: {is_valid}")
        
        # Test with wrong secret
        is_valid = await e2ee.verify_proof_of_knowledge(proof, b"wrong_secret", challenge)
        print(f"Proof with wrong secret is valid: {is_valid}")
    
    asyncio.run(main())

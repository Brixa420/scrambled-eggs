import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .self_modifying import SecurityLevel, SelfModifyingEncryption

logger = logging.getLogger(__name__)


class KeyType(Enum):
    """Types of encryption keys."""

    SESSION = "session"
    IDENTITY = "identity"
    EPHEMERAL = "ephemeral"


@dataclass
class KeyMaterial:
    """Represents cryptographic key material."""

    key_type: KeyType
    key_data: bytes
    created: float
    expires: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            "key_type": self.key_type.value,
            "key_data": self.key_data.hex(),
            "created": self.created,
            "expires": self.expires,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMaterial":
        """Create from a dictionary."""
        return cls(
            key_type=KeyType(data["key_type"]),
            key_data=bytes.fromhex(data["key_data"]),
            created=data["created"],
            expires=data.get("expires"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class EncryptionResult:
    """Result of an encryption operation."""

    ciphertext: bytes
    key_id: str
    iv: bytes
    tag: bytes
    scheme_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            "ciphertext": self.ciphertext.hex(),
            "key_id": self.key_id,
            "iv": self.iv.hex(),
            "tag": self.tag.hex(),
            "scheme_id": self.scheme_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptionResult":
        """Create from a dictionary."""
        return cls(
            ciphertext=bytes.fromhex(data["ciphertext"]),
            key_id=data["key_id"],
            iv=bytes.fromhex(data["iv"]),
            tag=bytes.fromhex(data["tag"]),
            scheme_id=data["scheme_id"],
            metadata=data.get("metadata", {}),
        )


class CryptoEngine:
    """
    Handles all cryptographic operations with self-modifying capabilities.

    This engine automatically adjusts its encryption schemes based on
    security events and detected threats.
    """

    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        """
        Initialize the crypto engine.

        Args:
            security_level: Initial security level
        """
        # Initialize self-modifying encryption system
        self.sme = SelfModifyingEncryption(initial_level=security_level)

        # Key management
        self.identity_keys = self._generate_identity_keys()
        self.session_keys: Dict[str, KeyMaterial] = {}
        self.ephemeral_keys: Dict[str, KeyMaterial] = {}
        self.key_store: Dict[str, Dict[str, Any]] = {}

        # Initialize the current scheme
        self.current_scheme = self.sme.current_scheme
        logger.info(f"Initialized crypto engine at {security_level.name} security level")

        # Generate initial session key
        self.rotate_session_key()

    def _generate_identity_keys(self) -> Dict[str, Any]:
        """Generate long-term identity keys."""
        # Generate X25519 key for key exchange
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()

        # Generate Ed25519 key for signing
        ed25519_private = ec.generate_private_key(ec.SECP256K1())
        ed25519_public = ed25519_private.public_key()

        return {
            "x25519_private": x25519_private,
            "x25519_public": x25519_public,
            "ed25519_private": ed25519_private,
            "ed25519_public": ed25519_public,
        }

    def get_public_keys(self) -> Dict[str, bytes]:
        """Get public keys for key exchange."""
        x25519_pub_bytes = self.identity_keys["x25519_public"].public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        ed25519_pub_bytes = self.identity_keys["ed25519_public"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {"x25519": x25519_pub_bytes, "ed25519": ed25519_pub_bytes}

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate a new key pair for ECDH key exchange."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize public key for transmission
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        return private_key, pub_bytes

    def derive_shared_secret(
        self, private_key: x25519.X25519PrivateKey, peer_public_key: bytes
    ) -> bytes:
        """Derive a shared secret using ECDH."""
        try:
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
            shared_key = private_key.exchange(peer_key)

            # Derive a secure key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"scrambled-eggs-key-derivation",
                backend=default_backend(),
            ).derive(shared_key)

            return derived_key
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise

    def rotate_session_key(self) -> str:
        """
        Generate a new session key.

        Returns:
            str: The ID of the new session key
        """
        # Generate a new random key
        key_id = f"session_{int(time.time())}"
        key_data = os.urandom(32)  # 256-bit key

        # Store the key
        self.session_keys[key_id] = KeyMaterial(
            key_type=KeyType.SESSION,
            key_data=key_data,
            created=time.time(),
            expires=time.time() + 3600,  # Expire in 1 hour
            metadata={
                "scheme_id": self.current_scheme.scheme_id,
                "security_level": self.sme.current_level.name,
            },
        )

        # Log the key rotation
        logger.info(f"Rotated session key: {key_id}")
        return key_id

    def _derive_key(self, key_material: bytes, info: bytes, length: int = 32) -> bytes:
        """
        Derive a key using HKDF.

        Args:
            key_material: Input key material
            info: Context and application specific info
            length: Length of the derived key in bytes

        Returns:
            bytes: Derived key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(key_material)

    def encrypt_message(
        self,
        plaintext: bytes,
        key: Optional[bytes] = None,
        key_id: Optional[str] = None,
        associated_data: Optional[bytes] = None,
    ) -> EncryptionResult:
        """
        Encrypt a message using the current encryption scheme.

        Args:
            plaintext: The data to encrypt
            key: Optional encryption key (if None, a session key will be used)
            key_id: Optional key ID (if None, one will be generated)
            associated_data: Optional additional authenticated data

        Returns:
            EncryptionResult containing the encrypted data and metadata
        """
        try:
            scheme = self.current_scheme

            # Generate or use provided key
            if key is None:
                # Use the most recent session key or generate a new one
                if not self.session_keys:
                    key_id = self.rotate_session_key()
                else:
                    key_id = max(self.session_keys.keys())
                key_material = self.session_keys[key_id]
                key = key_material.key_data
            else:
                # Use the provided key and generate a key ID if not provided
                key_material = KeyMaterial(
                    key_type=KeyType.EPHEMERAL,
                    key_data=key,
                    created=time.time(),
                    expires=time.time() + 3600,  # Expire in 1 hour
                )
                if key_id is None:
                    key_id = f"ephemeral_{int(time.time())}"
                self.ephemeral_keys[key_id] = key_material

            # Generate IV based on the scheme's requirements
            iv = os.urandom(scheme.iv_size)

            # Create the appropriate cipher and mode
            cipher_algorithm = scheme.cipher(key)
            mode_instance = scheme.mode(iv)

            # Create encryptor
            encryptor = Cipher(
                cipher_algorithm, mode_instance, backend=default_backend()
            ).encryptor()

            # Add associated data if provided and the mode supports it
            if associated_data and hasattr(encryptor, "authenticate_additional_data"):
                encryptor.authenticate_additional_data(associated_data)

            # Encrypt the data
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Get the authentication tag if the mode uses it
            tag = getattr(encryptor, "tag", None)

            # Create the result with all necessary metadata
            return EncryptionResult(
                ciphertext=ciphertext,
                key_id=key_id,
                iv=iv,
                tag=tag or b"",  # Some modes don't use tags
                scheme_id=scheme.scheme_id,
                metadata={
                    "version": "1.0",
                    "algorithm": f"{cipher_algorithm.name.upper()}-{mode_instance.name.upper()}",
                    "key_size": scheme.key_size,
                    "iv_size": scheme.iv_size,
                    "hash_algorithm": scheme.hash_algorithm.name,
                    "key_type": key_material.key_type.value,
                    "key_created": key_material.created,
                    "key_expires": key_material.expires,
                },
            )

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            # Log the security event
            self.handle_security_event(
                event_type="encryption_failure",
                severity=SecurityLevel.HIGH,
                description=f"Encryption failed: {str(e)}",
                details={
                    "exception_type": type(e).__name__,
                    "scheme_id": getattr(scheme, "scheme_id", "unknown"),
                },
            )
            raise

    def _detect_breach(self, data: bytes) -> bool:
        """
        Detect potential security breaches in encrypted data.

        Args:
            data: The data to check

        Returns:
            bool: True if a breach is detected, False otherwise
        """
        return self.sme.detect_breach(data)

    def handle_security_event(
        self,
        event_type: str,
        severity: SecurityLevel,
        description: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Handle a security event that might trigger encryption scheme changes.

        Args:
            event_type: Type of security event
            severity: Severity level
            description: Description of the event
            details: Additional event details
        """
        self.sme.log_security_event(event_type, severity, description, details)

        # If the security level changed, update our scheme
        if self.current_scheme.scheme_id != self.sme.current_scheme.scheme_id:
            self.current_scheme = self.sme.current_scheme
            logger.warning(f"Encryption scheme changed to: {self.current_scheme.scheme_id}")

            # Rotate session keys when the scheme changes
            self.rotate_session_key()

    def get_security_status(self) -> Dict[str, Any]:
        """
        Get the current security status.

        Returns:
            Dict containing security status information
        """
        status = self.sme.get_security_status()
        status.update(
            {
                "active_session_keys": len(self.session_keys),
                "active_ephemeral_keys": len(self.ephemeral_keys),
                "current_scheme": self.current_scheme.scheme_id,
                "security_level": self.sme.current_level.name,
            }
        )
        return status

    def decrypt_message(
        self,
        ciphertext: bytes,
        key: Optional[bytes] = None,
        key_id: Optional[str] = None,
        iv: Optional[bytes] = None,
        tag: Optional[bytes] = None,
        scheme_id: Optional[str] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt a message using the appropriate encryption scheme.

        Args:
            ciphertext: The encrypted data
            key: The decryption key (if None, will be looked up by key_id)
            key_id: ID of the key to use for decryption
            iv: Initialization vector
            tag: Authentication tag (for AEAD modes)
            scheme_id: ID of the encryption scheme used
            associated_data: Additional authenticated data

        Returns:
            The decrypted plaintext

        Raises:
            ValueError: If decryption fails or required parameters are missing
            KeyError: If the key_id is not found
        """
        try:
            # Look up the key if not provided
            if key is None and key_id:
                # First try session keys
                if key_id in self.session_keys:
                    key_material = self.session_keys[key_id]
                # Then try ephemeral keys
                elif key_id in self.ephemeral_keys:
                    key_material = self.ephemeral_keys[key_id]
                else:
                    raise KeyError(f"Key not found: {key_id}")
                key = key_material.key_data
            elif key is None:
                raise ValueError("Either key or key_id must be provided")

            # Get the scheme - use current scheme if not specified
            scheme = None
            if scheme_id:
                # In a real implementation, we'd look up the scheme by ID
                # For now, we'll just log it and use the current scheme
                logger.debug(f"Using scheme from message: {scheme_id}")
                scheme = self.current_scheme
            else:
                scheme = self.current_scheme

            # Validate required parameters
            if iv is None:
                raise ValueError("IV is required for decryption")

            # For modes that require a tag but none was provided
            if tag is None and hasattr(scheme.mode, "requires_tag") and scheme.mode.requires_tag:
                raise ValueError("Authentication tag is required for this encryption mode")

            # Create the appropriate cipher and mode
            cipher_algorithm = scheme.cipher(key)

            # Handle different modes appropriately
            if tag is not None and hasattr(scheme.mode, "requires_tag"):
                # AEAD mode with tag (like GCM)
                mode_instance = scheme.mode(iv, tag)
            else:
                # Non-AEAD mode (like CBC)
                mode_instance = scheme.mode(iv)

            # Create decryptor
            decryptor = Cipher(
                cipher_algorithm, mode_instance, backend=default_backend()
            ).decryptor()

            # Add associated data if provided and the mode supports it
            if associated_data and hasattr(decryptor, "authenticate_additional_data"):
                decryptor.authenticate_additional_data(associated_data)

            # Decrypt the data
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return plaintext

            except InvalidTag as e:
                # This could indicate a tampering attempt
                self.handle_security_event(
                    event_type="decryption_failure",
                    severity=SecurityLevel.HIGH,
                    description="Authentication tag verification failed",
                    details={"key_id": key_id, "scheme_id": scheme.scheme_id, "exception": str(e)},
                )
                raise ValueError(
                    "Message authentication failed - the message may have been tampered with"
                )

        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            # Log the security event
            self.handle_security_event(
                event_type="decryption_failure",
                severity=SecurityLevel.HIGH,
                description=f"Decryption failed: {str(e)}",
                details={
                    "exception_type": type(e).__name__,
                    "key_id": key_id,
                    "scheme_id": scheme_id or "unknown",
                },
            )
            raise

    def sign_message(self, message: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Sign a message using ECDSA."""
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(
        self, message: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        """Verify a message signature."""
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

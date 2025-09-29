"""
Crypto Engine

Handles all cryptographic operations including encryption, decryption, and key management.
"""

import base64
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

logger = logging.getLogger(__name__)


@dataclass
class KeyPair:
    """Represents a public/private key pair."""

    public_key: bytes
    private_key: Optional[bytes] = None


class CryptoEngine:
    """
    Cryptographic engine for handling encryption, decryption, and key management.
    """

    # Constants
    AES_KEY_SIZE = 32  # 256 bits
    IV_SIZE = 16  # 128 bits
    SALT_SIZE = 16  # 128 bits
    ITERATIONS = 100000  # For PBKDF2
    HASH_ALGORITHM = hashes.SHA256
    SYMMETRIC_ALGORITHM = algorithms.AES
    SYMMETRIC_MODE = modes.CBC
    ASYMMETRIC_PADDING = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the crypto engine.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self._key_pairs: Dict[str, KeyPair] = {}
        self._symmetric_keys: Dict[str, bytes] = {}

        # Initialize with default key pair if none exists
        if not self._key_pairs.get("default"):
            self._generate_key_pair("default")

    def _generate_key_pair(self, key_id: str) -> KeyPair:
        """
        Generate a new RSA key pair.

        Args:
            key_id: Unique identifier for the key pair

        Returns:
            Generated KeyPair
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        key_pair = KeyPair(public_key=public_pem, private_key=private_pem)
        self._key_pairs[key_id] = key_pair
        return key_pair

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """
        Derive a symmetric key from a password and salt.

        Args:
            password: The password to derive the key from
            salt: Random salt

        Returns:
            Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=self.HASH_ALGORITHM(),
            length=self.AES_KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(password)

    def encrypt_symmetric(self, data: bytes, key_id: str) -> bytes:
        """
        Encrypt data using a symmetric key.

        Args:
            data: Data to encrypt
            key_id: ID of the symmetric key to use

        Returns:
            Encrypted data with IV prepended
        """
        if key_id not in self._symmetric_keys:
            raise ValueError(f"Symmetric key '{key_id}' not found")

        key = self._symmetric_keys[key_id]
        iv = os.urandom(self.IV_SIZE)

        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt
        cipher = Cipher(self.SYMMETRIC_ALGORITHM(key), self.SYMMETRIC_MODE(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Return IV + encrypted data
        return iv + encrypted

    def decrypt_symmetric(self, data: bytes, key_id: str) -> bytes:
        """
        Decrypt data using a symmetric key.

        Args:
            data: Data to decrypt (with IV prepended)
            key_id: ID of the symmetric key to use

        Returns:
            Decrypted data
        """
        if key_id not in self._symmetric_keys:
            raise ValueError(f"Symmetric key '{key_id}' not found")

        if len(data) < self.IV_SIZE:
            raise ValueError("Invalid encrypted data: too short")

        key = self._symmetric_keys[key_id]
        iv = data[: self.IV_SIZE]
        encrypted = data[self.IV_SIZE :]

        # Decrypt
        cipher = Cipher(self.SYMMETRIC_ALGORITHM(key), self.SYMMETRIC_MODE(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def encrypt_asymmetric(self, data: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt data using a public key.

        Args:
            data: Data to encrypt
            public_key_pem: PEM-encoded public key

        Returns:
            Encrypted data
        """
        public_key = load_pem_public_key(public_key_pem)
        return public_key.encrypt(data, self.ASYMMETRIC_PADDING)

    def decrypt_asymmetric(self, data: bytes, key_id: str) -> bytes:
        """
        Decrypt data using a private key.

        Args:
            data: Data to decrypt
            key_id: ID of the key pair to use

        Returns:
            Decrypted data
        """
        if key_id not in self._key_pairs or not self._key_pairs[key_id].private_key:
            raise ValueError(f"Private key '{key_id}' not found")

        private_key = load_pem_private_key(self._key_pairs[key_id].private_key, password=None)

        return private_key.decrypt(data, self.ASYMMETRIC_PADDING)

    def sign(self, data: bytes, key_id: str) -> bytes:
        """
        Sign data using a private key.

        Args:
            data: Data to sign
            key_id: ID of the key pair to use

        Returns:
            Signature
        """
        if key_id not in self._key_pairs or not self._key_pairs[key_id].private_key:
            raise ValueError(f"Private key '{key_id}' not found")

        private_key = load_pem_private_key(self._key_pairs[key_id].private_key, password=None)

        return private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

    def verify(self, data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        """
        Verify a signature.

        Args:
            data: Data that was signed
            signature: Signature to verify
            public_key_pem: PEM-encoded public key

        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            public_key = load_pem_public_key(public_key_pem)
            public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, InvalidKey):
            return False

    def generate_symmetric_key(self, key_id: str, size: int = 32) -> bytes:
        """
        Generate a new symmetric key.

        Args:
            key_id: ID to associate with the key
            size: Key size in bytes (default: 32)

        Returns:
            Generated key
        """
        key = os.urandom(size)
        self._symmetric_keys[key_id] = key
        return key

    def get_public_key(self, key_id: str = "default") -> bytes:
        """
        Get a public key in PEM format.

        Args:
            key_id: ID of the key pair

        Returns:
            PEM-encoded public key
        """
        if key_id not in self._key_pairs:
            self._generate_key_pair(key_id)
        return self._key_pairs[key_id].public_key

    def export_key_pair(self, key_id: str, password: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Export a key pair for storage.

        Args:
            key_id: ID of the key pair to export
            password: Optional password for encryption

        Returns:
            Dictionary containing 'public_key' and 'private_key'
        """
        if key_id not in self._key_pairs:
            raise ValueError(f"Key pair '{key_id}' not found")

        key_pair = self._key_pairs[key_id]

        if not key_pair.private_key:
            raise ValueError(f"Private key for '{key_id}' not available")

        result = {"public_key": key_pair.public_key, "private_key": key_pair.private_key}

        return result

    def import_key_pair(
        self, key_id: str, public_key: bytes, private_key: Optional[bytes] = None
    ) -> None:
        """
        Import a key pair.

        Args:
            key_id: ID to associate with the key pair
            public_key: PEM-encoded public key
            private_key: Optional PEM-encoded private key
        """
        self._key_pairs[key_id] = KeyPair(public_key=public_key, private_key=private_key)

    def encrypt_message(self, message: str, recipient_public_key: bytes) -> Dict[str, Any]:
        """
        Encrypt a message for a recipient.

        Args:
            message: Message to encrypt
            recipient_public_key: Recipient's public key in PEM format

        Returns:
            Dictionary containing encrypted data and metadata
        """
        # Generate a random symmetric key for this message
        session_key = os.urandom(self.AES_KEY_SIZE)
        session_key_id = f"session_{os.urandom(8).hex()}"
        self._symmetric_keys[session_key_id] = session_key

        # Encrypt the message with the symmetric key
        iv = os.urandom(self.IV_SIZE)

        # Pad the message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode("utf-8")) + padder.finalize()

        # Encrypt
        cipher = Cipher(self.SYMMETRIC_ALGORITHM(session_key), self.SYMMETRIC_MODE(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        # Encrypt the session key with the recipient's public key
        encrypted_key = self.encrypt_asymmetric(session_key, recipient_public_key)

        # Sign the message
        signature = self.sign(encrypted_message + iv + encrypted_key, "default")

        return {
            "version": "1.0",
            "ciphertext": base64.b64encode(encrypted_message).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
            "sender_public_key": self.get_public_key("default").decode("utf-8"),
        }

    def decrypt_message(self, message_data: Dict[str, Any]) -> str:
        """
        Decrypt a message.

        Args:
            message_data: Dictionary containing encrypted message data

        Returns:
            Decrypted message
        """
        # Extract and decode the message components
        encrypted_message = base64.b64decode(message_data["ciphertext"])
        iv = base64.b64decode(message_data["iv"])
        encrypted_key = base64.b64decode(message_data["encrypted_key"])
        signature = base64.b64decode(message_data["signature"])
        sender_public_key = message_data["sender_public_key"].encode("utf-8")

        # Verify the signature
        if not self.verify(encrypted_message + iv + encrypted_key, signature, sender_public_key):
            raise ValueError("Invalid signature")

        # Decrypt the session key
        session_key = self.decrypt_asymmetric(encrypted_key, "default")

        # Decrypt the message
        cipher = Cipher(self.SYMMETRIC_ALGORITHM(session_key), self.SYMMETRIC_MODE(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode("utf-8")

"""
ScrambledEggsCrypto Implementation

This module contains the ScrambledEggsCrypto class which provides
multi-layered encryption and decryption functionality.
"""

import base64
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encryption_layer import EncryptionLayer

# Import the EncryptionResult class first to avoid circular imports
from .encryption_result import EncryptionResult as EncryptionResultClass

# Lazy import key manager to prevent circular imports
_key_manager_instance = None


def get_key_manager():
    global _key_manager_instance
    if _key_manager_instance is None:
        from app.services.key_management import KeyManager

        _key_manager_instance = KeyManager()
    return _key_manager_instance


from app.core.exceptions import DecryptionError, EncryptionError, KeyManagementError

# Type alias for backward compatibility
EncryptionResult = Dict[str, Any]

logger = logging.getLogger(__name__)


class ScrambledEggsCrypto:
    """
    Implementation of the Scrambled Eggs encryption scheme.

    This class provides methods for encrypting and decrypting data using a
    multi-layered encryption approach with secure key derivation and key management.
    """

    # Constants for key derivation
    DEFAULT_KEY_SIZE = 32  # 256 bits
    DEFAULT_ITERATIONS = 100000
    DEFAULT_SALT_SIZE = 16

    def __init__(self):
        """Initialize the ScrambledEggsCrypto instance."""
        self.key_manager = get_key_manager()
        self.default_layer = EncryptionLayer.SCRAMBLED_EGGS

    def encrypt(
        self,
        data: bytes,
        key: Optional[bytes] = None,
        layer: Optional[EncryptionLayer] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Encrypt data using the specified encryption layer.

        Args:
            data: The data to encrypt
            key: Optional encryption key (generated if not provided)
            layer: Encryption layer to use (defaults to SCRAMBLED_EGGS)
            **kwargs: Additional encryption parameters

        Returns:
            Dictionary containing the encrypted data and metadata

        Raises:
            EncryptionError: If encryption fails
        """
        if layer is None:
            layer = self.default_layer

        try:
            # If no key is provided, generate a new one
            key_id = None
            if key is None:
                key_id = self.key_manager.generate_key()
                key = self.key_manager.get_key(key_id)
            elif isinstance(key, str):
                # If key is a string, assume it's a key ID
                key_id = key
                key = self.key_manager.get_key(key_id)
            elif not isinstance(key, bytes):
                # Convert key to bytes if it's not already
                key = key.encode("utf-8") if isinstance(key, str) else bytes(key)

            if layer == EncryptionLayer.SCRAMBLED_EGGS:
                return self._encrypt_scrambled_eggs(data, key, **kwargs)
            elif layer == EncryptionLayer.AES_256_GCM:
                return self._encrypt_aes_256_gcm(data, key, **kwargs)
                raise EncryptionError(f"Unsupported encryption layer: {layer}")
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt(
        self, encrypted_data: Dict[str, Any], key: Optional[Union[bytes, str]] = None
    ) -> bytes:
        """
        Decrypt data using the appropriate algorithm based on the encrypted data.

        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            key: The encryption key (can be key bytes, key ID string, or None to use key from metadata)

        Returns:
            The decrypted data

        Raises:
            DecryptionError: If decryption fails
            KeyManagementError: If key retrieval fails
        """
        try:
            # Get the encryption layer/algorithm
            layer_str = encrypted_data.get("algorithm")
            if not layer_str:
                raise DecryptionError("No encryption algorithm specified in encrypted data")

            # Convert string to EncryptionLayer enum
            try:
                layer = EncryptionLayer(layer_str)
            except ValueError:
                raise DecryptionError(f"Invalid encryption algorithm: {layer_str}")

            # Get the key ID from metadata if available
            key_id = encrypted_data.get("key_id")

            # Handle key retrieval
            if key is None and key_id:
                # Get key by ID if no key provided but key_id is in metadata
                key = self.key_manager.get_key(key_id)
            elif isinstance(key, str):
                # If key is a string, treat it as a key ID
                key = self.key_manager.get_key(key)
            elif not isinstance(key, bytes):
                # Convert key to bytes if it's not already
                key = key.encode("utf-8") if isinstance(key, str) else bytes(key)

            if not key:
                raise DecryptionError("No decryption key provided and none found in metadata")

            # Decrypt using the appropriate method
            if layer == EncryptionLayer.SCRAMBLED_EGGS:
                return self._decrypt_scrambled_eggs(encrypted_data, key)
            elif layer == EncryptionLayer.AES_256_GCM:
                return self._decrypt_aes_256_gcm(encrypted_data, key)
            else:
                raise DecryptionError(f"Unsupported encryption layer: {layer}")

        except KeyManagementError as e:
            logger.error(f"Key management error during decryption: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise DecryptionError(f"Decryption failed: {str(e)}")

    def _encrypt_scrambled_eggs(self, data: bytes, key: bytes, **kwargs) -> "EncryptionResultClass":
        """
        Encrypt data using the Scrambled Eggs encryption scheme.

        Args:
            data: The data to encrypt
            key: The encryption key
            **kwargs: Additional encryption parameters

        Returns:
            Dictionary containing the encrypted data and metadata
        """
        # Generate a random salt
        salt = os.urandom(self.DEFAULT_SALT_SIZE)

        # Derive encryption and authentication keys
        enc_key, auth_key = self._derive_keys(key, salt)

        # Generate a random IV
        iv = os.urandom(12)  # 96 bits for AES-GCM

        # Encrypt the data using AES-GCM
        cipher = AESGCM(enc_key)
        ciphertext = cipher.encrypt(iv, data, None)

        # The ciphertext includes the tag at the end
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        # Create the result dictionary
        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "auth_tag": base64.b64encode(tag).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "algorithm": EncryptionLayer.SCRAMBLED_EGGS,
            "key_id": kwargs.get("key_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0",
        }

    def _decrypt_scrambled_eggs(self, encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """
        Decrypt data using the Scrambled Eggs encryption scheme.

        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            key: The decryption key (must be bytes)

        Returns:
            The decrypted data

        Raises:
            DecryptionError: If decryption fails
        """
        if not isinstance(key, bytes):
            raise DecryptionError("Decryption key must be bytes")

        try:
            # Extract the encrypted data and metadata with validation
            required_fields = ["ciphertext", "iv", "auth_tag", "salt"]
            for field in required_fields:
                if field not in encrypted_data:
                    raise DecryptionError(f"Missing required field: {field}")

            # Decode base64 fields
            try:
                ciphertext = base64.b64decode(encrypted_data["ciphertext"])
                iv = base64.b64decode(encrypted_data["iv"])
                tag = base64.b64decode(encrypted_data["auth_tag"])
                salt = base64.b64decode(encrypted_data["salt"])
            except (TypeError, ValueError) as e:
                raise DecryptionError(f"Invalid base64 data: {str(e)}")

            # Validate key and salt
            if not key:
                raise DecryptionError("Empty decryption key")
            if not salt:
                raise DecryptionError("Invalid salt in encrypted data")

            # Derive the encryption and authentication keys
            try:
                enc_key, auth_key = self._derive_keys(key, salt)
            except Exception as e:
                raise DecryptionError(f"Key derivation failed: {str(e)}")

            # Decrypt the data using AES-GCM
            try:
                cipher = AESGCM(enc_key)
                # Combine the ciphertext and tag
                ciphertext_with_tag = ciphertext + tag
                # Decrypt the data
                return cipher.decrypt(iv, ciphertext_with_tag, None)
            except InvalidTag:
                raise DecryptionError(
                    "Invalid authentication tag - the key may be incorrect or data corrupted"
                )
            except Exception as e:
                raise DecryptionError(f"Decryption operation failed: {str(e)}")

        except DecryptionError:
            raise  # Re-raise our custom exceptions
        except Exception as e:
            logger.exception("Unexpected error during decryption")
            raise DecryptionError(f"Decryption failed: {str(e)}")

    def _encrypt_aes_256_gcm(self, data: bytes, key: bytes, **kwargs) -> "EncryptionResultClass":
        """
        Encrypt data using AES-256-GCM.

        Args:
            data: The data to encrypt
            key: The encryption key
            **kwargs: Additional encryption parameters

        Returns:
            Dictionary containing the encrypted data and metadata
        """
        # Generate a random IV
        iv = os.urandom(12)  # 96 bits for AES-GCM

        # Encrypt the data using AES-GCM
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(iv, data, None)

        # The ciphertext includes the tag at the end
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        # Create the result dictionary
        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "auth_tag": base64.b64encode(tag).decode("utf-8"),
            "algorithm": EncryptionLayer.AES_256_GCM,
            "key_id": kwargs.get("key_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0",
        }

    def _decrypt_aes_256_gcm(self, encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            key: The decryption key

        Returns:
            The decrypted data

        Raises:
            DecryptionError: If decryption fails
        """
        try:
            # Extract the encrypted data and metadata
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            iv = base64.b64decode(encrypted_data["iv"])
            tag = base64.b64decode(encrypted_data["auth_tag"])

            # Combine the ciphertext and tag
            ciphertext_with_tag = ciphertext + tag

            # Decrypt the data using AES-GCM
            cipher = AESGCM(key)

            try:
                decrypted_data = cipher.decrypt(iv, ciphertext_with_tag, None)
                return decrypted_data
            except InvalidTag:
                raise DecryptionError("Invalid authentication tag")

        except KeyError as e:
            raise DecryptionError(f"Missing required field: {str(e)}")
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}")

    def _derive_keys(self, key: bytes, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Derive encryption and authentication keys from a master key.

        Args:
            key: The master key
            salt: The salt to use for key derivation

        Returns:
            A tuple containing (encryption_key, authentication_key)
        """
        # Use HKDF to derive keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption key + 32 bytes for auth key
            salt=salt,
            info=b"scrambled-eggs-key-derivation",
        )

        derived_key = hkdf.derive(key)

        # Split the derived key into encryption and authentication keys
        enc_key = derived_key[:32]
        auth_key = derived_key[32:]

        return enc_key, auth_key


# Helper function for HKDF
def HKDF(algorithm, length, salt, info, backend=None):
    """
    HKDF key derivation function.

    Args:
        algorithm: The hash algorithm to use
        length: The length of the derived key in bytes
        salt: The salt to use for key derivation
        info: The info parameter for HKDF
        backend: The cryptography backend to use

    Returns:
        The derived key
    """
    if backend is None:
        from cryptography.hazmat.backends import default_backend

        backend = default_backend()

    # Use the HKDF implementation from cryptography.hazmat.primitives.kdf.hkdf
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as HKDFImpl

    hkdf = HKDFImpl(algorithm=algorithm, length=length, salt=salt, info=info, backend=backend)

    return hkdf

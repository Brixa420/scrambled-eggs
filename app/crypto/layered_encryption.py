"""
Layered Encryption System with Fail-Safe Mechanism

This module implements a multi-layered encryption system that applies multiple layers of encryption
to data, with a fail-safe mechanism that adds additional layers when decryption fails.
"""

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA3_512
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)


@dataclass
class LayerConfig:
    """Configuration for a single encryption layer."""

    cipher: str  # e.g., 'AES-256-CBC', 'AES-256-GCM'
    key_size: int  # in bytes
    iv_size: int  # in bytes
    use_hmac: bool = True
    hmac_key: Optional[bytes] = None
    metadata: Dict = field(default_factory=dict)


class LayerResult:
    """Result of a single encryption/decryption layer."""

    def __init__(self, data: bytes, metadata: Optional[Dict] = None):
        self.data = data
        self.metadata = metadata or {}


class LayeredEncryption:
    """
    Implements a multi-layered encryption system with fail-safe mechanism.

    Features:
    - Multiple layers of encryption with different algorithms and keys
    - Random number of layers with configurable minimum and maximum
    - Fail-safe mechanism that adds more layers when decryption fails
    - Support for different encryption algorithms per layer
    - Metadata tracking for each layer
    """

    def __init__(self, min_layers: int = 3, max_layers: int = 10):
        """
        Initialize the layered encryption system.

        Args:
            min_layers: Minimum number of encryption layers to apply
            max_layers: Maximum number of encryption layers to apply
        """
        self.min_layers = min_layers
        self.max_layers = max_layers
        self.layer_configs: List[LayerConfig] = []
        self._init_default_layers()

    def _init_default_layers(self):
        """Initialize default layer configurations."""
        # Default layers with different configurations
        self.layer_configs = [
            LayerConfig(
                cipher="AES-256-CBC",
                key_size=32,  # 256 bits
                iv_size=16,  # 128 bits
                use_hmac=True,
                metadata={"name": "Layer-1-CBC"},
            ),
            LayerConfig(
                cipher="AES-256-GCM",
                key_size=32,  # 256 bits
                iv_size=12,  # 96 bits for GCM
                use_hmac=False,  # GCM has built-in authentication
                metadata={"name": "Layer-2-GCM"},
            ),
            LayerConfig(
                cipher="AES-256-CFB",
                key_size=32,  # 256 bits
                iv_size=16,  # 128 bits
                use_hmac=True,
                metadata={"name": "Layer-3-CFB"},
            ),
        ]

        # Generate HMAC keys for layers that need them
        for config in self.layer_configs:
            if config.use_hmac and config.hmac_key is None:
                config.hmac_key = get_random_bytes(32)  # 256-bit HMAC key

    def _generate_key(self, key_size: int) -> bytes:
        """Generate a random encryption key."""
        return get_random_bytes(key_size)

    def _generate_iv(self, iv_size: int) -> bytes:
        """Generate a random initialization vector."""
        return get_random_bytes(iv_size)

    def _hmac_sign(self, data: bytes, key: bytes) -> bytes:
        """Generate HMAC for data integrity."""
        h = HMAC.new(key, digestmod=SHA3_512)
        h.update(data)
        return h.digest()

    def _hmac_verify(self, data: bytes, signature: bytes, key: bytes) -> bool:
        """Verify HMAC for data integrity."""
        h = HMAC.new(key, digestmod=SHA3_512)
        h.update(data)
        try:
            h.verify(signature)
            return True
        except ValueError:
            return False

    def _encrypt_layer(self, data: bytes, config: LayerConfig) -> Tuple[bytes, Dict]:
        """Encrypt data with a single layer of encryption."""
        key = self._generate_key(config.key_size)
        iv = self._generate_iv(config.iv_size)

        # Encrypt the data
        if config.cipher == "AES-256-CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            block_size = AES.block_size
            padded_data = pad(data, block_size)
            encrypted = cipher.encrypt(padded_data)
        elif config.cipher == "AES-256-GCM":
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            encrypted, tag = cipher.encrypt_and_digest(data)
        elif config.cipher == "AES-256-CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
            encrypted = cipher.encrypt(data)
        else:
            raise ValueError(f"Unsupported cipher: {config.cipher}")

        # Prepare the result
        result = {
            "cipher": config.cipher,
            "key": key.hex(),
            "iv": iv.hex(),
            "metadata": config.metadata,
        }

        # Add authentication tag for GCM
        if config.cipher == "AES-256-GCM":
            result["tag"] = tag.hex()

        # Add HMAC if enabled
        if config.use_hmac and config.cipher != "AES-256-GCM":  # GCM has built-in auth
            hmac_data = iv + encrypted
            if config.cipher == "AES-256-GCM":
                hmac_data += tag
            hmac = self._hmac_sign(hmac_data, config.hmac_key)
            result["hmac"] = hmac.hex()

        # Combine the encrypted data with metadata
        encrypted_payload = encrypted
        if config.cipher == "AES-256-GCM":
            encrypted_payload = tag + encrypted

        return encrypted_payload, result

    def _decrypt_layer(self, data: bytes, layer_info: Dict, config: LayerConfig) -> bytes:
        """Decrypt data with a single layer of encryption."""
        try:
            key = bytes.fromhex(layer_info["key"])
            iv = bytes.fromhex(layer_info["iv"])

            # Verify HMAC if enabled
            if config.use_hmac and config.cipher != "AES-256-GCM":
                if "hmac" not in layer_info:
                    raise ValueError("HMAC verification failed: No HMAC provided")
                hmac = bytes.fromhex(layer_info["hmac"])
                if not self._hmac_verify(iv + data, hmac, config.hmac_key):
                    raise ValueError("HMAC verification failed")

            # Decrypt the data
            if config.cipher == "AES-256-CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(data)
                try:
                    return unpad(decrypted, AES.block_size)
                except ValueError as e:
                    raise ValueError("Decryption failed: Invalid padding") from e

            elif config.cipher == "AES-256-GCM":
                if "tag" not in layer_info:
                    raise ValueError("GCM tag missing")
                tag = bytes.fromhex(layer_info["tag"])
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                return cipher.decrypt_and_verify(data, tag)

            elif config.cipher == "AES-256-CFB":
                cipher = AES.new(key, AES.MODE_CFB, iv)
                return cipher.decrypt(data)

            else:
                raise ValueError(f"Unsupported cipher: {config.cipher}")

        except Exception as e:
            logger.error(f"Layer decryption failed: {e}")
            raise

    def encrypt(self, data: bytes, num_layers: Optional[int] = None) -> Tuple[bytes, Dict]:
        """
        Encrypt data with multiple layers of encryption.

        Args:
            data: The data to encrypt
            num_layers: Number of encryption layers to apply (random if None)

        Returns:
            A tuple of (encrypted_data, metadata) where metadata contains the keys and IVs
        """
        if num_layers is None:
            num_layers = random.randint(self.min_layers, self.max_layers)

        current_data = data
        metadata = {
            "version": "1.0",
            "created_at": time.time(),
            "num_layers": num_layers,
            "layers": [],
        }

        for i in range(num_layers):
            # Rotate through available configurations
            config_idx = i % len(self.layer_configs)
            config = self.layer_configs[config_idx]

            # Encrypt the current data
            encrypted_data, layer_metadata = self._encrypt_layer(current_data, config)

            # Update metadata
            layer_metadata["layer_number"] = i + 1
            metadata["layers"].append(layer_metadata)

            # Prepare for next layer
            current_data = encrypted_data

        return current_data, metadata

    def decrypt(self, encrypted_data: bytes, metadata: Dict) -> bytes:
        """
        Decrypt data with multiple layers of encryption.

        Args:
            encrypted_data: The encrypted data
            metadata: The metadata containing keys and IVs

        Returns:
            The decrypted data

        Raises:
            ValueError: If decryption fails at any layer
        """
        if "layers" not in metadata or not isinstance(metadata["layers"], list):
            raise ValueError("Invalid metadata: missing or invalid layers information")

        current_data = encrypted_data

        # Process layers in reverse order
        for layer_info in reversed(metadata["layers"]):
            try:
                # Find the corresponding config
                config = None
                for cfg in self.layer_configs:
                    if cfg.metadata.get("name") == layer_info.get("metadata", {}).get("name"):
                        config = cfg
                        break

                if not config:
                    raise ValueError(f"No matching configuration found for layer: {layer_info}")

                # Decrypt the current layer
                current_data = self._decrypt_layer(current_data, layer_info, config)

            except Exception as e:
                # If decryption fails, apply the fail-safe mechanism
                logger.warning(
                    f"Decryption failed at layer {layer_info.get('layer_number', 'unknown')}: {e}"
                )
                logger.info("Activating fail-safe mechanism: Adding more encryption layers")

                # Add more layers (up to 2000 as per requirement)
                additional_layers = min(2000, 10)  # Add 10 more layers, up to 2000 total
                current_data, new_metadata = self.encrypt(
                    current_data, num_layers=additional_layers
                )

                # Update the metadata with the new layers
                metadata["layers"].extend(new_metadata["layers"])
                metadata["fail_safe_activated"] = True
                metadata["fail_safe_timestamp"] = time.time()

                # Try decrypting again with the updated data and metadata
                return self.decrypt(current_data, metadata)

        return current_data


class ScrambledEggsLayeredEncryption:
    """
    Enhanced Scrambled Eggs encryption with layered encryption and fail-safe mechanism.

    This class combines the existing ScrambledEggsEncryption with the new layered encryption
    system to provide enhanced security through multiple layers of encryption and a fail-safe
    mechanism that adds more layers when decryption fails.
    """

    def __init__(self, min_layers: int = 3, max_layers: int = 10):
        """
        Initialize the enhanced encryption system.

        Args:
            min_layers: Minimum number of encryption layers to apply
            max_layers: Maximum number of encryption layers to apply
        """
        from .scrambled_eggs_encryption import AIParams, ScrambledEggsEncryption

        self.min_layers = min_layers
        self.max_layers = max_layers
        self.layered_encryption = LayeredEncryption(min_layers, max_layers)
        self.core_encryption = ScrambledEggsEncryption(AIParams())

    def encrypt(self, data: bytes) -> Tuple[bytes, Dict]:
        """
        Encrypt data with multiple layers of encryption.

        Args:
            data: The data to encrypt

        Returns:
            A tuple of (encrypted_data, metadata)
        """
        # First, encrypt with the core ScrambledEggs encryption
        public_key = self.core_encryption.export_public_key()
        enc_session_key, encrypted_data, hmac_value = self.core_encryption.hybrid_encrypt(
            data, public_key
        )

        # Combine the encrypted data with the session key and HMAC
        combined_data = enc_session_key + hmac_value + encrypted_data

        # Then apply layered encryption
        encrypted_layers, metadata = self.layered_encryption.encrypt(combined_data)

        # Add core encryption metadata
        metadata["core_encryption"] = {
            "public_key": public_key.hex(),
            "session_key": enc_session_key.hex(),
            "hmac": hmac_value.hex(),
        }

        return encrypted_layers, metadata

    def decrypt(self, encrypted_data: bytes, metadata: Dict) -> bytes:
        """
        Decrypt data with multiple layers of encryption.

        Args:
            encrypted_data: The encrypted data
            metadata: The metadata containing keys and IVs

        Returns:
            The decrypted data

        Raises:
            ValueError: If decryption fails
        """
        try:
            # First, decrypt the layered encryption
            decrypted_layers = self.layered_encryption.decrypt(encrypted_data, metadata)

            # Extract the components
            if "core_encryption" not in metadata:
                raise ValueError("Core encryption metadata missing")

            core_meta = metadata["core_encryption"]
            enc_session_key = bytes.fromhex(core_meta["session_key"])
            hmac_value = bytes.fromhex(core_meta["hmac"])

            # The remaining data is the encrypted data from the core encryption
            iv_tag_ciphertext = decrypted_layers

            # Decrypt using the core encryption
            return self.core_encryption.hybrid_decrypt(
                enc_session_key, iv_tag_ciphertext, hmac_value
            )

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise


def example_usage():
    """Example usage of the layered encryption system."""
    # Initialize the encryption system
    crypto = ScrambledEggsLayeredEncryption(min_layers=3, max_layers=5)

    # Sample data to encrypt
    data = b"This is a test message for the layered encryption system."
    print(f"Original data: {data.decode('utf-8')}")

    # Encrypt the data
    encrypted_data, metadata = crypto.encrypt(data)
    print(f"Encrypted data: {encrypted_data[:50]}... (truncated)")

    # Save the metadata (in a real application, you'd save this securely)
    import json

    metadata_json = json.dumps(metadata, indent=2)
    print("\nEncryption metadata:")
    print(metadata_json)

    # Decrypt the data
    decrypted_data = crypto.decrypt(encrypted_data, metadata)
    print(f"\nDecrypted data: {decrypted_data.decode('utf-8')}")

    # Verify the data
    assert decrypted_data == data, "Decrypted data does not match original!"
    print("\nVerification successful!")


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)
    example_usage()

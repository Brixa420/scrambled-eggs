"""
Dynamic encryption system that adds security layers in response to threats.
"""

import json
import logging
import os
import random
import time
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

logger = logging.getLogger(__name__)


class EncryptionLayer:
    """Represents a single encryption layer with its configuration."""

    def __init__(self, algorithm: str, key_size: int, mode: str, **kwargs):
        self.algorithm = algorithm
        self.key_size = key_size
        self.mode = mode
        self.params = kwargs
        self.created_at = time.time()
        self.usage_count = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert layer configuration to a dictionary."""
        return {
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "mode": self.mode,
            "params": self.params,
            "created_at": self.created_at,
            "usage_count": self.usage_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptionLayer":
        """Create a layer from a dictionary."""
        layer = cls(
            algorithm=data["algorithm"],
            key_size=data["key_size"],
            mode=data["mode"],
            **data.get("params", {}),
        )
        layer.created_at = data.get("created_at", time.time())
        layer.usage_count = data.get("usage_count", 0)
        return layer


class DynamicEncryption:
    """Manages dynamic encryption layers that adapt to security threats."""

    # Available encryption algorithms and their configurations
    ALGORITHMS = {
        "AES": {"key_sizes": [128, 192, 256], "modes": ["CBC", "GCM", "CTR"], "requires_iv": True},
        "ChaCha20": {"key_sizes": [256], "modes": ["Poly1305"], "requires_iv": True},
        "Blowfish": {"key_sizes": [128, 192, 256], "modes": ["CBC", "OFB"], "requires_iv": True},
    }

    def __init__(self, base_algorithm: str = "AES", base_key_size: int = 256):
        self.layers = []
        self.base_algorithm = base_algorithm
        self.base_key_size = base_key_size
        self._initialize_base_layer()

    def _initialize_base_layer(self):
        """Initialize the base encryption layer."""
        if self.base_algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {self.base_algorithm}")

        self.layers.append(
            EncryptionLayer(
                algorithm=self.base_algorithm,
                key_size=self.base_key_size,
                mode=self.ALGORITHMS[self.base_algorithm]["modes"][0],
                description="Base encryption layer",
            )
        )

    def add_random_layer(self) -> EncryptionLayer:
        """Add a new random encryption layer."""
        # Select a random algorithm and configuration
        algo_name = random.choice(list(self.ALGORITHMS.keys()))
        algo_config = self.ALGORITHMS[algo_name]

        layer = EncryptionLayer(
            algorithm=algo_name,
            key_size=random.choice(algo_config["key_sizes"]),
            mode=random.choice(algo_config["modes"]),
            description=f"Dynamic security layer {len(self.layers) + 1}",
            created_in_response_to_threat=True,
            threat_level=random.randint(1, 10),
        )

        self.layers.append(layer)
        logger.info(f"Added new encryption layer: {layer.algorithm}-{layer.key_size}-{layer.mode}")
        return layer

    def remove_layer(self, index: int):
        """Remove an encryption layer by index."""
        if 0 <= index < len(self.layers):
            return self.layers.pop(index)
        return None

    def get_active_layers(self) -> list:
        """Get all active encryption layers."""
        return [layer.to_dict() for layer in self.layers]

    def get_encryption_parameters(self) -> Dict[str, Any]:
        """Get parameters needed for the current encryption setup."""
        return {
            "layers": [layer.to_dict() for layer in self.layers],
            "total_layers": len(self.layers),
            "security_level": self.calculate_security_level(),
        }

    def calculate_security_level(self) -> int:
        """Calculate a security level based on active layers."""
        level = 0
        for layer in self.layers:
            # Base points for algorithm
            algo_points = {"AES": 10, "ChaCha20": 12, "Blowfish": 8}.get(layer.algorithm, 5)

            # Points for key size
            key_points = layer.key_size // 32  # 4 points for 128-bit, 8 for 256-bit, etc.

            # Points for mode
            mode_points = {"GCM": 3, "Poly1305": 3, "CBC": 2, "CTR": 2, "OFB": 1}.get(layer.mode, 1)

            level += (algo_points + key_points) * mode_points

        return level

    def to_dict(self) -> Dict[str, Any]:
        """Convert the dynamic encryption state to a dictionary."""
        return {
            "base_algorithm": self.base_algorithm,
            "base_key_size": self.base_key_size,
            "layers": [layer.to_dict() for layer in self.layers],
            "security_level": self.calculate_security_level(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DynamicEncryption":
        """Create a DynamicEncryption instance from a dictionary."""
        instance = cls(
            base_algorithm=data.get("base_algorithm", "AES"),
            base_key_size=data.get("base_key_size", 256),
        )

        # Clear the default layer
        instance.layers = []

        # Add all layers from the dictionary
        for layer_data in data.get("layers", []):
            instance.layers.append(EncryptionLayer.from_dict(layer_data))

        return instance

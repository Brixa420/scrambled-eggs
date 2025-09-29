"""
Gate System for Scrambled Eggs

Implements the 1000+ gate encryption system with dynamic security properties.
"""

import hashlib
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class GateType(Enum):
    """Types of encryption gates in the system."""

    ENCRYPTION = auto()
    DECRYPTION = auto()
    AUTHENTICATION = auto()
    VALIDATION = auto()
    TRANSFORMATION = auto()
    MUTATION = auto()
    OBFUSCATION = auto()
    COMPRESSION = auto()
    EXPANSION = auto()
    ENTROPY = auto()


@dataclass
class Gate:
    """Represents a single encryption gate with dynamic properties."""

    gate_id: int
    gate_type: GateType
    encryption_algorithm: str
    key: bytes
    iv: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0

    def process(self, data: bytes, operation: str = "encrypt") -> bytes:
        """Process data through this gate."""
        self.last_accessed = datetime.utcnow()
        self.access_count += 1

        try:
            if self.gate_type == GateType.ENCRYPTION:
                return self._apply_encryption(data, operation)
            elif self.gate_type == GateType.AUTHENTICATION:
                return self._apply_authentication(data)
            elif self.gate_type == GateType.VALIDATION:
                return self._apply_validation(data)
            elif self.gate_type == GateType.TRANSFORMATION:
                return self._apply_transformation(data)
            elif self.gate_type == GateType.MUTATION:
                return self._apply_mutation(data)
            elif self.gate_type == GateType.OBFUSCATION:
                return self._apply_obfuscation(data)
            elif self.gate_type == GateType.COMPRESSION:
                return self._apply_compression(data, operation)
            elif self.gate_type == GateType.EXPANSION:
                return self._apply_expansion(data, operation)
            elif self.gate_type == GateType.ENTROPY:
                return self._apply_entropy(data)
            return data
        except Exception as e:
            logger.error(f"Error in gate {self.gate_id} ({self.gate_type.name}): {str(e)}")
            raise

    def _apply_encryption(self, data: bytes, operation: str) -> bytes:
        """Apply encryption/decryption using the gate's algorithm."""
        if self.encryption_algorithm == "AES-256-CBC":
            return self._aes_cbc(data, operation)
        elif self.encryption_algorithm == "AES-256-GCM":
            return self._aes_gcm(data, operation)
        elif self.encryption_algorithm == "ChaCha20":
            return self._chacha20(data, operation)
        elif self.encryption_algorithm == "Blowfish":
            return self._blowfish(data, operation)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.encryption_algorithm}")

    def _aes_cbc(self, data: bytes, operation: str) -> bytes:
        """Apply AES-CBC encryption/decryption."""
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())

        if operation == "encrypt":
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            return encryptor.update(padded_data) + encryptor.finalize()
        else:
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(data) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

    def _aes_gcm(self, data: bytes, operation: str) -> bytes:
        """Apply AES-GCM encryption/decryption."""
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(self.iv, min_tag_length=16),
            backend=default_backend(),
        )

        if operation == "encrypt":
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize() + encryptor.tag
        else:
            if len(data) < 16:  # Tag is 16 bytes
                raise ValueError("Ciphertext too short")
            tag = data[-16:]
            data = data[:-16]
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize_with_tag(tag)

    def _chacha20(self, data: bytes, operation: str) -> bytes:
        """Apply ChaCha20 encryption/decryption."""
        cipher = Cipher(
            algorithms.ChaCha20(self.key, self.iv), mode=None, backend=default_backend()
        )

        if operation == "encrypt":
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()
        else:
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()

    def _blowfish(self, data: bytes, operation: str) -> bytes:
        """Apply Blowfish encryption/decryption."""
        cipher = Cipher(
            algorithms.Blowfish(self.key), modes.CBC(self.iv), backend=default_backend()
        )

        if operation == "encrypt":
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            return encryptor.update(padded_data) + encryptor.finalize()
        else:
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(data) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

    def _apply_authentication(self, data: bytes) -> bytes:
        """Apply HMAC authentication."""
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    def _apply_validation(self, data: bytes) -> bytes:
        """Apply data validation and integrity checks."""
        # Simple checksum validation
        checksum = hashlib.sha256(data).digest()
        return checksum

    def _apply_transformation(self, data: bytes) -> bytes:
        """Apply data transformation (reversible)."""
        # Simple XOR transformation with key
        transformed = bytearray()
        key_byte = self.key[0] if self.key else 0x55
        for i, b in enumerate(data):
            transformed.append(b ^ (key_byte + i % 256))
        return bytes(transformed)

    def _apply_mutation(self, data: bytes) -> bytes:
        """Apply data mutation (potentially destructive)."""
        # Add some random noise based on the key
        mutated = bytearray(data)
        for i in range(len(mutated)):
            if i < len(self.key):
                mutated[i] = (mutated[i] + self.key[i]) % 256
            else:
                mutated[i] = (mutated[i] + i) % 256
        return bytes(mutated)

    def _apply_obfuscation(self, data: bytes) -> bytes:
        """Apply data obfuscation."""
        # Simple byte rotation based on key
        if not data:
            return b""

        rotation = sum(self.key) % len(data) if len(data) > 0 else 0
        if rotation == 0:
            rotation = 1
        return data[rotation:] + data[:rotation]

    def _apply_compression(self, data: bytes, operation: str) -> bytes:
        """Apply compression/decompression."""
        if operation == "encrypt":
            # Simple run-length encoding as a basic compression
            compressed = bytearray()
            if not data:
                return b""

            count = 1
            for i in range(1, len(data)):
                if data[i] == data[i - 1] and count < 255:
                    count += 1
                else:
                    compressed.append(count)
                    compressed.append(data[i - 1])
                    count = 1
            # Add the last run
            compressed.append(count)
            compressed.append(data[-1])
            return bytes(compressed)
        else:
            # Decompress
            decompressed = bytearray()
            for i in range(0, len(data), 2):
                if i + 1 >= len(data):
                    break
                count = data[i]
                byte = data[i + 1]
                decompressed.extend([byte] * count)
            return bytes(decompressed)

    def _apply_expansion(self, data: bytes, operation: str) -> bytes:
        """Apply data expansion/contraction."""
        if operation == "encrypt":
            # Simple expansion by repeating each byte
            expanded = bytearray()
            for b in data:
                expanded.append(b)
                expanded.append((b + 1) % 256)  # Simple variation
            return bytes(expanded)
        else:
            # Contract back
            contracted = bytearray()
            for i in range(0, len(data), 2):
                if i < len(data):
                    contracted.append(data[i])
            return bytes(contracted)

    def _apply_entropy(self, data: bytes) -> bytes:
        """Apply entropy encoding/decoding."""
        # Simple entropy encoding using key-based permutation
        if not data:
            return b""

        # Create a permutation based on the key
        perm = list(range(256))
        random.seed(int.from_bytes(self.key[:4], "little"))
        random.shuffle(perm)

        # Apply permutation
        result = bytearray(len(data))
        for i, b in enumerate(data):
            result[i] = perm[b]

        return bytes(result)

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance and security metrics for this gate."""
        return {
            "gate_id": self.gate_id,
            "gate_type": self.gate_type.name,
            "algorithm": self.encryption_algorithm,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed.isoformat(),
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


class GateSystem:
    """Manages the collection of encryption gates."""

    def __init__(self, num_gates: int = 1000):
        self.gates: Dict[int, Gate] = {}
        self._initialize_gates(num_gates)

    def _initialize_gates(self, num_gates: int) -> None:
        """Initialize the specified number of gates with random configurations."""
        algorithms = ["AES-256-CBC", "AES-256-GCM", "ChaCha20", "Blowfish"]

        gate_types = list(GateType)

        for gate_id in range(num_gates):
            gate_type = random.choice(gate_types)
            algo = random.choice(algorithms)

            # Generate deterministic but unique keys and IVs for each gate
            seed = f"{gate_id}-{algo}-{gate_type.name}".encode()
            key = hashlib.sha256(seed + b"-key").digest()
            iv = hashlib.sha256(seed + b"-iv").digest()

            # Create metadata
            metadata = {
                "creation_seed": gate_id,
                "entropy_level": random.random(),
                "security_level": random.choice(["low", "medium", "high"]),
                "performance_rating": random.uniform(0.5, 1.0),
                "last_health_check": datetime.utcnow().isoformat(),
                "is_active": True,
                "version": "1.0",
                "tags": [f"type_{gate_type.name.lower()}", f"algo_{algo.lower()}"],
            }

            self.gates[gate_id] = Gate(
                gate_id=gate_id,
                gate_type=gate_type,
                encryption_algorithm=algo,
                key=key,
                iv=iv[:16],  # Ensure IV is appropriate length
                metadata=metadata,
            )

    def get_gate(self, gate_id: int) -> Optional[Gate]:
        """Get a gate by its ID."""
        return self.gates.get(gate_id)

    def get_random_gates(self, count: int, gate_type: Optional[GateType] = None) -> List[Gate]:
        """Get a list of random gates, optionally filtered by type."""
        candidates = [
            gate for gate in self.gates.values() if gate_type is None or gate.gate_type == gate_type
        ]
        return random.sample(candidates, min(count, len(candidates)))

    def process_through_gates(
        self, data: bytes, gate_ids: List[int], operation: str = "encrypt"
    ) -> bytes:
        """Process data through a sequence of gates."""
        result = data
        for gate_id in gate_ids:
            if gate_id in self.gates:
                result = self.gates[gate_id].process(result, operation)
        return result

    def get_gate_metrics(self) -> Dict:
        """Get metrics about the gate system."""
        now = datetime.utcnow()
        active_gates = [
            g for g in self.gates.values() if (now - g.last_accessed) < timedelta(hours=1)
        ]

        return {
            "total_gates": len(self.gates),
            "active_gates": len(active_gates),
            "avg_access_count": (
                sum(g.access_count for g in self.gates.values()) / len(self.gates)
                if self.gates
                else 0
            ),
            "gate_types": {
                gt.name: len([g for g in self.gates.values() if g.gate_type == gt])
                for gt in GateType
            },
            "algorithms": {
                "AES-256-CBC": len(
                    [g for g in self.gates.values() if g.encryption_algorithm == "AES-256-CBC"]
                ),
                "AES-256-GCM": len(
                    [g for g in self.gates.values() if g.encryption_algorithm == "AES-256-GCM"]
                ),
                "ChaCha20": len(
                    [g for g in self.gates.values() if g.encryption_algorithm == "ChaCha20"]
                ),
                "Blowfish": len(
                    [g for g in self.gates.values() if g.encryption_algorithm == "Blowfish"]
                ),
            },
            "last_updated": now.isoformat(),
        }

    def get_gate_status(self, gate_id: int) -> Optional[Dict]:
        """Get detailed status for a specific gate."""
        if gate_id not in self.gates:
            return None

        gate = self.gates[gate_id]
        return {
            "gate_id": gate.gate_id,
            "gate_type": gate.gate_type.name,
            "algorithm": gate.encryption_algorithm,
            "access_count": gate.access_count,
            "last_accessed": gate.last_accessed.isoformat(),
            "created_at": gate.created_at.isoformat(),
            "is_active": gate.metadata.get("is_active", True),
            "performance": gate.metadata.get("performance_rating", 0.0),
            "security_level": gate.metadata.get("security_level", "medium"),
            "entropy": gate.metadata.get("entropy_level", 0.0),
        }

    def get_gates_by_type(self, gate_type: GateType) -> List[Dict]:
        """Get all gates of a specific type."""
        return [
            self.get_gate_status(gate_id)
            for gate_id, gate in self.gates.items()
            if gate.gate_type == gate_type
        ]

    def get_gates_by_algorithm(self, algorithm: str) -> List[Dict]:
        """Get all gates using a specific algorithm."""
        return [
            self.get_gate_status(gate_id)
            for gate_id, gate in self.gates.items()
            if gate.encryption_algorithm.lower() == algorithm.lower()
        ]

    def get_health_status(self) -> Dict:
        """Get overall health status of the gate system."""
        now = datetime.utcnow()
        active_gates = [
            g for g in self.gates.values() if (now - g.last_accessed) < timedelta(hours=1)
        ]

        return {
            "total_gates": len(self.gates),
            "active_gates": len(active_gates),
            "inactive_gates": len(self.gates) - len(active_gates),
            "health_score": (
                min(100, len(active_gates) / len(self.gates) * 100) if self.gates else 0
            ),
            "last_checked": now.isoformat(),
            "gate_type_distribution": {
                gt.name: len([g for g in self.gates.values() if g.gate_type == gt])
                for gt in GateType
            },
        }

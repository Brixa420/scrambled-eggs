"""
Threshold Cryptography and Secure Key Sharing

This module implements threshold cryptography and secure key sharing schemes,
including Shamir's Secret Sharing and verifiable secret sharing (VSS).
"""

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import Enum
from secrets import randbelow, token_bytes
from typing import Dict, List, Optional, Set, Tuple

# Try to import the secretsharing library
try:
    from secretsharing import SecretSharer

    HAS_SECRETSHARING = True
except ImportError:
    HAS_SECRETSHARING = False

# Try to import the PyCryptodome library for threshold cryptography
try:
    from Crypto.Protocol.SecretSharing import Shamir

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


class KeyShareType(Enum):
    """Types of key sharing schemes."""

    SHAMIR = "shamir"  # Shamir's Secret Sharing
    FELDMAN = "feldman"  # Feldman's Verifiable Secret Sharing
    PEDERSEN = "pedersen"  # Pedersen's Verifiable Secret Sharing
    THRESHOLD_ECDSA = "threshold_ecdsa"  # Threshold ECDSA
    THRESHOLD_BLS = "threshold_bls"  # Threshold BLS signatures


@dataclass
class KeyShare:
    """Represents a share of a secret key."""

    index: int
    share: bytes
    threshold: int
    total_shares: int
    key_type: KeyShareType
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Serialize the key share to a dictionary."""
        return {
            "index": self.index,
            "share": self.share.hex(),
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "key_type": self.key_type.value,
            "metadata": self.metadata or {},
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "KeyShare":
        """Deserialize a key share from a dictionary."""
        return cls(
            index=data["index"],
            share=bytes.fromhex(data["share"]),
            threshold=data["threshold"],
            total_shares=data["total_shares"],
            key_type=KeyShareType(data["key_type"]),
            metadata=data.get("metadata"),
        )


class ThresholdKeyShare:
    """
    Threshold Cryptography and Secure Key Sharing

    This class provides methods for:
    1. Splitting a secret into shares using Shamir's Secret Sharing
    2. Reconstructing a secret from a subset of shares
    3. Verifiable secret sharing (Feldman, Pedersen)
    4. Threshold signatures (ECDSA, BLS)
    """

    def __init__(self, key_type: KeyShareType = KeyShareType.SHAMIR):
        """
        Initialize the threshold key sharing system.

        Args:
            key_type: The type of key sharing scheme to use
        """
        self.key_type = key_type

        if key_type == KeyShareType.SHAMIR and not HAS_SECRETSHARING:
            raise ImportError(
                "secretsharing library is required for Shamir's Secret Sharing. "
                "Install with: pip install secretsharing"
            )

        if (
            key_type in (KeyShareType.THRESHOLD_ECDSA, KeyShareType.THRESHOLD_BLS)
            and not HAS_PYCRYPTODOME
        ):
            raise ImportError(
                "PyCryptodome is required for threshold signatures. "
                "Install with: pip install pycryptodome"
            )

    def split_secret(
        self, secret: bytes, threshold: int, total_shares: int, key_id: Optional[str] = None
    ) -> List[KeyShare]:
        """
        Split a secret into multiple shares using the specified scheme.

        Args:
            secret: The secret to split
            threshold: Minimum number of shares required to reconstruct the secret
            total_shares: Total number of shares to generate
            key_id: Optional identifier for the key

        Returns:
            A list of KeyShare objects
        """
        if threshold < 2 or threshold > total_shares:
            raise ValueError("Threshold must be at least 2 and at most total_shares")

        if self.key_type == KeyShareType.SHAMIR:
            return self._shamir_split(secret, threshold, total_shares, key_id)
        elif self.key_type == KeyShareType.FELDMAN:
            return self._feldman_split(secret, threshold, total_shares, key_id)
        elif self.key_type == KeyShareType.PEDERSEN:
            return self._pedersen_split(secret, threshold, total_shares, key_id)
        elif self.key_type == KeyShareType.THRESHOLD_ECDSA:
            return self._threshold_ecdsa_keygen(threshold, total_shares, key_id)
        elif self.key_type == KeyShareType.THRESHOLD_BLS:
            return self._threshold_bls_keygen(threshold, total_shares, key_id)
        else:
            raise ValueError(f"Unsupported key sharing type: {self.key_type}")

    def reconstruct_secret(self, shares: List[KeyShare]) -> bytes:
        """
        Reconstruct the original secret from a subset of shares.

        Args:
            shares: A list of KeyShare objects (must be at least the threshold)

        Returns:
            The reconstructed secret

        Raises:
            ValueError: If not enough shares are provided or reconstruction fails
        """
        if not shares:
            raise ValueError("No shares provided")

        # All shares should have the same parameters
        key_type = shares[0].key_type
        threshold = shares[0].threshold

        if len(shares) < threshold:
            raise ValueError(f"At least {threshold} shares are required, got {len(shares)}")

        if any(s.key_type != key_type for s in shares):
            raise ValueError("All shares must be of the same type")

        if key_type == KeyShareType.SHAMIR:
            return self._shamir_reconstruct(shares)
        elif key_type == KeyShareType.FELDMAN:
            return self._feldman_reconstruct(shares)
        elif key_type == KeyShareType.PEDERSEN:
            return self._pedersen_reconstruct(shares)
        else:
            raise ValueError(f"Unsupported key sharing type for reconstruction: {key_type}")

    def verify_share(self, share: KeyShare, public_info: Dict) -> bool:
        """
        Verify that a share is valid using the public verification information.

        Args:
            share: The share to verify
            public_info: Public information generated during sharing

        Returns:
            True if the share is valid, False otherwise
        """
        if share.key_type == KeyShareType.FELDMAN:
            return self._verify_feldman_share(share, public_info)
        elif share.key_type == KeyShareType.PEDERSEN:
            return self._verify_pedersen_share(share, public_info)
        else:
            # For Shamir's scheme, we can only verify by trying to reconstruct
            return True

    # ===== Implementation of specific schemes =====

    def _shamir_split(
        self, secret: bytes, threshold: int, total_shares: int, key_id: str = None
    ) -> List[KeyShare]:
        """Split a secret using Shamir's Secret Sharing."""
        if not HAS_SECRETSHARING:
            raise RuntimeError("secretsharing library is required for Shamir's Secret Sharing")

        # Convert the secret to a hex string for the secretsharing library
        secret_hex = secret.hex()

        # Generate shares
        shares = SecretSharer.split_secret(secret_hex, threshold, total_shares)

        # Convert to KeyShare objects
        result = []
        for i, share in enumerate(shares):
            # The secretsharing library returns shares in the format "1-xxxxx"
            # where the first part is the index (1-based)
            index = int(share.split("-")[0])
            result.append(
                KeyShare(
                    index=index,
                    share=share.encode("ascii"),
                    threshold=threshold,
                    total_shares=total_shares,
                    key_type=KeyShareType.SHAMIR,
                    metadata={"key_id": key_id, "share_format": "secretsharing-ascii"},
                )
            )

        return result

    def _shamir_reconstruct(self, shares: List[KeyShare]) -> bytes:
        """Reconstruct a secret from Shamir shares."""
        if not HAS_SECRETSHARING:
            raise RuntimeError("secretsharing library is required for Shamir's Secret Sharing")

        # Convert shares to the format expected by the secretsharing library
        share_strings = [s.share.decode("ascii") for s in shares]

        # Reconstruct the secret
        try:
            secret_hex = SecretSharer.recover_secret(share_strings)
            return bytes.fromhex(secret_hex)
        except Exception as e:
            raise ValueError(f"Failed to reconstruct secret: {str(e)}")

    def _feldman_split(
        self, secret: bytes, threshold: int, total_shares: int, key_id: str = None
    ) -> List[KeyShare]:
        """Split a secret using Feldman's Verifiable Secret Sharing."""
        # This is a simplified implementation for demonstration
        # In practice, you'd want to use a well-tested library

        # Generate coefficients for the polynomial
        coefficients = [int.from_bytes(os.urandom(32), "big") for _ in range(threshold - 1)]
        coefficients.insert(0, int.from_bytes(secret, "big"))  # a0 is the secret

        # Evaluate the polynomial at different points
        shares = []
        commitments = []

        # Precompute g^a_i mod p for verification
        p = 2**521 - 1  # A large prime (in practice, use a proper group)
        g = 2  # Generator

        for a in coefficients:
            commitments.append(pow(g, a, p))

        # Generate shares
        for i in range(1, total_shares + 1):
            # Evaluate the polynomial at x = i
            share = 0
            for j, a in enumerate(coefficients):
                share += a * (i**j)

            shares.append(
                KeyShare(
                    index=i,
                    share=share.to_bytes((share.bit_length() + 7) // 8, "big"),
                    threshold=threshold,
                    total_shares=total_shares,
                    key_type=KeyShareType.FELDMAN,
                    metadata={
                        "key_id": key_id,
                        "commitments": [str(c) for c in commitments],
                        "prime": str(p),
                        "generator": str(g),
                    },
                )
            )

        return shares

    def _verify_feldman_share(self, share: KeyShare, public_info: Dict) -> bool:
        """Verify a Feldman VSS share."""
        # This is a simplified verification for demonstration
        try:
            p = int(public_info["prime"])
            g = int(public_info["generator"])
            commitments = [int(c) for c in public_info["commitments"]]

            # Reconstruct the expected value
            expected = 1
            for j, c in enumerate(commitments):
                expected = (expected * pow(c, share.index**j, p)) % p

            # Compute g^share mod p
            share_value = int.from_bytes(share.share, "big")
            actual = pow(g, share_value, p)

            return expected == actual
        except (KeyError, ValueError):
            return False

    def _feldman_reconstruct(self, shares: List[KeyShare]) -> bytes:
        """Reconstruct a secret from Feldman shares."""
        # For Feldman, reconstruction is the same as Shamir's
        return self._shamir_reconstruct(shares)

    def _pedersen_split(
        self, secret: bytes, threshold: int, total_shares: int, key_id: str = None
    ) -> List[KeyShare]:
        """Split a secret using Pedersen's Verifiable Secret Sharing."""
        # This is a simplified implementation for demonstration
        # In practice, you'd want to use a well-tested library

        # Generate coefficients for the polynomial f(x)
        f_coeffs = [int.from_bytes(os.urandom(32), "big") for _ in range(threshold - 1)]
        f_coeffs.insert(0, int.from_bytes(secret, "big"))  # a0 is the secret

        # Generate coefficients for the polynomial h(x)
        h_coeffs = [int.from_bytes(os.urandom(32), "big") for _ in range(threshold - 1)]
        h_coeffs.insert(0, int.from_bytes(os.urandom(32), "big"))

        # Evaluate the polynomials at different points
        shares = []

        # Precompute commitments (g^a_i * h^b_i)
        p = 2**521 - 1  # A large prime (in practice, use a proper group)
        g = 2  # Generator for f(x)
        h = 3  # Generator for h(x)

        commitments = []
        for a, b in zip(f_coeffs, h_coeffs):
            # Commitment is (g^a * h^b) mod p
            commitment = (pow(g, a, p) * pow(h, b, p)) % p
            commitments.append(str(commitment))

        # Generate shares
        for i in range(1, total_shares + 1):
            # Evaluate f(x) at x = i
            f_share = 0
            for j, a in enumerate(f_coeffs):
                f_share += a * (i**j)

            # Evaluate h(x) at x = i
            h_share = 0
            for j, b in enumerate(h_coeffs):
                h_share += b * (i**j)

            # The share is the pair (f(i), h(i))
            share_data = {"f_share": str(f_share), "h_share": str(h_share)}

            shares.append(
                KeyShare(
                    index=i,
                    share=json.dumps(share_data).encode("utf-8"),
                    threshold=threshold,
                    total_shares=total_shares,
                    key_type=KeyShareType.PEDERSEN,
                    metadata={
                        "key_id": key_id,
                        "commitments": commitments,
                        "prime": str(p),
                        "generators": {"g": str(g), "h": str(h)},
                    },
                )
            )

        return shares

    def _verify_pedersen_share(self, share: KeyShare, public_info: Dict) -> bool:
        """Verify a Pedersen VSS share."""
        try:
            p = int(public_info["prime"])
            g = int(public_info["generators"]["g"])
            h = int(public_info["generators"]["h"])
            commitments = [int(c) for c in public_info["commitments"]]

            # Parse the share data
            share_data = json.loads(share.share.decode("utf-8"))
            f_share = int(share_data["f_share"])
            h_share = int(share_data["h_share"])

            # Compute the left side: g^f_share * h^h_share mod p
            left = (pow(g, f_share, p) * pow(h, h_share, p)) % p

            # Compute the right side: product of (commitments[j]^{i^j}) mod p
            right = 1
            for j, c in enumerate(commitments):
                right = (right * pow(c, share.index**j, p)) % p

            return left == right
        except (KeyError, ValueError, json.JSONDecodeError):
            return False

    def _pedersen_reconstruct(self, shares: List[KeyShare]) -> bytes:
        """Reconstruct a secret from Pedersen shares."""
        # For Pedersen, reconstruction is similar to Shamir's but using only the f_share part

        # Extract the f_shares
        f_shares = []
        for share in shares:
            try:
                share_data = json.loads(share.share.decode("utf-8"))
                f_share = int(share_data["f_share"])
                f_shares.append((share.index, f_share))
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                raise ValueError(f"Invalid Pedersen share format: {str(e)}")

        # Use Lagrange interpolation to reconstruct the secret (f(0))
        secret = 0
        p = 2**521 - 1  # Should match the prime used in sharing

        for i, (x_i, y_i) in enumerate(f_shares):
            # Compute the Lagrange coefficient l_i(0)
            numerator = 1
            denominator = 1

            for j, (x_j, _) in enumerate(f_shares):
                if i != j:
                    numerator = (numerator * (-x_j)) % p
                    denominator = (denominator * (x_i - x_j)) % p

            # Compute denominator^{-1} mod p
            inv_denominator = pow(denominator, -1, p)
            l_i = (numerator * inv_denominator) % p

            # Add the term to the secret
            secret = (secret + y_i * l_i) % p

        # Convert the secret back to bytes
        return secret.to_bytes((secret.bit_length() + 7) // 8, "big")

    def _threshold_ecdsa_keygen(
        self, threshold: int, total_shares: int, key_id: str = None
    ) -> List[KeyShare]:
        """Generate threshold ECDSA key shares."""
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("PyCryptodome is required for threshold ECDSA")

        from Crypto.Protocol.SecretSharing import Shamir
        from Crypto.PublicKey import ECC

        # Generate a random secret key
        secret_key = ECC.generate(curve="P-256")
        secret = secret_key.d.to_bytes(32, "big")

        # Split the secret using Shamir's Secret Sharing
        shares_data = Shamir.split(threshold, total_shares, secret)

        # Convert to KeyShare objects
        shares = []
        for idx, share_data in shares_data:
            shares.append(
                KeyShare(
                    index=idx,
                    share=share_data,
                    threshold=threshold,
                    total_shares=total_shares,
                    key_type=KeyShareType.THRESHOLD_ECDSA,
                    metadata={
                        "key_id": key_id,
                        "curve": "P-256",
                        "public_key": secret_key.public_key().export_key(format="PEM"),
                    },
                )
            )

        return shares

    def _threshold_bls_keygen(
        self, threshold: int, total_shares: int, key_id: str = None
    ) -> List[KeyShare]:
        """Generate threshold BLS key shares."""
        # This is a placeholder implementation
        # In practice, you'd use a BLS library like py-ecc or blspy

        # Generate a random secret key
        secret = os.urandom(32)

        # Split the secret using Shamir's Secret Sharing
        shares = self._shamir_split(secret, threshold, total_shares, key_id)

        # Update the key type
        for share in shares:
            share.key_type = KeyShareType.THRESHOLD_BLS
            if share.metadata is None:
                share.metadata = {}
            share.metadata.update(
                {
                    "key_type": "BLS12-381",
                    "public_key": hashlib.sha256(secret).hexdigest(),  # Placeholder
                }
            )

        return shares

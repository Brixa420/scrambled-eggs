"""
Hybrid Cryptography Module

This module provides hybrid cryptographic schemes that combine classical and
post-quantum algorithms to provide both security against classical and
quantum computers (cryptographic agility).
"""

import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .dilithium import Dilithium, DilithiumVariant
from .kyber import KyberKEM, KyberVariant


class HybridCrypto:
    """
    Hybrid Cryptography combining classical and post-quantum algorithms.

    This class provides methods for:
    1. Hybrid Key Encapsulation (combining Kyber with ECDH or RSA-KEM)
    2. Hybrid Signatures (combining Dilithium with ECDSA or RSA-PSS)
    3. Hybrid Encryption (combining AES-GCM/ChaCha20-Poly1305 with Kyber)
    """

    class KeyType(Enum):
        """Supported key types for hybrid operations."""

        EC = "ec"
        RSA = "rsa"
        KYBER = "kyber"
        DILITHIUM = "dilithium"

    def __init__(
        self,
        kem_variant: KyberVariant = KyberVariant.KYBER768,
        sig_variant: DilithiumVariant = DilithiumVariant.DILITHIUM3,
    ):
        """
        Initialize the hybrid crypto system.

        Args:
            kem_variant: Kyber variant to use for KEM
            sig_variant: Dilithium variant to use for signatures
        """
        self.kem = KyberKEM(kem_variant)
        self.signer = Dilithium(sig_variant)
        self.kem_variant = kem_variant
        self.sig_variant = sig_variant

    # ===== Hybrid Key Encapsulation =====

    def generate_hybrid_kem_keypair(
        self,
        key_type: KeyType = KeyType.EC,
        curve: ec.EllipticCurve = ec.SECP384R1(),
        rsa_key_size: int = 3072,
    ) -> Tuple[dict, dict]:
        """
        Generate a hybrid key pair for key encapsulation.

        Args:
            key_type: Type of classical key to generate (EC or RSA)
            curve: Elliptic curve to use for EC keys
            rsa_key_size: Key size in bits for RSA keys

        Returns:
            A tuple of (private_key_dict, public_key_dict)
        """
        # Generate post-quantum key pair
        pq_public, pq_private = self.kem.generate_keypair()

        # Generate classical key pair
        if key_type == self.KeyType.EC:
            private_key = ec.generate_private_key(curve)
            public_key = private_key.public_key()

            # Serialize keys
            priv_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            ).decode("ascii")

            pub_pem = public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")

            key_data = {
                "kty": "EC",
                "curve": curve.name,
                "private_key": priv_pem,
                "public_key": pub_pem,
            }

        elif key_type == self.KeyType.RSA:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)
            public_key = private_key.public_key()

            # Serialize keys
            priv_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            ).decode("ascii")

            pub_pem = public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")

            key_data = {
                "kty": "RSA",
                "key_size": rsa_key_size,
                "private_key": priv_pem,
                "public_key": pub_pem,
            }
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        # Combine with post-quantum keys
        private_data = {
            **key_data,
            "pq_kem_private_key": pq_private.secret_key.hex(),
            "pq_kem_public_key": pq_private.public_key.hex(),
            "pq_kem_variant": self.kem_variant.value,
            "pq_sig_private_key": None,
            "pq_sig_public_key": None,
            "pq_sig_variant": None,
        }

        public_data = {
            **{k: v for k, v in key_data.items() if not k.startswith("private")},
            "pq_kem_public_key": pq_private.public_key.hex(),
            "pq_kem_variant": self.kem_variant.value,
            "pq_sig_public_key": None,
            "pq_sig_variant": None,
        }

        return private_data, public_data

    def encapsulate_hybrid(self, public_key_dict: dict) -> Tuple[bytes, dict]:
        """
        Generate a shared secret using hybrid key encapsulation.

        Args:
            public_key_dict: Recipient's public key dictionary

        Returns:
            A tuple of (shared_secret, encapsulation_data)
        """
        # Generate a shared secret using Kyber
        kyber_public = bytes.fromhex(public_key_dict["pq_kem_public_key"])
        pq_shared_secret, pq_ciphertext = self.kem.encapsulate(kyber_public)

        # Generate a shared secret using the classical algorithm
        if public_key_dict["kty"] == "EC":
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            # Load the public key
            pub_key = load_pem_public_key(public_key_dict["public_key"].encode("ascii"))

            # Generate an ephemeral key pair
            private_key = ec.generate_private_key(pub_key.curve)
            public_key = private_key.public_key()

            # Perform ECDH
            shared_key = private_key.exchange(ec.ECDH(), pub_key)

            # The encapsulation includes the ephemeral public key
            encapsulation = {
                "ephemeral_public_key": public_key.public_bytes(
                    encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
                ).decode("ascii"),
                "pq_ciphertext": pq_ciphertext.hex(),
            }

        elif public_key_dict["kty"] == "RSA":
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            # Generate a random secret
            shared_key = os.urandom(32)

            # Encrypt with RSA-OAEP
            pub_key = load_pem_public_key(public_key_dict["public_key"].encode("ascii"))

            ciphertext = pub_key.encrypt(
                shared_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            encapsulation = {"ciphertext": ciphertext.hex(), "pq_ciphertext": pq_ciphertext.hex()}
        else:
            raise ValueError(f"Unsupported key type: {public_key_dict['kty']}")

        # Combine both shared secrets using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 512 bits
            salt=None,
            info=b"hybrid_kem_shared_secret",
        )

        combined_secret = hkdf.derive(shared_key + pq_shared_secret)

        return combined_secret, encapsulation

    def decapsulate_hybrid(self, encapsulation: dict, private_key_dict: dict) -> bytes:
        """
        Decapsulate a shared secret using the recipient's private key.

        Args:
            encapsulation: The encapsulation data from the sender
            private_key_dict: The recipient's private key dictionary

        Returns:
            The shared secret
        """
        # Decapsulate the Kyber shared secret
        pq_ciphertext = bytes.fromhex(encapsulation["pq_ciphertext"])
        pq_shared_secret = self.kem.decapsulate(
            pq_ciphertext, bytes.fromhex(private_key_dict["pq_kem_private_key"])
        )

        # Decapsulate the classical shared secret
        if private_key_dict["kty"] == "EC":
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            # Load the private key
            private_key = load_pem_private_key(
                private_key_dict["private_key"].encode("ascii"), password=None
            )

            # Load the ephemeral public key
            pub_key = load_pem_public_key(encapsulation["ephemeral_public_key"].encode("ascii"))

            # Perform ECDH
            shared_key = private_key.exchange(ec.ECDH(), pub_key)

        elif private_key_dict["kty"] == "RSA":
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            # Load the private key
            private_key = load_pem_private_key(
                private_key_dict["private_key"].encode("ascii"), password=None
            )

            # Decrypt with RSA-OAEP
            shared_key = private_key.decrypt(
                bytes.fromhex(encapsulation["ciphertext"]),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            raise ValueError(f"Unsupported key type: {private_key_dict['kty']}")

        # Combine both shared secrets using HKDF (same as in encapsulate)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 512 bits
            salt=None,
            info=b"hybrid_kem_shared_secret",
        )

        return hkdf.derive(shared_key + pq_shared_secret)

    # ===== Hybrid Signatures =====

    def generate_hybrid_signing_keypair(self) -> Tuple[dict, dict]:
        """
        Generate a hybrid signing key pair (combining ECDSA and Dilithium).

        Returns:
            A tuple of (private_key_dict, public_key_dict)
        """
        # Generate ECDSA key pair (P-384)
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        # Serialize keys
        priv_pem = private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        ).decode("ascii")

        pub_pem = public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

        # Generate Dilithium key pair
        dilithium_keypair = self.signer.generate_keypair()

        # Combine into hybrid key pair
        private_data = {
            "kty": "EC",
            "curve": "secp384r1",
            "private_key": priv_pem,
            "public_key": pub_pem,
            "pq_sig_private_key": dilithium_keypair.secret_key.hex(),
            "pq_sig_public_key": dilithium_keypair.public_key.hex(),
            "pq_sig_variant": self.sig_variant.value,
        }

        public_data = {
            "kty": "EC",
            "curve": "secp384r1",
            "public_key": pub_pem,
            "pq_sig_public_key": dilithium_keypair.public_key.hex(),
            "pq_sig_variant": self.sig_variant.value,
        }

        return private_data, public_data

    def sign_hybrid(self, message: bytes, private_key_dict: dict) -> dict:
        """
        Sign a message using both ECDSA and Dilithium.

        Args:
            message: The message to sign
            private_key_dict: The signer's private key dictionary

        Returns:
            A dictionary containing both signatures
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        # Load the ECDSA private key
        private_key = load_pem_private_key(
            private_key_dict["private_key"].encode("ascii"), password=None
        )

        # Sign with ECDSA
        ecdsa_signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))

        # Sign with Dilithium
        dilithium_sig = self.signer.sign(
            message, bytes.fromhex(private_key_dict["pq_sig_private_key"])
        )

        return {
            "ecdsa_signature": ecdsa_signature.hex(),
            "dilithium_signature": dilithium_sig.hex(),
            "algorithm": "ECDSA_WITH_DILITHIUM",
            "pq_sig_variant": self.sig_variant.value,
        }

    def verify_hybrid(self, message: bytes, signature_dict: dict, public_key_dict: dict) -> bool:
        """
        Verify a hybrid signature.

        Args:
            message: The signed message
            signature_dict: The signature dictionary from sign_hybrid
            public_key_dict: The signer's public key dictionary

        Returns:
            True if both signatures are valid, False otherwise
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        # Verify ECDSA signature
        try:
            public_key = load_pem_public_key(public_key_dict["public_key"].encode("ascii"))

            public_key.verify(
                bytes.fromhex(signature_dict["ecdsa_signature"]), message, ec.ECDSA(hashes.SHA384())
            )
            ecdsa_valid = True
        except (InvalidSignature, ValueError):
            ecdsa_valid = False

        # Verify Dilithium signature
        dilithium_valid = self.signer.verify(
            message,
            bytes.fromhex(signature_dict["dilithium_signature"]),
            bytes.fromhex(public_key_dict["pq_sig_public_key"]),
        )

        # Return True only if both signatures are valid
        return ecdsa_valid and dilithium_valid

    # ===== Hybrid Encryption =====

    def encrypt_hybrid(
        self, message: bytes, public_key_dict: dict, aad: Optional[bytes] = None
    ) -> dict:
        """
        Encrypt a message using hybrid encryption.

        The encryption uses:
        1. A random symmetric key is generated for AES-256-GCM
        2. The symmetric key is encrypted using hybrid KEM
        3. The message is encrypted with the symmetric key

        Args:
            message: The message to encrypt
            public_key_dict: The recipient's public key dictionary
            aad: Optional additional authenticated data

        Returns:
            A dictionary containing the encrypted message and metadata
        """
        # Generate a random symmetric key and nonce
        symmetric_key = os.urandom(32)  # 256-bit key for AES-256
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM

        # Encrypt the symmetric key using hybrid KEM
        shared_secret, encapsulation = self.encapsulate_hybrid(public_key_dict)

        # Derive encryption and MAC keys from the shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption, 32 for MAC
            salt=None,
            info=b"hybrid_encryption_key_derivation",
        )

        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:32]  # First 32 bytes for encryption
        mac_key = key_material[32:]  # Next 32 bytes for MAC

        # Encrypt the message with AES-256-GCM
        cipher = AESGCM(enc_key)
        ciphertext = cipher.encrypt(nonce, message, aad)

        # The last 16 bytes are the authentication tag
        encrypted_message = ciphertext[:-16]
        tag = ciphertext[-16:]

        # Create a MAC of the ciphertext and AAD
        hmac_obj = hmac.HMAC(mac_key, hashes.SHA256())
        if aad:
            hmac_obj.update(aad)
        hmac_obj.update(nonce)
        hmac_obj.update(encrypted_message)
        hmac_obj.update(tag)
        mac = hmac_obj.finalize()

        return {
            "version": "hybrid-encryption-v1",
            "ciphertext": encrypted_message.hex(),
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "mac": mac.hex(),
            "encapsulation": encapsulation,
            "algorithm": "AES-256-GCM",
            "aad": aad.hex() if aad else None,
        }

    def decrypt_hybrid(
        self, encrypted_data: dict, private_key_dict: dict, aad: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt a message that was encrypted with encrypt_hybrid.

        Args:
            encrypted_data: The encrypted data dictionary from encrypt_hybrid
            private_key_dict: The recipient's private key dictionary
            aad: Optional additional authenticated data (must match the original)

        Returns:
            The decrypted message

        Raises:
            ValueError: If decryption or verification fails
        """
        # Check if AAD was provided and matches the original
        if aad is not None and "aad" in encrypted_data:
            if aad.hex() != encrypted_data["aad"]:
                raise ValueError("Additional authenticated data does not match")

        # Decapsulate the shared secret
        shared_secret = self.decapsulate_hybrid(encrypted_data["encapsulation"], private_key_dict)

        # Derive the same encryption and MAC keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption, 32 for MAC
            salt=None,
            info=b"hybrid_encryption_key_derivation",
        )

        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:32]  # First 32 bytes for encryption
        mac_key = key_material[32:]  # Next 32 bytes for MAC

        # Verify the MAC
        hmac_obj = hmac.HMAC(mac_key, hashes.SHA256())
        if aad:
            hmac_obj.update(aad)
        hmac_obj.update(bytes.fromhex(encrypted_data["nonce"]))
        hmac_obj.update(bytes.fromhex(encrypted_data["ciphertext"]))
        hmac_obj.update(bytes.fromhex(encrypted_data["tag"]))

        try:
            hmac_obj.verify(bytes.fromhex(encrypted_data["mac"]))
        except Exception as e:
            raise ValueError("MAC verification failed") from e

        # Decrypt the message
        cipher = AESGCM(enc_key)
        try:
            plaintext = cipher.decrypt(
                bytes.fromhex(encrypted_data["nonce"]),
                bytes.fromhex(encrypted_data["ciphertext"] + encrypted_data["tag"]),
                aad,
            )
            return plaintext
        except Exception as e:
            raise ValueError("Decryption failed") from e

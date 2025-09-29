"""
Hardware Security Module (HSM) Interface

This module provides a unified interface for Hardware Security Modules (HSMs)
and PKCS#11 devices, with support for post-quantum cryptography operations.
"""

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Union

# Try to import PKCS#11 library
try:
    import PyKCS11

    HAS_PKCS11 = True
except ImportError:
    HAS_PKCS11 = False

# Try to import AWS KMS client
try:
    import boto3
    from botocore.exceptions import ClientError

    HAS_AWS_KMS = True
except ImportError:
    HAS_AWS_KMS = False

# Try to import Azure Key Vault client
try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.keys.crypto import (
        CryptographyClient,
        EncryptionAlgorithm,
        KeyWrapAlgorithm,
        SignatureAlgorithm,
    )

    HAS_AZURE_KV = True
except ImportError:
    HAS_AZURE_KV = False

# Try to import Google Cloud KMS client
try:
    from google.api_core.exceptions import GoogleAPICallError
    from google.cloud import kms

    HAS_GCP_KMS = True
except ImportError:
    HAS_GCP_KMS = False


class HSMType(Enum):
    """Supported HSM types."""

    PKCS11 = "pkcs11"
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GCP_KMS = "gcp_kms"
    SOFT_HSM = "soft_hsm"  # Software-based HSM for testing


class KeyType(Enum):
    """Supported key types."""

    RSA = "rsa"
    EC = "ec"
    AES = "aes"
    CHACHA20 = "chacha20"
    KYBER = "kyber"  # Post-quantum KEM
    DILITHIUM = "dilithium"  # Post-quantum signature


class KeyUsage(Enum):
    """Key usage flags."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    WRAP = "wrap"
    UNWRAP = "unwrap"
    DERIVE = "derive"
    KEY_AGREEMENT = "key_agreement"


@dataclass
class HSMKey:
    """Represents a key stored in an HSM."""

    key_id: str
    key_type: KeyType
    public_key: Optional[bytes] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    key_ops: List[KeyUsage] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the key to a dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "public_key": self.public_key.hex() if self.public_key else None,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "key_ops": [op.value for op in self.key_ops],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HSMKey":
        """Deserialize a key from a dictionary."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            public_key=bytes.fromhex(data["public_key"]) if data.get("public_key") else None,
            algorithm=data.get("algorithm"),
            key_size=data.get("key_size"),
            key_ops=[KeyUsage(op) for op in data.get("key_ops", [])],
            metadata=data.get("metadata", {}),
        )


class HSMInterface:
    """
    Unified interface for Hardware Security Modules (HSMs).

    This class provides a common interface for interacting with various HSM
    implementations, including PKCS#11 devices, AWS KMS, Azure Key Vault, and GCP KMS.
    """

    def __init__(self, hsm_type: HSMType, **config):
        """
        Initialize the HSM interface.

        Args:
            hsm_type: The type of HSM to use
            **config: Configuration parameters for the HSM
        """
        self.hsm_type = hsm_type
        self.config = config
        self._client = None
        self._session = None
        self._logger = logging.getLogger(__name__)

        # Initialize the appropriate HSM client
        if hsm_type == HSMType.PKCS11 and HAS_PKCS11:
            self._init_pkcs11()
        elif hsm_type == HSMType.AWS_KMS and HAS_AWS_KMS:
            self._init_aws_kms()
        elif hsm_type == HSMType.AZURE_KEY_VAULT and HAS_AZURE_KV:
            self._init_azure_kv()
        elif hsm_type == HSMType.GCP_KMS and HAS_GCP_KMS:
            self._init_gcp_kms()
        elif hsm_type == HSMType.SOFT_HSM:
            self._init_soft_hsm()
        else:
            raise ValueError(f"Unsupported HSM type: {hsm_type}")

    def _init_pkcs11(self) -> None:
        """Initialize a PKCS#11 HSM client."""
        if not HAS_PKCS11:
            raise ImportError("PyKCS11 is required for PKCS#11 support")

        lib = self.config.get("library_path")
        if not lib:
            raise ValueError("PKCS#11 library path is required")

        self._pkcs11 = PyKCS11.PyKCS11Lib()
        self._pkcs11.load(lib)

        # Get slots and log available tokens
        slots = self._pkcs11.getSlotList()
        self._logger.info(f"Found {len(slots)} PKCS#11 slots")

        # Use the first available slot by default
        self._slot = self.config.get("slot", slots[0] if slots else None)

        if self._slot is None:
            raise ValueError("No PKCS#11 slots available")

        self._logger.info(f"Using PKCS#11 slot: {self._slot}")

    def _init_aws_kms(self) -> None:
        """Initialize an AWS KMS client."""
        if not HAS_AWS_KMS:
            raise ImportError("boto3 is required for AWS KMS support")

        # Initialize the KMS client with the provided configuration
        self._kms = boto3.client("kms", **self.config.get("client_config", {}))
        self._logger.info("Initialized AWS KMS client")

    def _init_azure_kv(self) -> None:
        """Initialize an Azure Key Vault client."""
        if not HAS_AZURE_KV:
            raise ImportError(
                "azure-identity and azure-keyvault-keys are required for Azure Key Vault support"
            )

        vault_url = self.config.get("vault_url")
        if not vault_url:
            raise ValueError("Azure Key Vault URL is required")

        # Initialize the Azure credentials and key client
        credential = DefaultAzureCredential()
        self._key_client = KeyClient(vault_url=vault_url, credential=credential)
        self._logger.info(f"Initialized Azure Key Vault client for {vault_url}")

    def _init_gcp_kms(self) -> None:
        """Initialize a GCP KMS client."""
        if not HAS_GCP_KMS:
            raise ImportError("google-cloud-kms is required for GCP KMS support")

        # Initialize the KMS client
        self._gcp_client = kms.KeyManagementServiceClient()

        # Get the key ring and location from config
        self._project_id = self.config.get("project_id")
        self._location = self.config.get("location", "global")
        self._key_ring = self.config.get("key_ring", "scrambled-eggs")

        # Create the key ring path
        self._key_ring_path = self._gcp_client.key_ring_path(
            self._project_id, self._location, self._key_ring
        )

        # Ensure the key ring exists
        try:
            self._gcp_client.get_key_ring(name=self._key_ring_path)
        except GoogleAPICallError:
            if self.config.get("create_key_ring", False):
                parent = f"projects/{self._project_id}/locations/{self._location}"
                self._gcp_client.create_key_ring(
                    parent=parent,
                    key_ring_id=self._key_ring,
                    key_ring={"name": self._key_ring_path},
                )
                self._logger.info(f"Created key ring: {self._key_ring_path}")
            else:
                raise ValueError(
                    f"Key ring {self._key_ring_path} not found and create_key_ring is False"
                )

        self._logger.info(f"Initialized GCP KMS client for {self._key_ring_path}")

    def _init_soft_hsm(self) -> None:
        """Initialize a software-based HSM for testing."""
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._logger.info("Initialized software HSM (for testing only)")

    def connect(self, **kwargs) -> bool:
        """
        Connect to the HSM.

        Args:
            **kwargs: Additional connection parameters

        Returns:
            True if the connection was successful, False otherwise
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                pin = kwargs.get("pin", self.config.get("pin"))
                if not pin:
                    raise ValueError("PIN is required for PKCS#11")

                self._session = self._pkcs11.openSession(
                    self._slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
                )
                self._session.login(pin)
                self._logger.info("Connected to PKCS#11 HSM")
                return True

            elif self.hsm_type in (
                HSMType.AWS_KMS,
                HSMType.AZURE_KEY_VAULT,
                HSMType.GCP_KMS,
                HSMType.SOFT_HSM,
            ):
                # These services are connectionless
                return True

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Failed to connect to HSM: {str(e)}")
            return False

    def disconnect(self) -> None:
        """Disconnect from the HSM."""
        try:
            if self.hsm_type == HSMType.PKCS11 and hasattr(self, "_session") and self._session:
                try:
                    self._session.logout()
                except:
                    pass
                self._session.closeSession()
                self._session = None
                self._logger.info("Disconnected from PKCS#11 HSM")

        except Exception as e:
            self._logger.error(f"Error disconnecting from HSM: {str(e)}")

    def create_key(
        self,
        key_id: str,
        key_type: KeyType,
        key_size: int = 256,
        key_ops: Optional[List[KeyUsage]] = None,
        **kwargs,
    ) -> Optional[HSMKey]:
        """
        Create a new key in the HSM.

        Args:
            key_id: A unique identifier for the key
            key_type: The type of key to create
            key_size: The key size in bits
            key_ops: List of key operations this key can perform
            **kwargs: Additional key creation parameters

        Returns:
            An HSMKey object representing the created key, or None on failure
        """
        if not key_ops:
            key_ops = [op for op in KeyUsage]  # All operations by default

        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._create_pkcs11_key(key_id, key_type, key_size, key_ops, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._create_aws_kms_key(key_id, key_type, key_size, key_ops, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._create_azure_kv_key(key_id, key_type, key_size, key_ops, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._create_gcp_kms_key(key_id, key_type, key_size, key_ops, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._create_soft_hsm_key(key_id, key_type, key_size, key_ops, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Failed to create key: {str(e)}")
            return None

    def _create_pkcs11_key(
        self, key_id: str, key_type: KeyType, key_size: int, key_ops: List[KeyUsage], **kwargs
    ) -> HSMKey:
        """Create a key in a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Map key type to PKCS#11 mechanism
        if key_type == KeyType.RSA:
            mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN)

            # Define key attributes
            pub_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_VERIFY, True),
                (PyKCS11.CKA_ENCRYPT, KeyUsage.ENCRYPT in key_ops),
                (PyKCS11.CKA_WRAP, KeyUsage.WRAP in key_ops),
                (PyKCS11.CKA_MODULUS_BITS, key_size),
                (PyKCS11.CKA_PUBLIC_EXPONENT, (1, 0, 1)),  # 65537
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]

            priv_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_PRIVATE, True),
                (PyKCS11.CKA_SIGN, KeyUsage.SIGN in key_ops),
                (PyKCS11.CKA_DECRYPT, KeyUsage.DECRYPT in key_ops),
                (PyKCS11.CKA_UNWRAP, KeyUsage.UNWRAP in key_ops),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]

            # Generate the key pair
            pub_key, priv_key = self._session.generateKeyPair(
                pub_template, priv_template, mech=mech
            )

            # Get the public key attributes
            pub_attrs = self._session.getAttributeValue(
                pub_key, [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT]
            )

            # Create the HSMKey object
            return HSMKey(
                key_id=key_id,
                key_type=key_type,
                public_key=pub_attrs[0],  # Modulus
                algorithm=f"RSA-{key_size}",
                key_size=key_size,
                key_ops=key_ops,
                metadata={"pkcs11_public_handle": pub_key, "pkcs11_private_handle": priv_key},
            )

        elif key_type == KeyType.EC:
            # Similar implementation for EC keys
            raise NotImplementedError("EC key generation not implemented for PKCS#11")

        else:
            raise ValueError(f"Unsupported key type for PKCS#11: {key_type}")

    def _create_aws_kms_key(
        self, key_id: str, key_type: KeyType, key_size: int, key_ops: List[KeyUsage], **kwargs
    ) -> HSMKey:
        """Create a key in AWS KMS."""
        # Map key type to AWS KMS key spec
        if key_type == KeyType.RSA:
            if key_size == 2048:
                key_spec = "RSA_2048"
            elif key_size == 3072:
                key_spec = "RSA_3072"
            elif key_size == 4096:
                key_spec = "RSA_4096"
            else:
                raise ValueError(f"Unsupported RSA key size: {key_size}")
        elif key_type == KeyType.EC:
            if key_size == 256:
                key_spec = "ECC_NIST_P256"
            elif key_size == 384:
                key_spec = "ECC_NIST_P384"
            elif key_size == 521:
                key_spec = "ECC_NIST_P521"
            else:
                raise ValueError(f"Unsupported EC key size: {key_size}")
        else:
            raise ValueError(f"Unsupported key type for AWS KMS: {key_type}")

        # Determine key usage based on requested operations
        key_usage = "SIGN_VERIFY"
        if KeyUsage.ENCRYPT in key_ops or KeyUsage.DECRYPT in key_ops:
            key_usage = "ENCRYPT_DECRYPT"

        # Create the key
        try:
            response = self._kms.create_key(
                Policy=kwargs.get("policy"),
                Description=kwargs.get("description", f"Scrambled Eggs Key: {key_id}"),
                KeyUsage=key_usage,
                CustomerMasterKeySpec=key_spec,
                Tags=kwargs.get("tags", []),
                MultiRegion=kwargs.get("multi_region", False),
            )

            key_metadata = response["KeyMetadata"]

            # Get the public key
            if key_type == KeyType.RSA:
                public_key = self._kms.get_public_key(KeyId=key_metadata["KeyId"])["PublicKey"]
            else:
                public_key = None  # EC public key is not directly accessible

            return HSMKey(
                key_id=key_metadata["KeyId"],
                key_type=key_type,
                public_key=public_key,
                algorithm=key_spec,
                key_size=key_size,
                key_ops=key_ops,
                metadata={"aws_key_arn": key_metadata["Arn"], "aws_key_id": key_metadata["KeyId"]},
            )

        except ClientError as e:
            self._logger.error(f"AWS KMS error: {str(e)}")
            raise

    def _create_azure_kv_key(
        self, key_id: str, key_type: KeyType, key_size: int, key_ops: List[KeyUsage], **kwargs
    ) -> HSMKey:
        """Create a key in Azure Key Vault."""
        from azure.keyvault.keys import KeyType as AzureKeyType

        # Map key type to Azure Key Vault key type
        if key_type == KeyType.RSA:
            azure_key_type = AzureKeyType.rsa
        elif key_type == KeyType.EC:
            azure_key_type = AzureKeyType.ec
        else:
            raise ValueError(f"Unsupported key type for Azure Key Vault: {key_type}")

        # Create the key
        key = self._key_client.create_rsa_key(name=key_id, size=key_size, **kwargs)

        # Get the public key
        public_key = key.key.n.to_bytes((key.key.n.bit_length() + 7) // 8, "big")

        return HSMKey(
            key_id=key_id,
            key_type=key_type,
            public_key=public_key,
            algorithm=f"RSA-{key_size}",
            key_size=key_size,
            key_ops=key_ops,
            metadata={
                "azure_key_id": key.id,
                "azure_key_vault_url": self._key_client.vault_url,
                "azure_key_version": key.properties.version,
            },
        )

    def _create_gcp_kms_key(
        self, key_id: str, key_type: KeyType, key_size: int, key_ops: List[KeyUsage], **kwargs
    ) -> HSMKey:
        """Create a key in GCP KMS."""
        from google.cloud.kms import CryptoKey, CryptoKeyVersionTemplate
        from google.cloud.kms_v1.types import CryptoKeyVersion, CryptoKeyVersionTemplate

        # Map key type to GCP KMS algorithm
        if key_type == KeyType.RSA:
            if key_size == 2048:
                algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256
            elif key_size == 3072:
                algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256
            elif key_size == 4096:
                algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256
            else:
                raise ValueError(f"Unsupported RSA key size: {key_size}")
        else:
            raise ValueError(f"Unsupported key type for GCP KMS: {key_type}")

        # Create the key ring if it doesn't exist
        key_ring_path = self._gcp_client.key_ring_path(
            self._project_id, self._location, self._key_ring
        )

        # Create the key
        key = {
            "purpose": CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
            "version_template": {
                "algorithm": algorithm,
                "protection_level": kwargs.get("protection_level", "HSM"),
            },
            "labels": kwargs.get("labels", {"application": "scrambled-eggs"}),
        }

        request = {
            "parent": key_ring_path,
            "crypto_key_id": key_id,
            "crypto_key": key,
            "skip_initial_version_creation": False,
        }

        # Add IAM policy bindings if provided
        if "policy" in kwargs:
            request["crypto_key"][
                "version_destruction_behavior"
            ] = CryptoKey.VersionDestructionBehavior.DESTRUCTION_SCHEDULE

            # Set IAM policy
            policy = self._gcp_client.get_iam_policy(
                request={"resource": f"{key_ring_path}/cryptoKeys/{key_id}"}
            )

            # Add bindings from the provided policy
            for binding in kwargs["policy"].get("bindings", []):
                policy.bindings.append(binding)

            self._gcp_client.set_iam_policy(
                request={"resource": f"{key_ring_path}/cryptoKeys/{key_id}", "policy": policy}
            )

        # Create the key
        key = self._gcp_client.create_crypto_key(request=request)

        # Get the public key
        public_key = self._gcp_client.get_public_key(
            request={"name": f"{key.name}/cryptoKeyVersions/1"}
        )

        return HSMKey(
            key_id=key_id,
            key_type=key_type,
            public_key=public_key.pem.encode("utf-8"),
            algorithm=algorithm.name,
            key_size=key_size,
            key_ops=key_ops,
            metadata={
                "gcp_key_name": key.name,
                "gcp_key_ring": key_ring_path,
                "gcp_key_version": "1",
            },
        )

    def _create_soft_hsm_key(
        self, key_id: str, key_type: KeyType, key_size: int, key_ops: List[KeyUsage], **kwargs
    ) -> HSMKey:
        """Create a key in the software HSM (for testing only)."""
        import secrets

        # Generate a random key
        key = secrets.token_bytes(key_size // 8)

        # Store the key in memory
        self._keys[key_id] = {
            "key": key,
            "key_type": key_type,
            "key_size": key_size,
            "key_ops": key_ops,
            "created_at": datetime.datetime.utcnow().isoformat(),
            **kwargs,
        }

        # For RSA/EC, we'd normally generate a key pair, but for simplicity,
        # we'll just use the random bytes as the "public key" in this test implementation
        return HSMKey(
            key_id=key_id,
            key_type=key_type,
            public_key=key,
            algorithm=f"{key_type.value.upper()}-{key_size}",
            key_size=key_size,
            key_ops=key_ops,
            metadata={"test": True, "created_at": self._keys[key_id]["created_at"]},
        )

    def sign(
        self, key_id: str, data: bytes, algorithm: str = "SHA256", **kwargs
    ) -> Optional[bytes]:
        """
        Sign data using a key stored in the HSM.

        Args:
            key_id: The ID of the key to use for signing
            data: The data to sign
            algorithm: The signing algorithm to use
            **kwargs: Additional parameters

        Returns:
            The signature, or None on failure
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._sign_pkcs11(key_id, data, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._sign_aws_kms(key_id, data, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._sign_azure_kv(key_id, data, algorithm, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._sign_gcp_kms(key_id, data, algorithm, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._sign_soft_hsm(key_id, data, algorithm, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Signing failed: {str(e)}")
            return None

    def _sign_pkcs11(self, key_id: str, data: bytes, algorithm: str, **kwargs) -> bytes:
        """Sign data using a key in a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Find the private key by label
        priv_key = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]
        )[0]

        # Map algorithm to PKCS#11 mechanism
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA384_RSA_PKCS, None)
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA512_RSA_PKCS, None)
        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}")

        # Sign the data
        signature = self._session.sign(priv_key, data, mech)
        return bytes(signature)

    def _sign_aws_kms(self, key_id: str, data: bytes, algorithm: str, **kwargs) -> bytes:
        """Sign data using a key in AWS KMS."""
        # Map algorithm to AWS KMS signing algorithm
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_256"
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_384"
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_512"
        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}")

        # Sign the data
        response = self._kms.sign(
            KeyId=key_id, Message=data, MessageType="RAW", SigningAlgorithm=signing_algorithm
        )

        return response["Signature"]

    def _sign_azure_kv(self, key_id: str, data: bytes, algorithm: str, **kwargs) -> bytes:
        """Sign data using a key in Azure Key Vault."""
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

        # Map algorithm to Azure Key Vault signature algorithm
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            sig_algorithm = SignatureAlgorithm.rs256
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            sig_algorithm = SignatureAlgorithm.rs384
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            sig_algorithm = SignatureAlgorithm.rs512
        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}")

        # Get the crypto client for the key
        crypto_client = CryptographyClient(
            f"{self._key_client.vault_url}keys/{key_id}", DefaultAzureCredential()
        )

        # Sign the data
        result = crypto_client.sign(sig_algorithm, data)
        return result.signature

    def _sign_gcp_kms(self, key_id: str, data: bytes, algorithm: str, **kwargs) -> bytes:
        """Sign data using a key in GCP KMS."""
        from google.cloud.kms_v1 import Digest

        # Map algorithm to GCP KMS digest
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            digest = Digest(sha256=hashlib.sha256(data).digest())
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            digest = Digest(sha384=hashlib.sha384(data).digest())
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            digest = Digest(sha512=hashlib.sha512(data).digest())
        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}")

        # Sign the digest
        response = self._gcp_client.asymmetric_sign(
            name=f"{self._key_ring_path}/cryptoKeys/{key_id}/cryptoKeyVersions/1", digest=digest
        )

        return response.signature

    def _sign_soft_hsm(self, key_id: str, data: bytes, algorithm: str, **kwargs) -> bytes:
        """Sign data using a key in the software HSM (for testing only)."""
        if key_id not in self._keys:
            raise ValueError(f"Key not found: {key_id}")

        # In a real implementation, we would use the key to sign the data
        # For testing, we'll just return a hash of the data
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            return hashlib.sha256(data).digest()
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            return hashlib.sha384(data).digest()
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            return hashlib.sha512(data).digest()
        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}")

    def verify(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str = "SHA256", **kwargs
    ) -> bool:
        """
        Verify a signature using a key stored in the HSM.

        Args:
            key_id: The ID of the key to use for verification
            data: The original data that was signed
            signature: The signature to verify
            algorithm: The signing algorithm that was used
            **kwargs: Additional parameters

        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._verify_pkcs11(key_id, data, signature, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._verify_aws_kms(key_id, data, signature, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._verify_azure_kv(key_id, data, signature, algorithm, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._verify_gcp_kms(key_id, data, signature, algorithm, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._verify_soft_hsm(key_id, data, signature, algorithm, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Verification failed: {str(e)}")
            return False

    def _verify_pkcs11(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str, **kwargs
    ) -> bool:
        """Verify a signature using a key in a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Find the public key by label
        pub_key = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]
        )[0]

        # Map algorithm to PKCS#11 mechanism
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA384_RSA_PKCS, None)
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA512_RSA_PKCS, None)
        else:
            raise ValueError(f"Unsupported verification algorithm: {algorithm}")

        # Verify the signature
        try:
            self._session.verify(pub_key, data, signature, mech)
            return True
        except PyKCS11.PyKCS11Error:
            return False

    def _verify_aws_kms(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str, **kwargs
    ) -> bool:
        """Verify a signature using a key in AWS KMS."""
        # Map algorithm to AWS KMS signing algorithm
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_256"
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_384"
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_512"
        else:
            raise ValueError(f"Unsupported verification algorithm: {algorithm}")

        # Verify the signature
        try:
            self._kms.verify(
                KeyId=key_id,
                Message=data,
                MessageType="RAW",
                Signature=signature,
                SigningAlgorithm=signing_algorithm,
            )
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "KMSInvalidSignatureException":
                return False
            raise

    def _verify_azure_kv(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str, **kwargs
    ) -> bool:
        """Verify a signature using a key in Azure Key Vault."""
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

        # Map algorithm to Azure Key Vault signature algorithm
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            sig_algorithm = SignatureAlgorithm.rs256
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            sig_algorithm = SignatureAlgorithm.rs384
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            sig_algorithm = SignatureAlgorithm.rs512
        else:
            raise ValueError(f"Unsupported verification algorithm: {algorithm}")

        # Get the crypto client for the key
        crypto_client = CryptographyClient(
            f"{self._key_client.vault_url}keys/{key_id}", DefaultAzureCredential()
        )

        # Verify the signature
        try:
            result = crypto_client.verify(sig_algorithm, data, signature)
            return result.is_valid
        except Exception:
            return False

    def _verify_gcp_kms(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str, **kwargs
    ) -> bool:
        """Verify a signature using a key in GCP KMS."""
        from google.cloud.kms_v1 import Digest

        # Map algorithm to GCP KMS digest
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            digest = Digest(sha256=hashlib.sha256(data).digest())
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            digest = Digest(sha384=hashlib.sha384(data).digest())
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            digest = Digest(sha512=hashlib.sha512(data).digest())
        else:
            raise ValueError(f"Unsupported verification algorithm: {algorithm}")

        # Verify the signature
        try:
            response = self._gcp_client.asymmetric_verify(
                name=f"{self._key_ring_path}/cryptoKeys/{key_id}/cryptoKeyVersions/1",
                digest=digest,
                signature=signature,
            )
            return response.success
        except Exception:
            return False

    def _verify_soft_hsm(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str, **kwargs
    ) -> bool:
        """Verify a signature using a key in the software HSM (for testing only)."""
        if key_id not in self._keys:
            return False

        # In a real implementation, we would verify the signature using the public key
        # For testing, we'll just compare with a hash of the data
        if algorithm.upper() == "SHA256" or algorithm.upper() == "SHA-256":
            return signature == hashlib.sha256(data).digest()
        elif algorithm.upper() == "SHA384" or algorithm.upper() == "SHA-384":
            return signature == hashlib.sha384(data).digest()
        elif algorithm.upper() == "SHA512" or algorithm.upper() == "SHA-512":
            return signature == hashlib.sha512(data).digest()
        else:
            raise ValueError(f"Unsupported verification algorithm: {algorithm}")

    def encrypt(
        self, key_id: str, plaintext: bytes, algorithm: str = "RSA-OAEP", **kwargs
    ) -> Optional[bytes]:
        """
        Encrypt data using a key stored in the HSM.

        Args:
            key_id: The ID of the key to use for encryption
            plaintext: The data to encrypt
            algorithm: The encryption algorithm to use
            **kwargs: Additional parameters

        Returns:
            The encrypted ciphertext, or None on failure
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._encrypt_pkcs11(key_id, plaintext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._encrypt_aws_kms(key_id, plaintext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._encrypt_azure_kv(key_id, plaintext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._encrypt_gcp_kms(key_id, plaintext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._encrypt_soft_hsm(key_id, plaintext, algorithm, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Encryption failed: {str(e)}")
            return None

    def _encrypt_pkcs11(self, key_id: str, plaintext: bytes, algorithm: str, **kwargs) -> bytes:
        """Encrypt data using a key in a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Find the public key by label
        pub_key = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]
        )[0]

        # Map algorithm to PKCS#11 mechanism
        if algorithm.upper() == "RSA-OAEP":
            mech = PyKCS11.RSA_PKCS_OAEP_Mechanism(PyKCS11.CKM_SHA256, PyKCS11.CKG_MGF1_SHA256)
        elif algorithm.upper() == "RSA-PKCS":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

        # Encrypt the data
        ciphertext = self._session.encrypt(pub_key, plaintext, mech)
        return bytes(ciphertext)

    def _encrypt_aws_kms(self, key_id: str, plaintext: bytes, algorithm: str, **kwargs) -> bytes:
        """Encrypt data using a key in AWS KMS."""
        # AWS KMS has a 4KB limit for direct encryption
        if len(plaintext) > 4096:
            raise ValueError("Plaintext too large for AWS KMS direct encryption (max 4KB)")

        # Map algorithm to AWS KMS encryption algorithm
        if algorithm.upper() == "RSA-OAEP" or algorithm.upper() == "RSAES_OAEP_SHA_256":
            encryption_algorithm = "RSAES_OAEP_SHA_256"
        elif algorithm.upper() == "RSA-PKCS" or algorithm.upper() == "RSAES_PKCS1_V1_5":
            encryption_algorithm = "RSAES_PKCS1_V1_5"
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

        # Encrypt the data
        response = self._kms.encrypt(
            KeyId=key_id, Plaintext=plaintext, EncryptionAlgorithm=encryption_algorithm
        )

        return response["CiphertextBlob"]

    def _encrypt_azure_kv(self, key_id: str, plaintext: bytes, algorithm: str, **kwargs) -> bytes:
        """Encrypt data using a key in Azure Key Vault."""
        from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm

        # Map algorithm to Azure Key Vault encryption algorithm
        if algorithm.upper() == "RSA-OAEP" or algorithm.upper() == "RSA-OAEP-256":
            enc_algorithm = EncryptionAlgorithm.rsa_oaep_256
        elif algorithm.upper() == "RSA-PKCS" or algorithm.upper() == "RSA1_5":
            enc_algorithm = EncryptionAlgorithm.rsa15
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

        # Get the crypto client for the key
        crypto_client = CryptographyClient(
            f"{self._key_client.vault_url}keys/{key_id}", DefaultAzureCredential()
        )

        # Encrypt the data
        result = crypto_client.encrypt(enc_algorithm, plaintext)
        return result.ciphertext

    def _encrypt_gcp_kms(self, key_id: str, plaintext: bytes, algorithm: str, **kwargs) -> bytes:
        """Encrypt data using a key in GCP KMS."""
        # GCP KMS doesn't support direct encryption with asymmetric keys
        # Instead, we'll use envelope encryption with a data encryption key (DEK)

        # Generate a random DEK
        dek = os.urandom(32)  # 256-bit key for AES-256-GCM

        # Encrypt the DEK with the KMS key
        response = self._gcp_client.encrypt(
            name=f"{self._key_ring_path}/cryptoKeys/{key_id}", plaintext=dek
        )

        # Encrypt the data with the DEK using AES-256-GCM
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Return the encrypted DEK, nonce, and ciphertext
        return json.dumps(
            {
                "encrypted_dek": response.ciphertext.hex(),
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            }
        ).encode("utf-8")

    def _encrypt_soft_hsm(self, key_id: str, plaintext: bytes, algorithm: str, **kwargs) -> bytes:
        """Encrypt data using a key in the software HSM (for testing only)."""
        if key_id not in self._keys:
            raise ValueError(f"Key not found: {key_id}")

        # In a real implementation, we would use the key to encrypt the data
        # For testing, we'll just XOR the plaintext with a repeating key
        key = self._keys[key_id]["key"]
        key_len = len(key)

        # Simple XOR encryption (not secure, for testing only)
        ciphertext = bytearray(plaintext)
        for i in range(len(ciphertext)):
            ciphertext[i] ^= key[i % key_len]

        return bytes(ciphertext)

    def decrypt(
        self, key_id: str, ciphertext: bytes, algorithm: str = "RSA-OAEP", **kwargs
    ) -> Optional[bytes]:
        """
        Decrypt data using a key stored in the HSM.

        Args:
            key_id: The ID of the key to use for decryption
            ciphertext: The data to decrypt
            algorithm: The decryption algorithm to use
            **kwargs: Additional parameters

        Returns:
            The decrypted plaintext, or None on failure
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._decrypt_pkcs11(key_id, ciphertext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._decrypt_aws_kms(key_id, ciphertext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._decrypt_azure_kv(key_id, ciphertext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._decrypt_gcp_kms(key_id, ciphertext, algorithm, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._decrypt_soft_hsm(key_id, ciphertext, algorithm, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Decryption failed: {str(e)}")
            return None

    def _decrypt_pkcs11(self, key_id: str, ciphertext: bytes, algorithm: str, **kwargs) -> bytes:
        """Decrypt data using a key in a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Find the private key by label
        priv_key = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]
        )[0]

        # Map algorithm to PKCS#11 mechanism
        if algorithm.upper() == "RSA-OAEP":
            mech = PyKCS11.RSA_PKCS_OAEP_Mechanism(PyKCS11.CKM_SHA256, PyKCS11.CKG_MGF1_SHA256)
        elif algorithm.upper() == "RSA-PKCS":
            mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
        else:
            raise ValueError(f"Unsupported decryption algorithm: {algorithm}")

        # Decrypt the data
        plaintext = self._session.decrypt(priv_key, ciphertext, mech)
        return bytes(plaintext)

    def _decrypt_aws_kms(self, key_id: str, ciphertext: bytes, algorithm: str, **kwargs) -> bytes:
        """Decrypt data using a key in AWS KMS."""
        # Map algorithm to AWS KMS encryption algorithm
        if algorithm.upper() == "RSA-OAEP" or algorithm.upper() == "RSAES_OAEP_SHA_256":
            encryption_algorithm = "RSAES_OAEP_SHA_256"
        elif algorithm.upper() == "RSA-PKCS" or algorithm.upper() == "RSAES_PKCS1_V1_5":
            encryption_algorithm = "RSAES_PKCS1_V1_5"
        else:
            raise ValueError(f"Unsupported decryption algorithm: {algorithm}")

        # Decrypt the data
        response = self._kms.decrypt(
            KeyId=key_id, CiphertextBlob=ciphertext, EncryptionAlgorithm=encryption_algorithm
        )

        return response["Plaintext"]

    def _decrypt_azure_kv(self, key_id: str, ciphertext: bytes, algorithm: str, **kwargs) -> bytes:
        """Decrypt data using a key in Azure Key Vault."""
        from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm

        # Map algorithm to Azure Key Vault encryption algorithm
        if algorithm.upper() == "RSA-OAEP" or algorithm.upper() == "RSA-OAEP-256":
            enc_algorithm = EncryptionAlgorithm.rsa_oaep_256
        elif algorithm.upper() == "RSA-PKCS" or algorithm.upper() == "RSA1_5":
            enc_algorithm = EncryptionAlgorithm.rsa15
        else:
            raise ValueError(f"Unsupported decryption algorithm: {algorithm}")

        # Get the crypto client for the key
        crypto_client = CryptographyClient(
            f"{self._key_client.vault_url}keys/{key_id}", DefaultAzureCredential()
        )

        # Decrypt the data
        result = crypto_client.decrypt(enc_algorithm, ciphertext)
        return result.plaintext

    def _decrypt_gcp_kms(self, key_id: str, ciphertext: bytes, algorithm: str, **kwargs) -> bytes:
        """Decrypt data using a key in GCP KMS."""
        # Parse the ciphertext (contains encrypted DEK, nonce, and ciphertext)
        try:
            data = json.loads(ciphertext.decode("utf-8"))
            encrypted_dek = bytes.fromhex(data["encrypted_dek"])
            nonce = bytes.fromhex(data["nonce"])
            ciphertext_bytes = bytes.fromhex(data["ciphertext"])
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError("Invalid ciphertext format") from e

        # Decrypt the DEK with the KMS key
        response = self._gcp_client.decrypt(
            name=f"{self._key_ring_path}/cryptoKeys/{key_id}", ciphertext=encrypted_dek
        )

        # Decrypt the data with the DEK using AES-256-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            aesgcm = AESGCM(response.plaintext)
            plaintext = aesgcm.decrypt(nonce, ciphertext_bytes, None)
            return plaintext
        except Exception as e:
            raise ValueError("Decryption failed") from e

    def _decrypt_soft_hsm(self, key_id: str, ciphertext: bytes, algorithm: str, **kwargs) -> bytes:
        """Decrypt data using a key in the software HSM (for testing only)."""
        if key_id not in self._keys:
            raise ValueError(f"Key not found: {key_id}")

        # In a real implementation, we would use the key to decrypt the data
        # For testing, we'll just XOR the ciphertext with the same key used for encryption
        key = self._keys[key_id]["key"]
        key_len = len(key)

        # Simple XOR decryption (not secure, for testing only)
        plaintext = bytearray(ciphertext)
        for i in range(len(plaintext)):
            plaintext[i] ^= key[i % key_len]

        return bytes(plaintext)

    def delete_key(self, key_id: str, **kwargs) -> bool:
        """
        Delete a key from the HSM.

        Args:
            key_id: The ID of the key to delete
            **kwargs: Additional parameters

        Returns:
            True if the key was deleted, False otherwise
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._delete_pkcs11_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._delete_aws_kms_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._delete_azure_kv_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._delete_gcp_kms_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._delete_soft_hsm_key(key_id, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Failed to delete key: {str(e)}")
            return False

    def _delete_pkcs11_key(self, key_id: str, **kwargs) -> bool:
        """Delete a key from a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Find and delete the private key
        priv_keys = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]
        )

        for key in priv_keys:
            self._session.destroyObject(key)

        # Find and delete the public key
        pub_keys = self._session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_LABEL, key_id.encode("utf-8")),
            ]
        )

        for key in pub_keys:
            self._session.destroyObject(key)

        return True

    def _delete_aws_kms_key(self, key_id: str, **kwargs) -> bool:
        """Schedule a key for deletion in AWS KMS."""
        # AWS KMS requires a minimum 7-day waiting period before actual deletion
        pending_window_in_days = kwargs.get("pending_window_in_days", 7)

        self._kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=pending_window_in_days)

        return True

    def _delete_azure_kv_key(self, key_id: str, **kwargs) -> bool:
        """Delete a key from Azure Key Vault."""
        # Start the key deletion process
        poller = self._key_client.begin_delete_key(key_id)

        # Wait for the deletion to complete
        deleted_key = poller.result()

        # Permanently delete the key (optional)
        if kwargs.get("purge", False):
            self._key_client.purge_deleted_key(key_id)

        return True

    def _delete_gcp_kms_key(self, key_id: str, **kwargs) -> bool:
        """Delete a key from GCP KMS."""
        # Schedule the key for destruction
        self._gcp_client.update_crypto_key_primary_version(
            name=f"{self._key_ring_path}/cryptoKeys/{key_id}",
            crypto_key_version_id="1",
            update_mask="primary_version_id",
            destroy_scheduled_duration=kwargs.get("schedule_days", 1) * 86400,  # Default 1 day
        )

        # If immediate deletion is requested, destroy the key version
        if kwargs.get("immediate", False):
            self._gcp_client.destroy_crypto_key_version(
                name=f"{self._key_ring_path}/cryptoKeys/{key_id}/cryptoKeyVersions/1"
            )

        return True

    def _delete_soft_hsm_key(self, key_id: str, **kwargs) -> bool:
        """Delete a key from the software HSM (for testing only)."""
        if key_id in self._keys:
            del self._keys[key_id]
            return True
        return False

    def list_keys(self, **kwargs) -> List[HSMKey]:
        """
        List all keys in the HSM.

        Args:
            **kwargs: Additional parameters

        Returns:
            A list of HSMKey objects
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._list_pkcs11_keys(**kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._list_aws_kms_keys(**kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._list_azure_kv_keys(**kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._list_gcp_kms_keys(**kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._list_soft_hsm_keys(**kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Failed to list keys: {str(e)}")
            return []

    def _list_pkcs11_keys(self, **kwargs) -> List[HSMKey]:
        """List all keys in a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        keys = []

        # Find all private keys
        priv_keys = self._session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])

        for key in priv_keys:
            try:
                # Get key attributes
                attrs = self._session.getAttributeValue(
                    key, [PyKCS11.CKA_LABEL, PyKCS11.CKA_KEY_TYPE, PyKCS11.CKA_ID]
                )

                key_id = attrs[0] if attrs[0] else attrs[2]  # Use label or ID as key ID
                if isinstance(key_id, bytes):
                    key_id = key_id.decode("utf-8", errors="replace")

                # Map key type
                if attrs[1] == PyKCS11.CKK_RSA:
                    key_type = KeyType.RSA
                    key_size = 2048  # Default, would need to get actual size
                elif attrs[1] == PyKCS11.CKK_EC:
                    key_type = KeyType.EC
                    key_size = 256  # Default, would need to get actual size
                else:
                    continue  # Skip unsupported key types

                # Get key operations
                key_ops = []
                if self._session.getAttributeValue(key, [PyKCS11.CKA_SIGN])[0]:
                    key_ops.append(KeyUsage.SIGN)
                if self._session.getAttributeValue(key, [PyKCS11.CKA_DECRYPT])[0]:
                    key_ops.append(KeyUsage.DECRYPT)
                if self._session.getAttributeValue(key, [PyKCS11.CKA_UNWRAP])[0]:
                    key_ops.append(KeyUsage.UNWRAP)

                # Create the HSMKey object
                keys.append(
                    HSMKey(
                        key_id=key_id,
                        key_type=key_type,
                        key_size=key_size,
                        key_ops=key_ops,
                        metadata={
                            "pkcs11_handle": key,
                            "key_type_name": PyKCS11.CKO.get(attrs[1], "UNKNOWN"),
                        },
                    )
                )

            except PyKCS11.PyKCS11Error as e:
                self._logger.warning(f"Error getting key attributes: {str(e)}")
                continue

        return keys

    def _list_aws_kms_keys(self, **kwargs) -> List[HSMKey]:
        """List all keys in AWS KMS."""
        keys = []

        # List all customer master keys (CMKs)
        paginator = self._kms.get_paginator("list_keys")

        for page in paginator.paginate():
            for key in page["Keys"]:
                try:
                    # Get key details
                    key_info = self._kms.describe_key(KeyId=key["KeyId"])
                    key_metadata = key_info["KeyMetadata"]

                    # Skip AWS-managed keys if requested
                    if (
                        kwargs.get("customer_managed_only", True)
                        and key_metadata["KeyManager"] != "CUSTOMER"
                    ):
                        continue

                    # Map key type
                    if key_metadata["KeySpec"].startswith("RSA"):
                        key_type = KeyType.RSA
                        key_size = int(key_metadata["KeySpec"].split("_")[-1])
                    elif key_metadata["KeySpec"].startswith("ECC"):
                        key_type = KeyType.EC
                        if "P_256" in key_metadata["KeySpec"]:
                            key_size = 256
                        elif "P_384" in key_metadata["KeySpec"]:
                            key_size = 384
                        elif "P_521" in key_metadata["KeySpec"]:
                            key_size = 521
                        else:
                            key_size = 256  # Default
                    else:
                        continue  # Skip unsupported key types

                    # Get key operations
                    key_ops = []
                    if key_metadata["KeyUsage"] == "SIGN_VERIFY":
                        key_ops.extend([KeyUsage.SIGN, KeyUsage.VERIFY])
                    elif key_metadata["KeyUsage"] == "ENCRYPT_DECRYPT":
                        key_ops.extend([KeyUsage.ENCRYPT, KeyUsage.DECRYPT])

                    # Create the HSMKey object
                    keys.append(
                        HSMKey(
                            key_id=key_metadata["KeyId"],
                            key_type=key_type,
                            key_size=key_size,
                            key_ops=key_ops,
                            metadata={
                                "arn": key_metadata["Arn"],
                                "key_manager": key_metadata["KeyManager"],
                                "key_state": key_metadata["KeyState"],
                                "creation_date": key_metadata["CreationDate"].isoformat(),
                                "description": key_metadata.get("Description", ""),
                            },
                        )
                    )

                except ClientError as e:
                    self._logger.warning(f"Error getting key info for {key['KeyId']}: {str(e)}")
                    continue

        return keys

    def _list_azure_kv_keys(self, **kwargs) -> List[HSMKey]:
        """List all keys in Azure Key Vault."""
        keys = []

        # List all keys
        for key_props in self._key_client.list_properties_of_keys():
            try:
                # Skip disabled keys if requested
                if kwargs.get("enabled_only", True) and not key_props.enabled:
                    continue

                # Get key details
                key = self._key_client.get_key(key_props.name, key_props.version)

                # Map key type
                if key.key_type.lower().startswith("rsa"):
                    key_type = KeyType.RSA
                    key_size = key.key_size
                elif key.key_type.lower().startswith("ec"):
                    key_type = KeyType.EC
                    key_size = key.key_size
                else:
                    continue  # Skip unsupported key types

                # Get key operations
                key_ops = []
                if "sign" in key.key_ops:
                    key_ops.append(KeyUsage.SIGN)
                if "verify" in key.key_ops:
                    key_ops.append(KeyUsage.VERIFY)
                if "encrypt" in key.key_ops:
                    key_ops.append(KeyUsage.ENCRYPT)
                if "decrypt" in key.key_ops:
                    key_ops.append(KeyUsage.DECRYPT)
                if "wrapKey" in key.key_ops:
                    key_ops.append(KeyUsage.WRAP)
                if "unwrapKey" in key.key_ops:
                    key_ops.append(KeyUsage.UNWRAP)

                # Create the HSMKey object
                keys.append(
                    HSMKey(
                        key_id=key.name,
                        key_type=key_type,
                        key_size=key_size,
                        key_ops=key_ops,
                        metadata={
                            "id": key.id,
                            "enabled": key_props.enabled,
                            "created": (
                                key_props.created_on.isoformat() if key_props.created_on else None
                            ),
                            "updated": (
                                key_props.updated_on.isoformat() if key_props.updated_on else None
                            ),
                            "recovery_level": key_props.recovery_level,
                        },
                    )
                )

            except Exception as e:
                self._logger.warning(f"Error getting key info for {key_props.name}: {str(e)}")
                continue

        return keys

    def _list_gcp_kms_keys(self, **kwargs) -> List[HSMKey]:
        """List all keys in GCP KMS."""
        keys = []

        # List all keys in the key ring
        for key in self._gcp_client.list_crypto_keys(
            parent=self._key_ring_path, filter_=kwargs.get("filter")
        ):
            try:
                # Skip disabled keys if requested
                if kwargs.get("enabled_only", True) and key.primary.state != 1:  # 1 = ENABLED
                    continue

                # Map key type
                if key.version_template.algorithm.name.startswith("RSA"):
                    key_type = KeyType.RSA
                    key_size = int(
                        key.version_template.algorithm.name.split("_")[-2]
                    )  # e.g., RSA_SIGN_PKCS1_2048_SHA256 -> 2048
                elif key.version_template.algorithm.name.startswith("EC"):
                    key_type = KeyType.EC
                    if "P256" in key.version_template.algorithm.name:
                        key_size = 256
                    elif "P384" in key.version_template.algorithm.name:
                        key_size = 384
                    else:
                        key_size = 256  # Default
                else:
                    continue  # Skip unsupported key types

                # Get key operations
                key_ops = []
                if "SIGN" in key.version_template.algorithm.name:
                    key_ops.extend([KeyUsage.SIGN, KeyUsage.VERIFY])
                elif "DECRYPT" in key.version_template.algorithm.name:
                    key_ops.extend([KeyUsage.ENCRYPT, KeyUsage.DECRYPT])

                # Create the HSMKey object
                keys.append(
                    HSMKey(
                        key_id=key.name.split("/")[-1],  # Extract just the key name
                        key_type=key_type,
                        key_size=key_size,
                        key_ops=key_ops,
                        metadata={
                            "name": key.name,
                            "create_time": key.create_time.ToDatetime().isoformat(),
                            "next_rotation_time": (
                                key.next_rotation_time.ToDatetime().isoformat()
                                if key.next_rotation_time
                                else None
                            ),
                            "rotation_period": (
                                key.rotation_period.seconds if key.rotation_period else None
                            ),
                            "version_template": {
                                "protection_level": key.version_template.protection_level,
                                "algorithm": key.version_template.algorithm.name,
                            },
                        },
                    )
                )

            except Exception as e:
                self._logger.warning(f"Error getting key info for {key.name}: {str(e)}")
                continue

        return keys

    def _list_soft_hsm_keys(self, **kwargs) -> List[HSMKey]:
        """List all keys in the software HSM (for testing only)."""
        keys = []

        for key_id, key_info in self._keys.items():
            keys.append(
                HSMKey(
                    key_id=key_id,
                    key_type=key_info["key_type"],
                    key_size=key_info["key_size"],
                    key_ops=key_info["key_ops"],
                    metadata={"created_at": key_info["created_at"], "test": True},
                )
            )

        return keys

    def get_key(self, key_id: str, **kwargs) -> Optional[HSMKey]:
        """
        Get a key by ID.

        Args:
            key_id: The ID of the key to retrieve
            **kwargs: Additional parameters

        Returns:
            The HSMKey object, or None if not found
        """
        try:
            if self.hsm_type == HSMType.PKCS11:
                return self._get_pkcs11_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.AWS_KMS:
                return self._get_aws_kms_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.AZURE_KEY_VAULT:
                return self._get_azure_kv_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.GCP_KMS:
                return self._get_gcp_kms_key(key_id, **kwargs)

            elif self.hsm_type == HSMType.SOFT_HSM:
                return self._get_soft_hsm_key(key_id, **kwargs)

            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_type}")

        except Exception as e:
            self._logger.error(f"Failed to get key: {str(e)}")
            return None

    def _get_pkcs11_key(self, key_id: str, **kwargs) -> Optional[HSMKey]:
        """Get a key from a PKCS#11 HSM."""
        if not hasattr(self, "_session") or not self._session:
            raise RuntimeError("Not connected to PKCS#11 HSM")

        # Try to find the key by label
        keys = self._session.findObjects([(PyKCS11.CKA_LABEL, key_id.encode("utf-8"))])

        if not keys:
            return None

        # Get the first key (should only be one with the same label)
        key = keys[0]

        # Get key attributes
        attrs = self._session.getAttributeValue(
            key, [PyKCS11.CKA_CLASS, PyKCS11.CKA_KEY_TYPE, PyKCS11.CKA_ID]
        )

        # Map key type
        if attrs[1] == PyKCS11.CKK_RSA:
            key_type = KeyType.RSA
            key_size = 2048  # Default, would need to get actual size
        elif attrs[1] == PyKCS11.CKK_EC:
            key_type = KeyType.EC
            key_size = 256  # Default, would need to get actual size
        else:
            return None  # Unsupported key type

        # Get key operations
        key_ops = []
        if attrs[0] == PyKCS11.CKO_PUBLIC_KEY:
            if self._session.getAttributeValue(key, [PyKCS11.CKA_VERIFY])[0]:
                key_ops.append(KeyUsage.VERIFY)
            if self._session.getAttributeValue(key, [PyKCS11.CKA_ENCRYPT])[0]:
                key_ops.append(KeyUsage.ENCRYPT)
            if self._session.getAttributeValue(key, [PyKCS11.CKA_WRAP])[0]:
                key_ops.append(KeyUsage.WRAP)
        elif attrs[0] == PyKCS11.CKO_PRIVATE_KEY:
            if self._session.getAttributeValue(key, [PyKCS11.CKA_SIGN])[0]:
                key_ops.append(KeyUsage.SIGN)
            if self._session.getAttributeValue(key, [PyKCS11.CKA_DECRYPT])[0]:
                key_ops.append(KeyUsage.DECRYPT)
            if self._session.getAttributeValue(key, [PyKCS11.CKA_UNWRAP])[0]:
                key_ops.append(KeyUsage.UNWRAP)

        # Get the public key if available
        public_key = None
        if attrs[0] == PyKCS11.CKO_PUBLIC_KEY:
            if key_type == KeyType.RSA:
                mod = self._session.getAttributeValue(key, [PyKCS11.CKA_MODULUS])[0]
                pub_exp = self._session.getAttributeValue(key, [PyKCS11.CKA_PUBLIC_EXPONENT])[0]
                public_key = mod  # Simplified, would need to encode properly

        # Create the HSMKey object
        return HSMKey(
            key_id=key_id,
            key_type=key_type,
            key_size=key_size,
            public_key=public_key,
            key_ops=key_ops,
            metadata={
                "pkcs11_handle": key,
                "key_class": PyKCS11.CKO.get(attrs[0], "UNKNOWN"),
                "key_type_name": PyKCS11.CKO.get(attrs[1], "UNKNOWN"),
            },
        )

    def _get_aws_kms_key(self, key_id: str, **kwargs) -> Optional[HSMKey]:
        """Get a key from AWS KMS."""
        try:
            # Get key details
            key_info = self._kms.describe_key(KeyId=key_id)
            key_metadata = key_info["KeyMetadata"]

            # Map key type
            if key_metadata["KeySpec"].startswith("RSA"):
                key_type = KeyType.RSA
                key_size = int(key_metadata["KeySpec"].split("_")[-1])
            elif key_metadata["KeySpec"].startswith("ECC"):
                key_type = KeyType.EC
                if "P_256" in key_metadata["KeySpec"]:
                    key_size = 256
                elif "P_384" in key_metadata["KeySpec"]:
                    key_size = 384
                elif "P_521" in key_metadata["KeySpec"]:
                    key_size = 521
                else:
                    key_size = 256  # Default
            else:
                return None  # Unsupported key type

            # Get key operations
            key_ops = []
            if key_metadata["KeyUsage"] == "SIGN_VERIFY":
                key_ops.extend([KeyUsage.SIGN, KeyUsage.VERIFY])
            elif key_metadata["KeyUsage"] == "ENCRYPT_DECRYPT":
                key_ops.extend([KeyUsage.ENCRYPT, KeyUsage.DECRYPT])

            # Get the public key if available
            public_key = None
            if key_metadata["KeyState"] == "Enabled":
                try:
                    public_key = self._kms.get_public_key(KeyId=key_id)["PublicKey"]
                except ClientError:
                    # Public key not available or not exportable
                    pass

            # Create the HSMKey object
            return HSMKey(
                key_id=key_metadata["KeyId"],
                key_type=key_type,
                key_size=key_size,
                public_key=public_key,
                key_ops=key_ops,
                metadata={
                    "arn": key_metadata["Arn"],
                    "key_manager": key_metadata["KeyManager"],
                    "key_state": key_metadata["KeyState"],
                    "creation_date": key_metadata["CreationDate"].isoformat(),
                    "description": key_metadata.get("Description", ""),
                    "enabled": key_metadata["KeyState"] == "Enabled",
                    "key_usage": key_metadata["KeyUsage"],
                    "origin": key_metadata.get("Origin", "AWS_KMS"),
                    "valid_to": key_metadata.get("ValidTo", ""),
                },
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return None
            raise

    def _get_azure_kv_key(self, key_id: str, **kwargs) -> Optional[HSMKey]:
        """Get a key from Azure Key Vault."""
        try:
            # Get the key
            key = self._key_client.get_key(key_id)

            # Map key type
            if key.key_type.lower().startswith("rsa"):
                key_type = KeyType.RSA
                key_size = key.key_size
            elif key.key_type.lower().startswith("ec"):
                key_type = KeyType.EC
                key_size = key.key_size
            else:
                return None  # Unsupported key type

            # Get key operations
            key_ops = []
            if "sign" in key.key_ops:
                key_ops.append(KeyUsage.SIGN)
            if "verify" in key.key_ops:
                key_ops.append(KeyUsage.VERIFY)
            if "encrypt" in key.key_ops:
                key_ops.append(KeyUsage.ENCRYPT)
            if "decrypt" in key.key_ops:
                key_ops.append(KeyUsage.DECRYPT)
            if "wrapKey" in key.key_ops:
                key_ops.append(KeyUsage.WRAP)
            if "unwrapKey" in key.key_ops:
                key_ops.append(KeyUsage.UNWRAP)

            # Get the public key if available
            public_key = None
            if hasattr(key, "n") and hasattr(key, "e"):
                # For RSA keys, we can construct the public key from n and e
                # This is a simplified example - in practice, you'd need to properly encode the key
                public_key = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big")

            # Create the HSMKey object
            return HSMKey(
                key_id=key.name,
                key_type=key_type,
                key_size=key_size,
                public_key=public_key,
                key_ops=key_ops,
                metadata={
                    "id": key.id,
                    "enabled": key.properties.enabled,
                    "created": (
                        key.properties.created_on.isoformat() if key.properties.created_on else None
                    ),
                    "updated": (
                        key.properties.updated_on.isoformat() if key.properties.updated_on else None
                    ),
                    "expires": (
                        key.properties.expires_on.isoformat() if key.properties.expires_on else None
                    ),
                    "not_before": (
                        key.properties.not_before.isoformat() if key.properties.not_before else None
                    ),
                    "recovery_level": key.properties.recovery_level,
                    "key_ops": key.key_ops,
                    "key_type": key.key_type,
                    "version": key.properties.version,
                },
            )

        except Exception as e:
            if hasattr(e, "status_code") and e.status_code == 404:
                return None
            raise

    def _get_gcp_kms_key(self, key_id: str, **kwargs) -> Optional[HSMKey]:
        """Get a key from GCP KMS."""
        try:
            # Get the key
            key = self._gcp_client.get_crypto_key(name=f"{self._key_ring_path}/cryptoKeys/{key_id}")

            # Get the primary version
            primary_version = None
            for version in self._gcp_client.list_crypto_key_versions(
                parent=key.name, filter_="state=ENABLED"
            ):
                if version.state == kms.CryptoKeyVersion.CryptoKeyVersionState.ENABLED:
                    primary_version = version
                    break

            if not primary_version:
                return None  # No enabled version found

            # Map key type
            if "RSA" in primary_version.algorithm.name:
                key_type = KeyType.RSA
                key_size = int(
                    primary_version.algorithm.name.split("_")[-2]
                )  # e.g., RSA_SIGN_PKCS1_2048_SHA256 -> 2048
            elif "EC" in primary_version.algorithm.name:
                key_type = KeyType.EC
                if "P256" in primary_version.algorithm.name:
                    key_size = 256
                elif "P384" in primary_version.algorithm.name:
                    key_size = 384
                else:
                    key_size = 256  # Default
            else:
                return None  # Unsupported key type

            # Get key operations
            key_ops = []
            if "SIGN" in primary_version.algorithm.name:
                key_ops.extend([KeyUsage.SIGN, KeyUsage.VERIFY])
            elif "DECRYPT" in primary_version.algorithm.name:
                key_ops.extend([KeyUsage.ENCRYPT, KeyUsage.DECRYPT])

            # Get the public key
            public_key = self._gcp_client.get_public_key(name=primary_version.name).pem.encode(
                "utf-8"
            )

            # Create the HSMKey object
            return HSMKey(
                key_id=key_id,
                key_type=key_type,
                key_size=key_size,
                public_key=public_key,
                key_ops=key_ops,
                metadata={
                    "name": key.name,
                    "primary_version": primary_version.name,
                    "algorithm": primary_version.algorithm.name,
                    "protection_level": primary_version.algorithm.protection_level,
                    "create_time": key.create_time.ToDatetime().isoformat(),
                    "next_rotation_time": (
                        key.next_rotation_time.ToDatetime().isoformat()
                        if key.next_rotation_time
                        else None
                    ),
                    "rotation_period": key.rotation_period.seconds if key.rotation_period else None,
                    "purpose": kms.CryptoKey.CryptoKeyPurpose.Name(key.purpose),
                    "version_template": {
                        "protection_level": key.version_template.protection_level,
                        "algorithm": key.version_template.algorithm.name,
                    },
                },
            )

        except GoogleAPICallError as e:
            if e.code == 5:  # NOT_FOUND
                return None
            raise

    def _get_soft_hsm_key(self, key_id: str, **kwargs) -> Optional[HSMKey]:
        """Get a key from the software HSM (for testing only)."""
        if key_id not in self._keys:
            return None

        key_info = self._keys[key_id]

        return HSMKey(
            key_id=key_id,
            key_type=key_info["key_type"],
            key_size=key_info["key_size"],
            public_key=key_info.get(
                "key"
            ),  # In a real implementation, this would be the public key
            key_ops=key_info["key_ops"],
            metadata={"created_at": key_info["created_at"], "test": True},
        )

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


# Example usage
if __name__ == "__main__":
    import logging

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Example: Using the software HSM (for testing)
    with HSMInterface(HSMType.SOFT_HSM) as hsm:
        # Create a new key
        key = hsm.create_key(
            key_id="test_key_rsa",
            key_type=KeyType.RSA,
            key_size=2048,
            key_ops=[KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT],
        )

        if key:
            print(f"Created key: {key.key_id}")
            print(f"Key type: {key.key_type}")
            print(f"Key size: {key.key_size} bits")
            print(f"Key operations: {[op.value for op in key.key_ops]}")

            # Sign some data
            data = b"Hello, HSM!"
            signature = hsm.sign(key.key_id, data)

            if signature:
                print(f"Signature: {signature.hex()}")

                # Verify the signature
                is_valid = hsm.verify(key.key_id, data, signature)
                print(f"Signature valid: {is_valid}")

                # Try with wrong data (should fail)
                is_valid = hsm.verify(key.key_id, b"Wrong data", signature)
                print(f"Signature with wrong data (should be invalid): {is_valid}")

            # Encrypt some data
            plaintext = b"Sensitive data that needs encryption"
            ciphertext = hsm.encrypt(key.key_id, plaintext)

            if ciphertext:
                print(f"Ciphertext: {ciphertext.hex()}")

                # Decrypt the data
                decrypted = hsm.decrypt(key.key_id, ciphertext)
                print(f"Decrypted: {decrypted}")
                print(f"Original and decrypted match: {plaintext == decrypted}")

            # List all keys
            print("\nAll keys:")
            for k in hsm.list_keys():
                print(f"- {k.key_id} ({k.key_type}, {k.key_size} bits)")

            # Get a specific key
            key_info = hsm.get_key("test_key_rsa")
            if key_info:
                print(f"\nKey info for test_key_rsa: {key_info}")

            # Delete the key
            if hsm.delete_key("test_key_rsa"):
                print("Key deleted successfully")
        else:
            print("Failed to create key")

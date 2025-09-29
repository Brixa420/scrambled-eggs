"""
Cloud HSM Client
This module provides a unified interface for interacting with various cloud HSM services,
including AWS KMS, Azure Key Vault, and GCP KMS.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

# Import cloud provider SDKs (optional imports)
try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.core.exceptions import AzureError
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.keys import KeyType as AzureKeyType
    from azure.keyvault.keys import KeyVaultKey
    from azure.keyvault.keys.crypto import (
        CryptographyClient,
        EncryptionAlgorithm,
        SignatureAlgorithm,
    )

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.api_core.exceptions import GoogleAPICallError, RetryError
    from google.cloud import kms

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from . import HSMInterface
from .types import HSMKey, HSMType, KeyType, KeyUsage


class CloudProvider(Enum):
    """Supported cloud providers."""

    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GCP_KMS = "gcp_kms"


class CloudHSMClient(HSMInterface):
    """
    Cloud HSM client that supports multiple cloud providers.

    This class provides a unified interface for interacting with various cloud HSM services,
    including AWS KMS, Azure Key Vault, and GCP KMS.
    """

    # Map our key types to provider-specific key types
    KEY_TYPE_MAP = {
        KeyType.AES: {
            "aws": "SYMMETRIC_DEFAULT",
            "azure": "oct",
            "gcp": "GOOGLE_SYMMETRIC_ENCRYPTION",
        },
        KeyType.RSA: {"aws": "RSA", "azure": "rsa", "gcp": "RSA_SIGN_PSS_2048_SHA256"},
        KeyType.EC: {"aws": "EC", "azure": "ec", "gcp": "EC_SIGN_P256_SHA256"},
    }

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Cloud HSM client.

        Args:
            config: Configuration dictionary with provider-specific settings
        """
        super().__init__(hsm_type=HSMType.CLOUD_KMS, config=config or {})
        self.provider = self.config.get("provider", "").lower()
        self._client = None
        self._key_cache = {}
        self._initialized = False

        # Initialize the appropriate client based on provider
        if self.provider == CloudProvider.AWS_KMS.value:
            if not AWS_AVAILABLE:
                raise ImportError("AWS KMS client not available. Install boto3: pip install boto3")
            self._init_aws_client()
        elif self.provider == CloudProvider.AZURE_KEY_VAULT.value:
            if not AZURE_AVAILABLE:
                raise ImportError(
                    "Azure Key Vault client not available. Install azure-identity and azure-keyvault-keys"
                )
            self._init_azure_client()
        elif self.provider == CloudProvider.GCP_KMS.value:
            if not GCP_AVAILABLE:
                raise ImportError("GCP KMS client not available. Install google-cloud-kms")
            self._init_gcp_client()
        else:
            raise ValueError(f"Unsupported cloud provider: {self.provider}")

    async def initialize(self) -> bool:
        """
        Initialize the Cloud HSM client.

        Returns:
            bool: True if initialization was successful, False otherwise
        """
        if self._initialized:
            return True

        try:
            # Test the connection to the cloud provider
            if self.provider == CloudProvider.AWS_KMS.value:
                # Simple operation to test AWS connection
                self._client.list_keys(Limit=1)
            elif self.provider == CloudProvider.AZURE_KEY_VAULT.value:
                # Simple operation to test Azure connection
                list(self._client.list_properties_of_keys(max_page_size=1))
            elif self.provider == CloudProvider.GCP_KMS.value:
                # Simple operation to test GCP connection
                self._client.list_key_rings(
                    request={
                        "parent": self._client.location_path(
                            self.config.get("project_id"), self.config.get("location", "global")
                        )
                    }
                )

            self._initialized = True
            self.logger.info(f"Successfully initialized {self.provider} client")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize {self.provider} client: {str(e)}")
            self._initialized = False
            return False

    async def connect(self) -> bool:
        """
        Connect to the cloud HSM service.

        This is a thin wrapper around initialize() for backward compatibility.

        Returns:
            bool: True if connection was successful, False otherwise
        """
        return await self.initialize()

    async def disconnect(self) -> None:
        """
        Disconnect from the cloud HSM service and clean up resources.
        """
        try:
            # Clear any cached keys
            self._key_cache.clear()

            # Close any active connections
            if self._client:
                if self.provider == CloudProvider.AWS_KMS.value and AWS_AVAILABLE:
                    # AWS boto3 clients don't need explicit closing
                    pass
                elif self.provider == CloudProvider.AZURE_KEY_VAULT.value and AZURE_AVAILABLE:
                    # Azure clients are typically context managers but don't need explicit closing
                    pass
                elif self.provider == CloudProvider.GCP_KMS.value and GCP_AVAILABLE:
                    # GCP clients don't need explicit closing
                    pass

                self._client = None

            self._initialized = False
            self.logger.info(f"Disconnected from {self.provider}")

        except Exception as e:
            self.logger.error(f"Error disconnecting from {self.provider}: {str(e)}")
        finally:
            self._client = None
            self._initialized = False

    async def create_key(
        self, key_type: Union[str, KeyType], key_size: int = None, key_id: str = None, **kwargs
    ) -> Optional[HSMKey]:
        """
        Create a new cryptographic key in the cloud HSM.

        Args:
            key_type: Type of key to create (e.g., 'aes', 'rsa', 'ec')
            key_size: Size of the key in bits
            key_id: Optional custom key ID

        Returns:
            HSMKey object if successful, None otherwise
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        # Normalize key type
        if isinstance(key_type, str):
            key_type = KeyType[key_type.upper()]

        # Generate a key ID if not provided
        key_id = key_id or f"key-{uuid.uuid4().hex}"

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._create_aws_key(key_type, key_size, key_id, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Failed to create key: {str(e)}")
            return None

    async def _create_aws_key(
        self, key_type: KeyType, key_size: int, key_id: str, **kwargs
    ) -> Optional[HSMKey]:
        """Create a key in AWS KMS."""
        key_spec = None
        key_usage = "ENCRYPT_DECRYPT"  # Default

        # Map key type and size to AWS KMS key specs
        if key_type == KeyType.AES:
            key_spec = "AES_256"  # AWS KMS only supports 256-bit AES keys
            key_size = 256
        elif key_type == KeyType.RSA:
            if key_size == 2048:
                key_spec = "RSA_2048"
            elif key_size == 3072:
                key_spec = "RSA_3072"
            elif key_size == 4096:
                key_spec = "RSA_4096"
            else:
                key_spec = "RSA_2048"  # Default

            # Determine key usage based on operations
            if kwargs.get("purpose") == "signing":
                key_usage = "SIGN_VERIFY"
        elif key_type == KeyType.EC:
            if key_size == 256:
                key_spec = "ECC_NIST_P256"
            elif key_size == 384:
                key_spec = "ECC_NIST_P384"
            elif key_size == 521:
                key_spec = "ECC_NIST_P521"
            else:
                key_spec = "ECC_NIST_P256"  # Default

            if kwargs.get("purpose") == "signing":
                key_usage = "SIGN_VERIFY"
        else:
            raise ValueError(f"Unsupported key type for AWS KMS: {key_type}")

        # Prepare tags
        aws_tags = []
        if kwargs.get("tags"):
            aws_tags = [{"TagKey": k, "TagValue": v} for k, v in kwargs["tags"].items()]

        if kwargs.get("label"):
            aws_tags.append({"TagKey": "Name", "TagValue": kwargs["label"]})

        try:
            # Create the key in AWS KMS
            response = self._client.create_key(
                Policy=kwargs.get("policy"),
                Description=kwargs.get("description", "Created by Scrambled Eggs"),
                KeyUsage=key_usage,
                CustomerMasterKeySpec=key_spec,
                Tags=aws_tags,
                MultiRegion=kwargs.get("multi_region", False),
            )

            key_metadata = response["KeyMetadata"]

            # Create the HSMKey object
            key = HSMKey(
                key_id=key_metadata["KeyId"],
                key_type=key_type,
                key_size=key_size,
                algorithm=key_spec,
                attributes={
                    "arn": key_metadata["Arn"],
                    "aws_account_id": key_metadata["AWSAccountId"],
                    "creation_date": key_metadata["CreationDate"],
                    "enabled": key_metadata["Enabled"],
                    "key_manager": key_metadata.get("KeyManager", "CUSTOMER"),
                    "key_state": key_metadata.get("KeyState", "Enabled"),
                    "origin": key_metadata.get("Origin", "AWS_KMS"),
                },
                metadata={
                    "provider": "aws_kms",
                    "region": key_metadata.get("Arn", "").split(":")[3],
                    "tags": kwargs.get("tags", {}),
                },
                created_at=key_metadata["CreationDate"],
            )

            # Cache the key
            self._key_cache[key_metadata["KeyId"]] = key

            return key

        except ClientError as e:
            self.logger.error(f"AWS KMS error: {str(e)}")
            return None

    async def get_key(self, key_id: str) -> Optional[HSMKey]:
        """
        Retrieve a key from the cloud HSM.

        Args:
            key_id: ID of the key to retrieve

        Returns:
            HSMKey object if found, None otherwise
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        # Check cache first
        if key_id in self._key_cache:
            return self._key_cache[key_id]

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._get_aws_key(key_id)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Failed to get key {key_id}: {str(e)}")
            return None

    async def _get_aws_key(self, key_id: str) -> Optional[HSMKey]:
        """Get a key from AWS KMS."""
        try:
            # Try to describe the key
            response = self._client.describe_key(KeyId=key_id)
            key_metadata = response["KeyMetadata"]

            # Map AWS key type to our key type
            key_type = None
            key_size = None

            if key_metadata["KeySpec"].startswith("AES"):
                key_type = KeyType.AES
                key_size = 256  # AWS only supports 256-bit AES keys
            elif key_metadata["KeySpec"].startswith("RSA"):
                key_type = KeyType.RSA
                key_size = int(key_metadata["KeySpec"].split("_")[-1])  # Extract size from spec
            elif key_metadata["KeySpec"].startswith("ECC"):
                key_type = KeyType.EC
                # Map curve to key size
                if "P256" in key_metadata["KeySpec"]:
                    key_size = 256
                elif "P384" in key_metadata["KeySpec"]:
                    key_size = 384
                elif "P521" in key_metadata["KeySpec"]:
                    key_size = 521

            # Get key policy and tags
            policy = self._client.get_key_policy(KeyId=key_id, PolicyName="default")
            tags = self._client.list_resource_tags(KeyId=key_id)

            # Create the HSMKey object
            key = HSMKey(
                key_id=key_metadata["KeyId"],
                key_type=key_type,
                key_size=key_size,
                algorithm=key_metadata["KeySpec"],
                attributes={
                    "arn": key_metadata["Arn"],
                    "aws_account_id": key_metadata["AWSAccountId"],
                    "creation_date": key_metadata["CreationDate"],
                    "enabled": key_metadata["Enabled"],
                    "key_manager": key_metadata.get("KeyManager", "CUSTOMER"),
                    "key_state": key_metadata.get("KeyState", "Enabled"),
                    "origin": key_metadata.get("Origin", "AWS_KMS"),
                },
                metadata={
                    "provider": "aws_kms",
                    "region": key_metadata.get("Arn", "").split(":")[3],
                    "policy": policy.get("Policy"),
                    "tags": {t["TagKey"]: t["TagValue"] for t in tags.get("Tags", [])},
                },
                created_at=key_metadata["CreationDate"],
            )

            # Cache the key
            self._key_cache[key_id] = key

            return key

        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.logger.warning(f"Key not found: {key_id}")
            else:
                self.logger.error(f"AWS KMS error: {str(e)}")
            return None

    async def encrypt(
        self, key_id: str, plaintext: bytes, algorithm: str = None, **kwargs
    ) -> Dict[str, bytes]:
        """
        Encrypt data using a key stored in the cloud HSM.

        Args:
            key_id: ID of the key to use for encryption
            plaintext: Data to encrypt
            algorithm: Encryption algorithm to use

        Returns:
            Dictionary containing the ciphertext and any additional data
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_encrypt(key_id, plaintext, algorithm, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            raise

    async def _aws_encrypt(
        self, key_id: str, plaintext: bytes, algorithm: str = None, **kwargs
    ) -> Dict[str, bytes]:
        """Encrypt data using AWS KMS."""
        try:
            # AWS KMS doesn't support custom IV or AAD for symmetric encryption
            if algorithm and algorithm.upper() != "SYMMETRIC_DEFAULT":
                self.logger.warning(f"AWS KMS doesn't support algorithm {algorithm}, using default")

            # Encrypt the data
            response = self._client.encrypt(
                KeyId=key_id,
                Plaintext=plaintext,
                EncryptionContext={"aad": kwargs.get("aad", b"").hex()} if "aad" in kwargs else {},
            )

            return {"ciphertext": response["CiphertextBlob"], "key_id": response["KeyId"]}

        except ClientError as e:
            self.logger.error(f"AWS KMS encryption error: {str(e)}")
            raise

    async def decrypt(
        self, key_id: str, ciphertext: bytes, algorithm: str = None, **kwargs
    ) -> Optional[bytes]:
        """
        Decrypt data using a key stored in the cloud HSM.

        Args:
            key_id: ID of the key to use for decryption
            ciphertext: Data to decrypt
            algorithm: Encryption algorithm that was used

        Returns:
            Decrypted plaintext, or None if decryption failed
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_decrypt(key_id, ciphertext, algorithm, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            return None

    async def _aws_decrypt(
        self, key_id: str, ciphertext: bytes, algorithm: str = None, **kwargs
    ) -> Optional[bytes]:
        """Decrypt data using AWS KMS."""
        try:
            # AWS KMS handles the algorithm, IV, and tag internally
            response = self._client.decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext={"aad": kwargs.get("aad", b"").hex()} if "aad" in kwargs else {},
            )

            return response["Plaintext"]

        except ClientError as e:
            self.logger.error(f"AWS KMS decryption error: {str(e)}")
            return None

    async def sign(
        self, key_id: str, data: bytes, algorithm: str = None, **kwargs
    ) -> Optional[bytes]:
        """
        Sign data using a key stored in the cloud HSM.

        Args:
            key_id: ID of the key to use for signing
            data: Data to sign
            algorithm: Signing algorithm to use

        Returns:
            Signature, or None if signing failed
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_sign(key_id, data, algorithm, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Signing failed: {str(e)}")
            return None

    async def _aws_sign(
        self, key_id: str, data: bytes, algorithm: str = None, **kwargs
    ) -> Optional[bytes]:
        """Sign data using AWS KMS."""
        try:
            # Default to SHA256 if no algorithm specified
            if not algorithm:
                algorithm = "RSASSA_PKCS1_V1_5_SHA_256"

            # Calculate the message digest
            if algorithm.endswith("_SHA_256"):
                message_type = "DIGEST"
                digest = hashlib.sha256(data).digest()
            elif algorithm.endswith("_SHA_384"):
                message_type = "DIGEST"
                digest = hashlib.sha384(data).digest()
            elif algorithm.endswith("_SHA_512"):
                message_type = "DIGEST"
                digest = hashlib.sha512(data).digest()
            else:
                message_type = "RAW"
                digest = data

            # Sign the data
            response = self._client.sign(
                KeyId=key_id, Message=digest, MessageType=message_type, SigningAlgorithm=algorithm
            )

            return response["Signature"]

        except ClientError as e:
            self.logger.error(f"AWS KMS signing error: {str(e)}")
            return None

    async def verify(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str = None, **kwargs
    ) -> bool:
        """
        Verify a signature using a key stored in the cloud HSM.

        Args:
            key_id: ID of the key to use for verification
            data: Original data that was signed
            signature: Signature to verify
            algorithm: Signing algorithm that was used

        Returns:
            True if the signature is valid, False otherwise
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_verify(key_id, data, signature, algorithm, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Signature verification failed: {str(e)}")
            return False

    async def _aws_verify(
        self, key_id: str, data: bytes, signature: bytes, algorithm: str = None, **kwargs
    ) -> bool:
        """Verify a signature using AWS KMS."""
        try:
            # Default to SHA256 if no algorithm specified
            if not algorithm:
                algorithm = "RSASSA_PKCS1_V1_5_SHA_256"

            # Calculate the message digest
            if algorithm.endswith("_SHA_256"):
                message_type = "DIGEST"
                digest = hashlib.sha256(data).digest()
            elif algorithm.endswith("_SHA_384"):
                message_type = "DIGEST"
                digest = hashlib.sha384(data).digest()
            elif algorithm.endswith("_SHA_512"):
                message_type = "DIGEST"
                digest = hashlib.sha512(data).digest()
            else:
                message_type = "RAW"
                digest = data

            # Verify the signature
            response = self._client.verify(
                KeyId=key_id,
                Message=digest,
                MessageType=message_type,
                Signature=signature,
                SigningAlgorithm=algorithm,
            )

            return response["SignatureValid"]

        except ClientError as e:
            self.logger.error(f"AWS KMS verification error: {str(e)}")
            return False

    async def get_public_key(self, key_id: str) -> Optional[bytes]:
        """
        Get the public part of a key pair.

        Args:
            key_id: ID of the key

        Returns:
            Public key in PEM format, or None if not available
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._get_aws_public_key(key_id)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Failed to get public key: {str(e)}")
            return None

    async def _get_aws_public_key(self, key_id: str) -> Optional[bytes]:
        """Get a public key from AWS KMS."""
        try:
            # Get the public key
            response = self._client.get_public_key(KeyId=key_id)

            # Return the public key in PEM format
            return response["PublicKey"]

        except ClientError as e:
            self.logger.error(f"AWS KMS error getting public key: {str(e)}")
            return None

    async def wrap_key(
        self, key_id: str, key_to_wrap: bytes, algorithm: str = None, **kwargs
    ) -> Dict[str, bytes]:
        """
        Wrap a key using a key stored in the cloud HSM.

        Args:
            key_id: ID of the key to use for wrapping
            key_to_wrap: Key to wrap (as bytes)
            algorithm: Wrapping algorithm to use

        Returns:
            Dictionary containing the wrapped key and any additional data
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_wrap_key(key_id, key_to_wrap, algorithm, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Key wrapping failed: {str(e)}")
            raise

    async def _aws_wrap_key(
        self, key_id: str, key_to_wrap: bytes, algorithm: str = None, **kwargs
    ) -> Dict[str, bytes]:
        """Wrap a key using AWS KMS."""
        try:
            # AWS KMS only supports wrapping with symmetric keys
            # and the key must be 32, 40, 44, 48, 52, 56, or 64 bytes

            # Default to AES_GCM if no algorithm specified
            if not algorithm:
                algorithm = "AES_GCM"

            # Encrypt the key
            response = self._client.encrypt(
                KeyId=key_id, Plaintext=key_to_wrap, EncryptionAlgorithm=algorithm
            )

            return {
                "wrapped_key": response["CiphertextBlob"],
                "key_id": response["KeyId"],
                "algorithm": algorithm,
            }

        except ClientError as e:
            self.logger.error(f"AWS KMS key wrapping error: {str(e)}")
            raise

    async def unwrap_key(
        self, key_id: str, wrapped_key: bytes, algorithm: str = None, **kwargs
    ) -> Optional[bytes]:
        """
        Unwrap a key using a key stored in the cloud HSM.

        Args:
            key_id: ID of the key to use for unwrapping
            wrapped_key: Wrapped key to unwrap
            algorithm: Wrapping algorithm that was used

        Returns:
            Unwrapped key, or None if unwrapping failed
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_unwrap_key(key_id, wrapped_key, algorithm, **kwargs)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Key unwrapping failed: {str(e)}")
            return None

    async def _aws_unwrap_key(
        self, key_id: str, wrapped_key: bytes, algorithm: str = None, **kwargs
    ) -> Optional[bytes]:
        """Unwrap a key using AWS KMS."""
        try:
            # Default to AES_GCM if no algorithm specified
            if not algorithm:
                algorithm = "AES_GCM"

            # Decrypt the key
            response = self._client.decrypt(
                KeyId=key_id, CiphertextBlob=wrapped_key, EncryptionAlgorithm=algorithm
            )

            return response["Plaintext"]

        except ClientError as e:
            self.logger.error(f"AWS KMS key unwrapping error: {str(e)}")
            return None

    async def list_keys(self, filter_func=None) -> List[HSMKey]:
        """
        List all keys in the cloud HSM.

        Args:
            filter_func: Optional function to filter keys

        Returns:
            List of HSMKey objects
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                keys = await self._list_aws_keys()
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

            # Apply filter if provided
            if filter_func:
                keys = [k for k in keys if filter_func(k)]

            return keys

        except Exception as e:
            self.logger.error(f"Failed to list keys: {str(e)}")
            return []

    async def _list_aws_keys(self) -> List[HSMKey]:
        """List all keys in AWS KMS."""
        keys = []

        try:
            # Get all keys (paginated)
            paginator = self._client.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page["Keys"]:
                    # Get key details
                    key_obj = await self._get_aws_key(key["KeyId"])
                    if key_obj:
                        keys.append(key_obj)

            return keys

        except ClientError as e:
            self.logger.error(f"AWS KMS error listing keys: {str(e)}")
            return []

    async def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from the cloud HSM.

        Args:
            key_id: ID of the key to delete

        Returns:
            True if the key was deleted, False otherwise
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_delete_key(key_id)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Failed to delete key {key_id}: {str(e)}")
            return False

    async def _aws_delete_key(self, key_id: str) -> bool:
        """Delete a key from AWS KMS."""
        try:
            # Schedule key deletion (default 30-day waiting period)
            response = self._client.schedule_key_deletion(
                KeyId=key_id, PendingWindowInDays=7  # Minimum waiting period is 7 days
            )

            # Remove from cache
            if key_id in self._key_cache:
                del self._key_cache[key_id]

            self.logger.info(
                f"Scheduled deletion of key {key_id}. Deletion date: {response['DeletionDate']}"
            )
            return True

        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.logger.warning(f"Key not found: {key_id}")
            else:
                self.logger.error(f"AWS KMS error deleting key: {str(e)}")
            return False

    async def get_key_attributes(self, key_id: str) -> Dict[str, Any]:
        """
        Get the attributes of a key.

        Args:
            key_id: ID of the key

        Returns:
            Dictionary of key attributes
        """
        key = await self.get_key(key_id)
        if not key:
            return {}

        return key.attributes

    async def set_key_attributes(self, key_id: str, attributes: Dict[str, Any]) -> bool:
        """
        Set the attributes of a key.

        Args:
            key_id: ID of the key
            attributes: Dictionary of attributes to set

        Returns:
            True if the attributes were set, False otherwise
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_set_key_attributes(key_id, attributes)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Failed to set key attributes: {str(e)}")
            return False

    async def _aws_set_key_attributes(self, key_id: str, attributes: Dict[str, Any]) -> bool:
        """Set key attributes in AWS KMS."""
        try:
            # AWS KMS allows updating description, key policy, and tags
            if "description" in attributes:
                self._client.update_key_description(
                    KeyId=key_id, Description=attributes["description"]
                )

            if "policy" in attributes:
                self._client.put_key_policy(
                    KeyId=key_id, PolicyName="default", Policy=attributes["policy"]
                )

            if "tags" in attributes:
                # First, get existing tags to determine what needs to be added/removed
                existing_tags = self._client.list_resource_tags(KeyId=key_id)
                existing_tag_keys = {t["TagKey"] for t in existing_tags.get("Tags", [])}
                new_tag_keys = set(attributes["tags"].keys())

                # Remove tags that are not in the new set
                tags_to_remove = existing_tag_keys - new_tag_keys
                if tags_to_remove:
                    self._client.untag_resource(KeyId=key_id, TagKeys=list(tags_to_remove))

                # Add/update tags
                if new_tag_keys:
                    tags = [{"TagKey": k, "TagValue": v} for k, v in attributes["tags"].items()]
                    self._client.tag_resource(KeyId=key_id, Tags=tags)

            return True

        except ClientError as e:
            self.logger.error(f"AWS KMS error setting key attributes: {str(e)}")
            return False

    async def rotate_key(self, key_id: str) -> Optional[str]:
        """
        Rotate a key, creating a new version.

        Args:
            key_id: ID of the key to rotate

        Returns:
            The ID of the new key version, or None if rotation failed
        """
        if not self._initialized:
            raise RuntimeError("HSM client not initialized")

        try:
            if self.provider == CloudProvider.AWS_KMS.value:
                return await self._aws_rotate_key(key_id)
            else:
                raise ValueError(f"Provider not implemented: {self.provider}")

        except Exception as e:
            self.logger.error(f"Key rotation failed: {str(e)}")
            return None

    async def _aws_rotate_key(self, key_id: str) -> Optional[str]:
        """Rotate a key in AWS KMS."""
        try:
            # AWS KMS automatically handles key rotation for customer-managed keys
            # with automatic rotation enabled

            # Get the current key
            key = await self._get_aws_key(key_id)
            if not key:
                return None

            # Check if automatic rotation is enabled
            response = self._client.get_key_rotation_status(KeyId=key_id)

            if not response.get("KeyRotationEnabled", False):
                # Enable automatic rotation if not already enabled
                self._client.enable_key_rotation(KeyId=key_id)
                self.logger.info(f"Enabled automatic rotation for key {key_id}")

            # Manually rotate the key to create a new version immediately
            self._client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)

            # Create a new key with the same parameters
            new_key_id = await self._create_aws_key(
                key_type=key.key_type,
                key_size=key.key_size,
                key_id=f"{key_id}-{int(datetime.utcnow().timestamp())}",
                **key.metadata,
            )

            return new_key_id.key_id if new_key_id else None

        except ClientError as e:
            self.logger.error(f"AWS KMS key rotation error: {str(e)}")
            return None

"""
File handling utilities for Scrambled Eggs encryption.
"""

import base64
import json
import os
from typing import Any, BinaryIO, Dict, Union

from .core import ScrambledEggs
from .exceptions import DecryptionError, EncryptionError, FileOperationError


class FileHandler:
    """Handles file operations for Scrambled Eggs encryption."""

    @staticmethod
    def encrypt_file(
        input_path: Union[str, BinaryIO],
        output_path: Union[str, BinaryIO],
        password: str,
        layers: int = 100,
    ) -> Dict[str, Any]:
        """
        Encrypt a file using Scrambled Eggs encryption.

        Args:
            input_path: Path to the input file or file-like object
            output_path: Path to save the encrypted file or file-like object
            password: Password for encryption
            layers: Number of hashing layers to use

        Returns:
            Dictionary containing encryption metadata
        """
        return encrypt_file(input_path, output_path, password, layers)

    @staticmethod
    def decrypt_file(
        input_path: Union[str, BinaryIO], output_path: Union[str, BinaryIO], password: str
    ) -> Dict[str, Any]:
        """
        Decrypt a file encrypted with Scrambled Eggs.

        Args:
            input_path: Path to the encrypted file or file-like object
            output_path: Path to save the decrypted file or file-like object
            password: Password used for encryption

        Returns:
            Dictionary containing decryption metadata
        """
        return decrypt_file(input_path, output_path, password)


def _read_file(file_path: Union[str, BinaryIO]) -> bytes:
    """Read file content as bytes."""
    try:
        if isinstance(file_path, (str, os.PathLike)):
            with open(file_path, "rb") as f:
                return f.read()
        else:
            return file_path.read()
    except Exception as e:
        raise FileOperationError(f"Failed to read file: {str(e)}")


def _write_file(file_path: Union[str, BinaryIO], data: bytes) -> None:
    """Write bytes to a file."""
    try:
        if isinstance(file_path, (str, os.PathLike)):
            with open(file_path, "wb") as f:
                f.write(data)
        else:
            file_path.write(data)
    except Exception as e:
        raise FileOperationError(f"Failed to write file: {str(e)}")


def encrypt_file(
    input_path: Union[str, BinaryIO],
    output_path: Union[str, BinaryIO],
    password: str,
    layers: int = 100,
) -> Dict[str, Any]:
    """
    Encrypt a file using Scrambled Eggs encryption.

    Args:
        input_path: Path to the input file or file-like object
        output_path: Path to save the encrypted file or file-like object
        password: Password for encryption
        layers: Number of hashing layers to use

    Returns:
        Dictionary containing encryption metadata
    """
    try:
        # Read the input file
        plaintext = _read_file(input_path)

        # Initialize the encryption
        scrambler = ScrambledEggs(password, initial_layers=layers)

        # Encrypt the data
        ciphertext, metadata = scrambler.encrypt(plaintext)

        # Prepare the output
        output_data = {"metadata": metadata, "data": base64.b64encode(ciphertext).decode("ascii")}

        # Write the encrypted data
        _write_file(output_path, json.dumps(output_data).encode("utf-8"))

        return metadata

    except Exception as e:
        raise EncryptionError(f"Encryption failed: {str(e)}")


def decrypt_file(
    input_path: Union[str, BinaryIO], output_path: Union[str, BinaryIO], password: str
) -> Dict[str, Any]:
    """
    Decrypt a file encrypted with Scrambled Eggs.

    Args:
        input_path: Path to the encrypted file or file-like object
        output_path: Path to save the decrypted file or file-like object
        password: Password used for encryption

    Returns:
        Dictionary containing decryption metadata
    """
    try:
        # Read the encrypted file
        encrypted_data = json.loads(_read_file(input_path).decode("utf-8"))

        # Extract metadata and ciphertext
        metadata = encrypted_data.get("metadata", {})
        ciphertext = base64.b64decode(encrypted_data.get("data", ""))

        # Initialize the decryption
        scrambler = ScrambledEggs(password, initial_layers=metadata.get("layers_used", 100))

        # Decrypt the data
        plaintext = scrambler.decrypt(ciphertext, metadata)

        # Write the decrypted data
        _write_file(output_path, plaintext)

        return {
            "layers_used": metadata.get("layers_used", 0),
            "breach_count": metadata.get("breach_count", 0),
            "timestamp": metadata.get("timestamp"),
        }

    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")

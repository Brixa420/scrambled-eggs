"""
File Encryption Service for Scrambled Eggs

This module provides secure file encryption and decryption using the Scrambled Eggs algorithm.
"""

import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

from cryptography.exceptions import InvalidTag

from app.core.security import SecurityManager
from app.services.scrambled_eggs_crypto import EncryptionResult, ScrambledEggsCrypto

logger = logging.getLogger(__name__)


class FileEncryptionService:
    """Service for encrypting and decrypting files with Scrambled Eggs encryption."""

    def __init__(
        self,
        security_manager: Optional[SecurityManager] = None,
        crypto_service: Optional[ScrambledEggsCrypto] = None,
    ):
        """Initialize the file encryption service."""
        self.security_manager = security_manager or SecurityManager()
        self.crypto_service = crypto_service or ScrambledEggsCrypto(self.security_manager)
        self.chunk_size = 64 * 1024  # 64KB chunks for file operations

    def _get_file_hash(self, file_path: Union[str, Path], algorithm: str = "sha256") -> str:
        """Calculate the hash of a file."""
        file_path = Path(file_path)
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)

        with open(file_path, "rb") as f:
            file_hash = hash_func()
            chunk = f.read(self.chunk_size)
            while chunk:
                file_hash.update(chunk)
                chunk = f.read(self.chunk_size)

        return file_hash.hexdigest()

    def encrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt a file using Scrambled Eggs encryption.

        Args:
            input_path: Path to the file to encrypt
            output_path: Path to save the encrypted file (default: input_path + '.enc')
            associated_data: Optional associated data to authenticate

        Returns:
            Dict containing metadata about the encrypted file

        Raises:
            FileNotFoundError: If the input file doesn't exist
            IOError: If there's an error reading/writing the file
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + ".enc")
        else:
            output_path = Path(output_path)

        # Get file metadata
        file_size = input_path.stat().st_size
        file_hash = self._get_file_hash(input_path)

        # Log the encryption start
        self.security_manager.log_security_event(
            "file_encryption_start",
            {
                "input_path": str(input_path),
                "output_path": str(output_path),
                "file_size": file_size,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        try:
            # Generate a unique file ID and nonce
            file_id = f"file_{int(datetime.utcnow().timestamp() * 1000)}"

            # Encrypt the file in chunks
            with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
                # Write file header with metadata
                header = {
                    "version": "1.0",
                    "algorithm": "aes-256-gcm",
                    "file_id": file_id,
                    "original_name": input_path.name,
                    "original_size": file_size,
                    "original_hash": file_hash,
                    "chunk_size": self.chunk_size,
                    "timestamp": datetime.utcnow().isoformat(),
                }

                # Encrypt and write the header
                header_bytes = json.dumps(header).encode("utf-8")
                header_result = self.crypto_service.encrypt(header_bytes, associated_data)

                # Write header metadata
                outfile.write(len(header_result.ciphertext).to_bytes(4, "big"))
                outfile.write(header_result.iv)
                outfile.write(header_result.tag)
                outfile.write(header_result.ciphertext)

                # Encrypt and write file content in chunks
                chunk_number = 0
                total_encrypted = 0

                while True:
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break

                    # Encrypt the chunk
                    result = self.crypto_service.encrypt(chunk, associated_data)

                    # Write chunk metadata
                    outfile.write(len(result.ciphertext).to_bytes(4, "big"))  # Chunk size
                    outfile.write(result.iv)
                    outfile.write(result.tag)
                    outfile.write(result.ciphertext)

                    chunk_number += 1
                    total_encrypted += len(chunk)

            # Log successful encryption
            self.security_manager.log_security_event(
                "file_encryption_success",
                {
                    "file_id": file_id,
                    "original_path": str(input_path),
                    "encrypted_path": str(output_path),
                    "original_size": file_size,
                    "encrypted_size": output_path.stat().st_size,
                    "chunks": chunk_number,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            return {
                "status": "success",
                "file_id": file_id,
                "original_path": str(input_path),
                "encrypted_path": str(output_path),
                "original_size": file_size,
                "encrypted_size": output_path.stat().st_size,
                "chunks": chunk_number,
                "algorithm": "aes-256-gcm",
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            # Log the error
            self.security_manager.log_security_event(
                "file_encryption_error",
                {
                    "error": str(e),
                    "input_path": str(input_path),
                    "output_path": str(output_path) if output_path else None,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            # Clean up partially written file on error
            if output_path and output_path.exists():
                try:
                    output_path.unlink()
                except Exception as cleanup_error:
                    logger.error(f"Failed to clean up after encryption error: {cleanup_error}")

            raise

    def decrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Decrypt a file encrypted with Scrambled Eggs encryption.

        Args:
            input_path: Path to the encrypted file
            output_path: Path to save the decrypted file (default: remove '.enc' suffix or add '.dec')
            associated_data: Optional associated data for authentication

        Returns:
            Dict containing metadata about the decrypted file

        Raises:
            FileNotFoundError: If the input file doesn't exist
            ValueError: If the file is not a valid encrypted file
            InvalidTag: If the authentication tag is invalid
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if output_path is None:
            if input_path.suffix == ".enc":
                output_path = input_path.with_suffix("")
            else:
                output_path = input_path.with_suffix(input_path.suffix + ".dec")
        else:
            output_path = Path(output_path)

        # Log the decryption start
        self.security_manager.log_security_event(
            "file_decryption_start",
            {
                "input_path": str(input_path),
                "output_path": str(output_path),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        try:
            with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
                # Read and decrypt the header
                header_size = int.from_bytes(infile.read(4), "big")
                header_iv = infile.read(12)  # 96-bit IV for GCM
                header_tag = infile.read(16)  # 128-bit authentication tag
                header_ciphertext = infile.read(header_size)

                # Decrypt the header
                header_result = EncryptionResult(
                    ciphertext=header_ciphertext,
                    iv=header_iv,
                    tag=header_tag,
                    key_id=None,  # Will use current key
                )

                try:
                    header_json = self.crypto_service.decrypt(header_result, associated_data)
                    header = json.loads(header_json.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise ValueError("Invalid encrypted file format: invalid header") from e

                # Verify header structure
                required_fields = [
                    "version",
                    "algorithm",
                    "file_id",
                    "original_name",
                    "original_size",
                ]
                if not all(field in header for field in required_fields):
                    raise ValueError(
                        "Invalid encrypted file format: missing required header fields"
                    )

                # Decrypt file content in chunks
                chunk_number = 0
                total_decrypted = 0

                while True:
                    # Read chunk metadata
                    chunk_header = infile.read(4)  # Chunk size (4 bytes)
                    if not chunk_header:
                        break  # End of file

                    chunk_size = int.from_bytes(chunk_header, "big")
                    chunk_iv = infile.read(12)  # 96-bit IV for GCM
                    chunk_tag = infile.read(16)  # 128-bit authentication tag
                    chunk_ciphertext = infile.read(chunk_size)

                    # Decrypt the chunk
                    result = EncryptionResult(
                        ciphertext=chunk_ciphertext,
                        iv=chunk_iv,
                        tag=chunk_tag,
                        key_id=None,  # Will use current key
                    )

                    try:
                        plaintext = self.crypto_service.decrypt(result, associated_data)
                        outfile.write(plaintext)
                        total_decrypted += len(plaintext)
                        chunk_number += 1
                    except InvalidTag as e:
                        # Log the error
                        self.security_manager.log_security_event(
                            "file_decryption_error",
                            {
                                "error": "Invalid authentication tag",
                                "file_id": header.get("file_id"),
                                "chunk": chunk_number,
                                "timestamp": datetime.utcnow().isoformat(),
                            },
                        )
                        raise

            # Verify the decrypted file size matches the original
            if total_decrypted != header["original_size"]:
                logger.warning(
                    f"Decrypted file size mismatch: expected {header['original_size']}, "
                    f"got {total_decrypted}"
                )

            # Verify the file hash if available
            if "original_hash" in header:
                actual_hash = self._get_file_hash(output_path)
                if actual_hash != header["original_hash"]:
                    logger.warning(
                        f"File hash mismatch for {output_path}. "
                        f"Expected: {header['original_hash']}, got: {actual_hash}"
                    )

            # Log successful decryption
            self.security_manager.log_security_event(
                "file_decryption_success",
                {
                    "file_id": header.get("file_id"),
                    "original_path": str(input_path),
                    "decrypted_path": str(output_path),
                    "original_size": header.get("original_size"),
                    "decrypted_size": output_path.stat().st_size,
                    "chunks": chunk_number,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            return {
                "status": "success",
                "file_id": header.get("file_id"),
                "original_name": header.get("original_name"),
                "original_size": header.get("original_size"),
                "decrypted_path": str(output_path),
                "decrypted_size": output_path.stat().st_size,
                "chunks": chunk_number,
                "algorithm": header.get("algorithm"),
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            # Log the error
            self.security_manager.log_security_event(
                "file_decryption_error",
                {
                    "error": str(e),
                    "input_path": str(input_path),
                    "output_path": str(output_path) if output_path else None,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            # Clean up partially written file on error
            if output_path and output_path.exists():
                try:
                    output_path.unlink()
                except Exception as cleanup_error:
                    logger.error(f"Failed to clean up after decryption error: {cleanup_error}")

            raise

    def encrypt_directory(
        self,
        directory: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
        recursive: bool = True,
    ) -> Dict[str, Any]:
        """
        Encrypt all files in a directory.

        Args:
            directory: Path to the directory to encrypt
            output_dir: Directory to save encrypted files (default: input_dir + '_encrypted')
            recursive: Whether to process subdirectories

        Returns:
            Dict with encryption results
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        if output_dir is None:
            output_dir = directory.parent / f"{directory.name}_encrypted"
        else:
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "directory": str(directory),
            "output_dir": str(output_dir),
            "files_processed": 0,
            "files_encrypted": 0,
            "errors": [],
            "start_time": datetime.utcnow().isoformat(),
            "details": [],
        }

        # Process files
        for item in directory.rglob("*") if recursive else directory.glob("*"):
            if item.is_file():
                results["files_processed"] += 1

                # Create relative path for output
                rel_path = item.relative_to(directory)
                item_output_dir = output_dir / rel_path.parent
                item_output_dir.mkdir(parents=True, exist_ok=True)

                try:
                    # Encrypt the file
                    result = self.encrypt_file(
                        input_path=item, output_path=item_output_dir / f"{item.name}.enc"
                    )
                    results["files_encrypted"] += 1
                    results["details"].append(
                        {"file": str(item), "status": "encrypted", "result": result}
                    )
                except Exception as e:
                    error_msg = f"Failed to encrypt {item}: {str(e)}"
                    logger.error(error_msg, exc_info=True)
                    results["errors"].append(error_msg)
                    results["details"].append(
                        {"file": str(item), "status": "error", "error": str(e)}
                    )

        results["end_time"] = datetime.utcnow().isoformat()
        results["duration_seconds"] = (
            datetime.fromisoformat(results["end_time"])
            - datetime.fromisoformat(results["start_time"])
        ).total_seconds()

        return results

    def decrypt_directory(
        self,
        directory: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
        recursive: bool = True,
    ) -> Dict[str, Any]:
        """
        Decrypt all files in a directory.

        Args:
            directory: Path to the directory containing encrypted files
            output_dir: Directory to save decrypted files (default: input_dir + '_decrypted')
            recursive: Whether to process subdirectories

        Returns:
            Dict with decryption results
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        if output_dir is None:
            output_dir = directory.parent / f"{directory.name}_decrypted"
        else:
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "directory": str(directory),
            "output_dir": str(output_dir),
            "files_processed": 0,
            "files_decrypted": 0,
            "errors": [],
            "start_time": datetime.utcnow().isoformat(),
            "details": [],
        }

        # Process files
        for item in directory.rglob("*.enc") if recursive else directory.glob("*.enc"):
            if item.is_file():
                results["files_processed"] += 1

                # Create relative path for output
                rel_path = item.relative_to(directory)
                item_output_dir = output_dir / rel_path.parent
                item_output_dir.mkdir(parents=True, exist_ok=True)

                # Determine output filename (remove .enc or replace with .dec)
                output_path = item_output_dir / item.stem

                try:
                    # Decrypt the file
                    result = self.decrypt_file(input_path=item, output_path=output_path)
                    results["files_decrypted"] += 1
                    results["details"].append(
                        {"file": str(item), "status": "decrypted", "result": result}
                    )
                except Exception as e:
                    error_msg = f"Failed to decrypt {item}: {str(e)}"
                    logger.error(error_msg, exc_info=True)
                    results["errors"].append(error_msg)
                    results["details"].append(
                        {"file": str(item), "status": "error", "error": str(e)}
                    )

        results["end_time"] = datetime.utcnow().isoformat()
        results["duration_seconds"] = (
            datetime.fromisoformat(results["end_time"])
            - datetime.fromisoformat(results["start_time"])
        ).total_seconds()

        return results


# Create a default instance for easy import
file_encryption_service = FileEncryptionService()

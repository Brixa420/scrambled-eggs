"""
Streaming encryption for Scrambled Eggs.
Provides efficient encryption/decryption of large files using chunked processing.
"""

import hashlib
import io
import logging
import os
from pathlib import Path
from typing import BinaryIO, Generator, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

# Default chunk size (4MB) - can be adjusted based on available memory
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


class StreamEncryptor:
    """Encrypts data in chunks for efficient memory usage."""

    def __init__(self, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize the stream encryptor.

        Args:
            key: Encryption key (must be 16, 24, or 32 bytes for AES)
            chunk_size: Size of each chunk to process (in bytes)
        """
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes long")

        self.key = key
        self.chunk_size = chunk_size
        self.backend = default_backend()

        # Generate a random IV for this encryption operation
        self.iv = os.urandom(16)

        # Set up the cipher
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)

        self.encryptor = self.cipher.encryptor()
        self.padder = padding.PKCS7(128).padder()  # 128-bit block size for AES
        self.finished = False

    def process_chunk(self, data: bytes) -> bytes:
        """Process a chunk of data.

        Args:
            data: Input data to encrypt

        Returns:
            Encrypted data chunk
        """
        if self.finished:
            raise ValueError("Encryptor already finished")

        # Pad the data if it's not the final chunk
        padded_data = self.padder.update(data)
        return self.encryptor.update(padded_data)

    def finalize(self) -> bytes:
        """Finalize the encryption.

        Returns:
            Final encrypted chunk with padding
        """
        if self.finished:
            return b""

        self.finished = True

        # Add padding for the final block
        final_block = self.padder.finalize()
        encrypted = self.encryptor.update(final_block) + self.encryptor.finalize()

        # Return the IV + encrypted data
        return self.iv + encrypted

    def encrypt_file(
        self, input_path: Union[str, Path, BinaryIO], output_path: Union[str, Path, BinaryIO]
    ) -> dict:
        """Encrypt a file in chunks.

        Args:
            input_path: Path to input file or file-like object
            output_path: Path to output file or file-like object

        Returns:
            Dictionary with encryption metadata
        """
        close_input = False
        close_output = False

        try:
            # Handle file paths or file-like objects
            if isinstance(input_path, (str, Path)):
                input_file = open(input_path, "rb")
                close_input = True
            else:
                input_file = input_path

            if isinstance(output_path, (str, Path)):
                output_file = open(output_path, "wb")
                close_output = True
            else:
                output_file = output_path

            # Write the IV at the beginning of the file
            output_file.write(self.iv)

            # Process file in chunks
            total_size = 0
            chunk_count = 0

            while True:
                chunk = input_file.read(self.chunk_size)
                if not chunk:
                    break

                # Process chunk
                encrypted_chunk = self.process_chunk(chunk)
                if encrypted_chunk:
                    output_file.write(encrypted_chunk)
                    total_size += len(encrypted_chunk)
                    chunk_count += 1

            # Finalize encryption
            final_chunk = self.finalize()
            if final_chunk:
                output_file.write(final_chunk[len(self.iv) :])  # Skip IV as we already wrote it
                total_size += len(final_chunk) - len(self.iv)

            # Return metadata
            return {
                "total_size": total_size,
                "chunk_count": chunk_count,
                "chunk_size": self.chunk_size,
                "algorithm": "AES-256-CBC",
                "iv": self.iv.hex(),
            }

        finally:
            if close_input:
                input_file.close()
            if close_output:
                output_file.close()


class StreamDecryptor:
    """Decrypts data in chunks for efficient memory usage."""

    def __init__(self, key: bytes, iv: bytes = None, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize the stream decryptor.

        Args:
            key: Decryption key (must be 16, 24, or 32 bytes for AES)
            iv: Initialization vector (if None, it will be read from the stream)
            chunk_size: Size of each chunk to process (in bytes)
        """
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes long")

        self.key = key
        self.iv = iv
        self.chunk_size = chunk_size
        self.backend = default_backend()
        self.iv_read = iv is not None
        self.cipher = None
        self.decryptor = None
        self.unpadder = padding.PKCS7(128).unpadder()  # 128-bit block size for AES
        self.finished = False

    def _ensure_cipher_initialized(self, iv: bytes = None):
        """Initialize the cipher if not already done."""
        if self.cipher is None:
            if iv is None and self.iv is None:
                raise ValueError("IV must be provided or read from stream")

            if iv is not None and self.iv is None:
                self.iv = iv

            self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
            self.decryptor = self.cipher.decryptor()

    def process_chunk(self, data: bytes, is_final: bool = False) -> bytes:
        """Process a chunk of encrypted data.

        Args:
            data: Encrypted data chunk
            is_final: Whether this is the final chunk

        Returns:
            Decrypted data chunk
        """
        if self.finished:
            return b""

        # If we haven't read the IV yet, read it from the first chunk
        if not self.iv_read:
            if len(data) < 16:
                raise ValueError("First chunk must contain at least 16 bytes (IV)")

            self.iv = data[:16]
            data = data[16:]
            self.iv_read = True
            self._ensure_cipher_initialized()

        # Initialize cipher if not done yet
        self._ensure_cipher_initialized()

        # Decrypt the chunk
        decrypted = self.decryptor.update(data)

        # If this is the final chunk, remove padding
        if is_final:
            decrypted += self.decryptor.finalize()
            decrypted = self.unpadder.update(decrypted) + self.unpadder.finalize()
            self.finished = True

        return decrypted

    def decrypt_file(
        self, input_path: Union[str, Path, BinaryIO], output_path: Union[str, Path, BinaryIO]
    ) -> dict:
        """Decrypt a file in chunks.

        Args:
            input_path: Path to input file or file-like object
            output_path: Path to output file or file-like object

        Returns:
            Dictionary with decryption metadata
        """
        close_input = False
        close_output = False

        try:
            # Handle file paths or file-like objects
            if isinstance(input_path, (str, Path)):
                input_file = open(input_path, "rb")
                close_input = True
            else:
                input_file = input_path

            if isinstance(output_path, (str, Path)):
                output_file = open(output_path, "wb")
                close_output = True
            else:
                output_file = output_path

            # Process file in chunks
            total_size = 0
            chunk_count = 0

            # Read the first chunk to get the IV if not provided
            first_chunk = input_file.read(max(16, self.chunk_size))
            if not first_chunk:
                raise ValueError("Input file is empty")

            # Process first chunk (contains IV)
            decrypted = self.process_chunk(first_chunk, is_final=False)
            if decrypted:
                output_file.write(decrypted)
                total_size += len(decrypted)
                chunk_count += 1

            # Process remaining chunks
            while True:
                chunk = input_file.read(self.chunk_size)
                if not chunk:
                    break

                # Process chunk
                decrypted = self.process_chunk(chunk, is_final=len(chunk) < self.chunk_size)
                if decrypted:
                    output_file.write(decrypted)
                    total_size += len(decrypted)
                    chunk_count += 1

            # If we haven't processed the final chunk yet, do it now
            if not self.finished:
                decrypted = self.process_chunk(b"", is_final=True)
                if decrypted:
                    output_file.write(decrypted)
                    total_size += len(decrypted)

            # Return metadata
            return {
                "total_size": total_size,
                "chunk_count": chunk_count,
                "chunk_size": self.chunk_size,
                "algorithm": "AES-256-CBC",
                "iv": self.iv.hex() if self.iv else None,
            }

        finally:
            if close_input:
                input_file.close()
            if close_output:
                output_file.close()


def encrypt_file_with_progress(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    key: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: callable = None,
) -> dict:
    """Encrypt a file with progress reporting.

    Args:
        input_path: Path to input file
        output_path: Path to output file
        key: Encryption key
        chunk_size: Size of each chunk to process
        progress_callback: Optional callback function that receives progress (0.0 to 1.0)

    Returns:
        Dictionary with encryption metadata
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # Get file size for progress reporting
    total_size = input_path.stat().st_size
    processed = 0

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        encryptor = StreamEncryptor(key=key, chunk_size=chunk_size)

        # Process file in chunks
        while True:
            chunk = infile.read(chunk_size)
            if not chunk:
                break

            # Encrypt chunk
            if len(chunk) == chunk_size:
                encrypted = encryptor.process_chunk(chunk)
            else:
                # Final chunk
                encrypted = encryptor.process_chunk(chunk) + encryptor.finalize()

            outfile.write(encrypted)
            processed += len(chunk)

            # Report progress
            if progress_callback and total_size > 0:
                progress = min(1.0, processed / total_size)
                progress_callback(progress)

    # Return metadata
    return {
        "input_size": total_size,
        "output_size": output_path.stat().st_size,
        "algorithm": "AES-256-CBC",
        "iv": encryptor.iv.hex(),
    }


def decrypt_file_with_progress(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    key: bytes,
    iv: bytes = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: callable = None,
) -> dict:
    """Decrypt a file with progress reporting.

    Args:
        input_path: Path to input file
        output_path: Path to output file
        key: Decryption key
        iv: Initialization vector (if None, will be read from file)
        chunk_size: Size of each chunk to process
        progress_callback: Optional callback function that receives progress (0.0 to 1.0)

    Returns:
        Dictionary with decryption metadata
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # Get file size for progress reporting
    total_size = input_path.stat().st_size
    processed = 0

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        # If IV is not provided, read it from the file
        if iv is None:
            iv = infile.read(16)
            processed += 16

        decryptor = StreamDecryptor(key=key, iv=iv, chunk_size=chunk_size)

        # Process file in chunks
        while True:
            chunk = infile.read(chunk_size)
            if not chunk:
                break

            # Decrypt chunk
            is_final = len(chunk) < chunk_size
            decrypted = decryptor.process_chunk(chunk, is_final=is_final)

            outfile.write(decrypted)
            processed += len(chunk)

            # Report progress
            if progress_callback and total_size > 0:
                progress = min(1.0, processed / total_size)
                progress_callback(progress)

    # Return metadata
    return {
        "input_size": total_size,
        "output_size": output_path.stat().st_size,
        "algorithm": "AES-256-CBC",
        "iv": iv.hex() if iv else None,
    }


# Example usage
if __name__ == "__main__":
    import argparse
    import getpass
    import sys

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive a key from a password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=600000,
            backend=default_backend(),
        )

        key = kdf.derive(password.encode())
        return key, salt

    def progress_callback(progress: float):
        """Print progress bar."""
        bar_length = 50
        block = int(round(bar_length * progress))
        progress_text = f"{'=' * block}{' ' * (bar_length - block)}"
        sys.stdout.write(f"\r[{progress_text}] {progress * 100:.1f}%")
        sys.stdout.flush()

    def main():
        parser = argparse.ArgumentParser(description="Streaming file encryption/decryption")
        parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
        parser.add_argument("input_file", help="Input file path")
        parser.add_argument("output_file", help="Output file path")
        parser.add_argument(
            "--key", help="Encryption/decryption key (if not provided, will prompt)"
        )
        parser.add_argument("--iv", help="Initialization vector (for decryption)")
        parser.add_argument(
            "--chunk-size",
            type=int,
            default=DEFAULT_CHUNK_SIZE,
            help=f"Chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})",
        )

        args = parser.parse_args()

        # Get key from argument or prompt
        if args.key:
            key = args.key.encode()
        else:
            key = getpass.getpass("Enter encryption key: ").encode()

        # Derive a secure key from the password
        key, salt = derive_key(key.decode())

        # Convert IV from hex if provided
        iv = bytes.fromhex(args.iv) if args.iv else None

        try:
            if args.action == "encrypt":
                print(f"Encrypting {args.input_file} to {args.output_file}...")
                result = encrypt_file_with_progress(
                    args.input_file,
                    args.output_file,
                    key=key,
                    chunk_size=args.chunk_size,
                    progress_callback=progress_callback,
                )
                print("\nEncryption complete!")
                print(f"IV (hex): {result['iv']}")

            else:  # decrypt
                print(f"Decrypting {args.input_file} to {args.output_file}...")
                result = decrypt_file_with_progress(
                    args.input_file,
                    args.output_file,
                    key=key,
                    iv=iv,
                    chunk_size=args.chunk_size,
                    progress_callback=progress_callback,
                )
                print("\nDecryption complete!")

        except Exception as e:
            print(f"\nError: {e}", file=sys.stderr)
            sys.exit(1)

    if __name__ == "__main__":
        main()

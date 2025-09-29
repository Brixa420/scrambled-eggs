"""
P2P Utility Functions for Scrambled Eggs.

This module provides utility functions for P2P networking, cryptography,
and message handling in the Scrambled Eggs application.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logger = logging.getLogger(__name__)

# Constants
SALT_LENGTH = 16
IV_LENGTH = 16
TAG_LENGTH = 16
KEY_LENGTH = 32  # 256 bits
NONCE_LENGTH = 12  # 96 bits for AES-GCM
CHUNK_SIZE = 65536  # 64KB chunks for file operations


def generate_key_pair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA key pair for asymmetric encryption.

    Args:
        key_size: Key size in bits (default: 2048)

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    """
    Serialize a public key to a PEM-encoded string.

    Args:
        public_key: The public key to serialize

    Returns:
        PEM-encoded public key as a string
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def deserialize_public_key(public_key_str: str) -> rsa.RSAPublicKey:
    """
    Deserialize a PEM-encoded public key string to an RSA public key object.

    Args:
        public_key_str: PEM-encoded public key string

    Returns:
        RSA public key object
    """
    return serialization.load_pem_public_key(public_key_str.encode("utf-8"))


def generate_symmetric_key() -> bytes:
    """
    Generate a random symmetric key for AES encryption.

    Returns:
        Random bytes of length KEY_LENGTH
    """
    return os.urandom(KEY_LENGTH)


def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive a key from a password using PBKDF2.

    Args:
        password: The password to derive the key from
        salt: Random salt
        iterations: Number of iterations for PBKDF2

    Returns:
        Derived key as bytes
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-GCM.

    Args:
        data: Data to encrypt
        key: Encryption key (must be 32 bytes for AES-256)

    Returns:
        Encrypted data with prepended IV and appended tag
    """
    # Generate a random IV
    iv = os.urandom(IV_LENGTH)

    # Create cipher and encrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted = encryptor.update(data) + encryptor.finalize()

    # Return IV + encrypted data + tag
    return iv + encrypted + encryptor.tag


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-GCM.

    Args:
        encrypted_data: Encrypted data with prepended IV and appended tag
        key: Decryption key (must be 32 bytes for AES-256)

    Returns:
        Decrypted data

    Raises:
        ValueError: If decryption fails
    """
    if len(encrypted_data) < IV_LENGTH + TAG_LENGTH:
        raise ValueError("Invalid encrypted data")

    # Extract IV, tag, and ciphertext
    iv = encrypted_data[:IV_LENGTH]
    tag = encrypted_data[-TAG_LENGTH:]
    ciphertext = encrypted_data[IV_LENGTH:-TAG_LENGTH]

    # Create cipher and decrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign data using RSA-PSS.

    Args:
        data: Data to sign
        private_key: Private key for signing

    Returns:
        Signature as bytes
    """
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify a signature using RSA-PSS.

    Args:
        data: Original data that was signed
        signature: Signature to verify
        public_key: Public key for verification

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def generate_message_id() -> str:
    """
    Generate a unique message ID.

    Returns:
        A unique message ID as a string
    """
    timestamp = int(datetime.utcnow().timestamp() * 1000)
    random_bytes = os.urandom(8)
    return f"msg_{timestamp}_{random_bytes.hex()}"


def serialize_message(message: Dict[str, Any]) -> bytes:
    """
    Serialize a message dictionary to bytes.

    Args:
        message: Message dictionary to serialize

    Returns:
        Serialized message as bytes
    """
    return json.dumps(message, ensure_ascii=False).encode("utf-8")


def deserialize_message(data: bytes) -> Dict[str, Any]:
    """
    Deserialize message bytes to a dictionary.

    Args:
        data: Serialized message as bytes

    Returns:
        Deserialized message dictionary

    Raises:
        ValueError: If deserialization fails
    """
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to deserialize message: {str(e)}")


def get_local_ip() -> str:
    """
    Get the local IP address of the machine.

    Returns:
        Local IP address as a string
    """
    try:
        # Create a socket connection to a public address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's public DNS
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def is_port_available(port: int, host: str = "0.0.0.0") -> bool:
    """
    Check if a port is available for binding.

    Args:
        port: Port number to check
        host: Host address to check (default: '0.0.0.0' for all interfaces)

    Returns:
        True if the port is available, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except (OSError, socket.error):
        return False


def find_available_port(start_port: int = 8000, end_port: int = 9000) -> Optional[int]:
    """
    Find an available port in the specified range.

    Args:
        start_port: Starting port number (inclusive)
        end_port: Ending port number (inclusive)

    Returns:
        Available port number or None if no port is available
    """
    for port in range(start_port, end_port + 1):
        if is_port_available(port):
            return port
    return None


def calculate_file_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Calculate the hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: 'sha256')

    Returns:
        Hexadecimal string representation of the file hash
    """
    hash_func = hashlib.new(algorithm)
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_func.update(byte_block)

    return hash_func.hexdigest()


async def async_read_file(file_path: Union[str, Path], chunk_size: int = CHUNK_SIZE) -> bytes:
    """
    Asynchronously read a file in chunks.

    Args:
        file_path: Path to the file
        chunk_size: Size of each chunk in bytes (default: 64KB)

    Returns:
        File content as bytes
    """
    file_path = Path(file_path)
    chunks = []

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
            # Allow other tasks to run
            await asyncio.sleep(0)

    return b"".join(chunks)


async def async_write_file(
    file_path: Union[str, Path], data: bytes, chunk_size: int = CHUNK_SIZE
) -> None:
    """
    Asynchronously write data to a file in chunks.

    Args:
        file_path: Path to the file
        data: Data to write
        chunk_size: Size of each chunk in bytes (default: 64KB)
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "wb") as f:
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            f.write(chunk)
            # Allow other tasks to run
            await asyncio.sleep(0)

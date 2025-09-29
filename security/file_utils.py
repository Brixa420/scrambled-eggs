"""File utilities for secure file handling."""

import hashlib
import io
import os
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union

import magic
from PIL import Image, UnidentifiedImageError
from werkzeug.datastructures import FileStorage

from .config import get_config
from .utils import security_utils

# Initialize config
config = get_config()


class FileSecurityError(Exception):
    """Raised when a security issue is detected with a file."""

    pass


class FileUtils:
    """Utilities for secure file handling."""

    @staticmethod
    def get_secure_filename(filename: str) -> str:
        """
        Generate a secure filename.

        Args:
            filename: The original filename

        Returns:
            A secure version of the filename
        """
        return security_utils.secure_filename(filename)

    @staticmethod
    def get_file_extension(filename: str) -> str:
        """
        Get the file extension from a filename.

        Args:
            filename: The filename

        Returns:
            The file extension (lowercase, without the dot)
        """
        return Path(filename).suffix.lower().lstrip(".")

    @staticmethod
    def is_allowed_extension(filename: str) -> bool:
        """
        Check if a file has an allowed extension.

        Args:
            filename: The filename to check

        Returns:
            True if the extension is allowed, False otherwise
        """
        if not filename:
            return False

        ext = FileUtils.get_file_extension(filename)
        return ext in config.ALLOWED_EXTENSIONS

    @staticmethod
    def validate_file_type(
        file: Union[FileStorage, BinaryIO, bytes], allowed_mime_types: Optional[List[str]] = None
    ) -> str:
        """
        Validate the file type using magic numbers.

        Args:
            file: The file to validate (FileStorage, file-like object, or bytes)
            allowed_mime_types: List of allowed MIME types (defaults to config.ALLOWED_EXTENSIONS)

        Returns:
            The detected MIME type

        Raises:
            FileSecurityError: If the file type is not allowed
        """
        if not file:
            raise FileSecurityError("No file provided")

        # Read the first 2048 bytes to determine the file type
        if isinstance(file, FileStorage):
            file.seek(0)
            header = file.read(2048)
            file.seek(0)
        elif hasattr(file, "read"):
            current_pos = file.tell()
            header = file.read(2048)
            file.seek(current_pos)
        elif isinstance(file, bytes):
            header = file[:2048]
        else:
            raise FileSecurityError("Invalid file type")

        if not header:
            raise FileSecurityError("Empty file")

        # Detect MIME type
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(header)

        # If no specific MIME types are provided, use the allowed extensions
        if allowed_mime_types is None:
            allowed_mime_types = []

            # Map common extensions to MIME types
            ext_to_mime = {
                "txt": "text/plain",
                "pdf": "application/pdf",
                "png": "image/png",
                "jpg": "image/jpeg",
                "jpeg": "image/jpeg",
                "gif": "image/gif",
            }

            for ext in config.ALLOWED_EXTENSIONS:
                if ext in ext_to_mime:
                    allowed_mime_types.append(ext_to_mime[ext])

        # Check if the MIME type is allowed
        if allowed_mime_types and mime_type not in allowed_mime_types:
            raise FileSecurityError(f"File type '{mime_type}' is not allowed")

        return mime_type

    @staticmethod
    def validate_image(
        file: Union[FileStorage, BinaryIO, bytes],
        max_width: Optional[int] = None,
        max_height: Optional[int] = None,
    ) -> Tuple[int, int]:
        """
        Validate an image file.

        Args:
            file: The image file to validate (FileStorage, file-like object, or bytes)
            max_width: Maximum allowed width in pixels (optional)
            max_height: Maximum allowed height in pixels (optional)

        Returns:
            A tuple of (width, height) of the image

        Raises:
            FileSecurityError: If the image is invalid or exceeds the maximum dimensions
        """
        try:
            # Open the image
            if isinstance(file, FileStorage):
                file.seek(0)
                img = Image.open(file)
                file.seek(0)
            elif hasattr(file, "read"):
                current_pos = file.tell()
                img = Image.open(file)
                file.seek(current_pos)
            elif isinstance(file, bytes):
                img = Image.open(io.BytesIO(file))
            else:
                raise FileSecurityError("Invalid image file")

            # Verify it's an image
            img.verify()

            # Get image dimensions
            width, height = img.size

            # Check dimensions if specified
            if (max_width is not None and width > max_width) or (
                max_height is not None and height > max_height
            ):
                raise FileSecurityError(
                    f"Image dimensions ({width}x{height}) exceed maximum allowed dimensions "
                    f"({max_width or 'unlimited'}x{max_height or 'unlimited'})"
                )

            return width, height

        except (UnidentifiedImageError, OSError) as e:
            raise FileSecurityError(f"Invalid image file: {str(e)}")

    @staticmethod
    def generate_secure_filename(original_filename: str, prefix: str = "", suffix: str = "") -> str:
        """
        Generate a secure filename with a random prefix.

        Args:
            original_filename: The original filename
            prefix: Optional prefix to add to the filename
            suffix: Optional suffix to add to the filename (before the extension)

        Returns:
            A secure filename
        """
        # Get the file extension
        ext = FileUtils.get_file_extension(original_filename)

        # Generate a random string for the filename
        random_str = uuid.uuid4().hex

        # Build the secure filename
        filename_parts = []
        if prefix:
            filename_parts.append(prefix)

        filename_parts.append(random_str)

        if suffix:
            filename_parts.append(suffix)

        filename = "_".join(filename_parts)

        # Add the extension if present
        if ext:
            filename = f"{filename}.{ext}"

        return filename

    @staticmethod
    def calculate_file_hash(
        file: Union[FileStorage, BinaryIO, bytes, str],
        algorithm: str = "sha256",
        chunk_size: int = 65536,
    ) -> str:
        """
        Calculate the hash of a file.

        Args:
            file: The file to hash (FileStorage, file-like object, bytes, or file path)
            algorithm: The hashing algorithm to use (default: 'sha256')
            chunk_size: The size of chunks to read (default: 64KB)

        Returns:
            The hexadecimal digest of the file's hash

        Raises:
            ValueError: If the algorithm is not supported
            FileNotFoundError: If the file does not exist (when file is a path)
        """
        # Get the hash function
        hash_func = getattr(hashlib, algorithm, None)
        if not hash_func:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        hasher = hash_func()

        # Handle different input types
        if isinstance(file, str):
            # Treat as file path
            with open(file, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hasher.update(chunk)
        elif isinstance(file, FileStorage):
            file.seek(0)
            for chunk in iter(lambda: file.read(chunk_size), b""):
                hasher.update(chunk)
            file.seek(0)
        elif hasattr(file, "read"):
            # File-like object
            current_pos = file.tell()
            file.seek(0)
            for chunk in iter(lambda: file.read(chunk_size), b""):
                hasher.update(chunk)
            file.seek(current_pos)
        elif isinstance(file, bytes):
            hasher.update(file)
        else:
            raise ValueError("Unsupported file type")

        return hasher.hexdigest()

    @staticmethod
    def sanitize_upload_path(base_dir: str, file_path: str) -> Path:
        """
        Sanitize a file path to prevent directory traversal attacks.

        Args:
            base_dir: The base directory that all files must be within
            file_path: The requested file path (relative to base_dir)

        Returns:
            A Path object representing the sanitized absolute path

        Raises:
            FileSecurityError: If the path would escape the base directory
        """
        # Convert to Path objects
        base_path = Path(base_dir).resolve()
        full_path = (base_path / file_path).resolve()

        # Check if the full path is within the base directory
        try:
            full_path.relative_to(base_path)
        except ValueError:
            raise FileSecurityError("Invalid file path")

        return full_path


# Create an instance for easy importing
file_utils = FileUtils()

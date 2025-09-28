"""
File sharing service with encryption and virus scanning.
"""
import os
import io
import magic
import hashlib
import logging
from typing import Tuple, Optional, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configure logging
logger = logging.getLogger(__name__)

class FileService:
    """Service for handling secure file uploads, downloads, and sharing."""
    
    def __init__(self, storage_path: str = None, max_file_size: int = 100 * 1024 * 1024):
        """Initialize the file service.
        
        Args:
            storage_path: Base directory for file storage
            max_file_size: Maximum allowed file size in bytes (default: 100MB)
        """
        self.storage_path = Path(storage_path or "./file_storage").absolute()
        self.max_file_size = max_file_size
        self.allowed_mime_types = {
            # Documents
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'text/csv',
            'application/rtf',
            'application/json',
            'application/xml',
            
            # Images
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'image/svg+xml',
            'image/tiff',
            'image/bmp',
            
            # Archives
            'application/zip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/x-tar',
            'application/gzip',
            'application/x-bzip2',
            
            # Audio
            'audio/mpeg',
            'audio/wav',
            'audio/ogg',
            'audio/webm',
            'audio/aac',
            
            # Video
            'video/mp4',
            'video/webm',
            'video/ogg',
            'video/x-msvideo',
            'video/x-ms-wmv',
            'video/quicktime',
            
            # Other
            'application/octet-stream'  # Fallback for unknown types
        }
        
        # Create storage directories if they don't exist
        self.encrypted_dir = self.storage_path / 'encrypted'
        self.temp_dir = self.storage_path / 'temp'
        self.quarantine_dir = self.storage_path / 'quarantine'
        
        for directory in [self.storage_path, self.encrypted_dir, self.temp_dir, self.quarantine_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _generate_key(self) -> bytes:
        """Generate a secure encryption key."""
        return os.urandom(32)  # 256 bits for AES-256
    
    def _generate_nonce(self) -> bytes:
        """Generate a secure nonce for encryption."""
        return os.urandom(12)  # 96 bits for AES-GCM
    
    def _derive_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive a key from a password using HKDF."""
        if salt is None:
            salt = os.urandom(16)
            
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'file-encryption',
        )
        
        key = hkdf.derive(password.encode('utf-8'))
        return key, salt
    
    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-GCM."""
        nonce = self._generate_nonce()
        aesgcm = AESGCM(key)
        
        # Encrypt the data
        ciphertext = aesgcm.encrypt(
            nonce=nonce,
            data=data,
            associated_data=None
        )
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-GCM."""
        if len(encrypted_data) < 28:  # 12 bytes nonce + 16 bytes tag
            raise ValueError("Encrypted data is too short")
            
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None
        )
    
    def _scan_file_for_viruses(self, file_path: Path) -> Tuple[bool, str]:
        """Scan a file for viruses.
        
        In a production environment, this would integrate with a virus scanning service.
        For now, we'll implement some basic checks.
        """
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return False, f"File size {file_size} exceeds maximum allowed size {self.max_file_size}"
            
            # Check file type
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(str(file_path))
            
            if mime_type not in self.allowed_mime_types and not mime_type.startswith('text/'):
                return False, f"File type {mime_type} is not allowed"
            
            # Check for common malware patterns (simplified example)
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB for initial scan
                
                # Look for potential shell scripts or executables in text files
                if mime_type.startswith('text/') and any(
                    pattern in content.lower()
                    for pattern in [b'<\?php', b'eval\(', b'base64_decode', b'system\(']
                ):
                    return False, "File contains potentially dangerous content"
            
            # If we get here, the file passed all checks
            return True, "File is clean"
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return False, f"Error scanning file: {str(e)}"
    
    def upload_file(self, file_data: bytes, filename: str, 
                   password: str = None, 
                   expiration_days: int = 7) -> Dict[str, Any]:
        """Upload and encrypt a file.
        
        Args:
            file_data: The file data as bytes
            filename: Original filename
            password: Optional password for additional encryption
            expiration_days: Number of days until the file expires
            
        Returns:
            Dict containing file metadata and access information
        """
        try:
            # Generate a unique file ID
            file_id = hashlib.sha256(os.urandom(32)).hexdigest()
            temp_path = self.temp_dir / f"{file_id}_{filename}"
            
            # Save the file temporarily for scanning
            with open(temp_path, 'wb') as f:
                f.write(file_data)
            
            # Scan the file for viruses
            is_safe, message = self._scan_file_for_viruses(temp_path)
            if not is_safe:
                # Move to quarantine
                quarantine_path = self.quarantine_dir / f"{file_id}_{filename}"
                temp_path.rename(quarantine_path)
                raise ValueError(f"File rejected: {message}")
            
            # Generate encryption key and nonce
            key = self._generate_key()
            
            # Encrypt the file
            encrypted_data = self._encrypt_data(file_data, key)
            
            # If a password is provided, encrypt the key
            encrypted_key = key
            salt = None
            if password:
                encrypted_key, salt = self._derive_key(password)
                encrypted_key = self._encrypt_data(key, encrypted_key)
            
            # Save the encrypted file
            encrypted_filename = f"{file_id}.enc"
            encrypted_path = self.encrypted_dir / encrypted_filename
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Clean up the temporary file
            temp_path.unlink()
            
            # Calculate expiration date
            expires_at = datetime.utcnow() + timedelta(days=expiration_days)
            
            # Return file metadata
            return {
                'file_id': file_id,
                'original_filename': filename,
                'encrypted_filename': encrypted_filename,
                'file_size': len(file_data),
                'encrypted_size': len(encrypted_data),
                'mime_type': magic.Magic(mime=True).from_buffer(file_data[:1024]),
                'sha256': hashlib.sha256(file_data).hexdigest(),
                'uploaded_at': datetime.utcnow().isoformat(),
                'expires_at': expires_at.isoformat(),
                'salt': b64encode(salt).decode('utf-8') if salt else None,
                'encrypted_key': b64encode(encrypted_key).decode('utf-8') if password else None
            }
            
        except Exception as e:
            # Clean up any temporary files
            if 'temp_path' in locals() and temp_path.exists():
                temp_path.unlink()
            raise
    
    def download_file(self, file_id: str, output_path: str = None, 
                     password: str = None, key: bytes = None) -> bytes:
        """Download and decrypt a file.
        
        Args:
            file_id: The ID of the file to download
            output_path: Optional path to save the decrypted file
            password: Password for decryption (if file was password-protected)
            key: Direct decryption key (alternative to password)
            
        Returns:
            Decrypted file data as bytes
        """
        try:
            # Find the encrypted file
            encrypted_path = None
            for f in self.encrypted_dir.glob(f"{file_id}*"):
                if f.is_file():
                    encrypted_path = f
                    break
            
            if not encrypted_path or not encrypted_path.exists():
                raise FileNotFoundError(f"File with ID {file_id} not found")
            
            # Read the encrypted data
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            # If we have a direct key, use it
            if key:
                decryption_key = key
            # If we have a password, derive the key
            elif password:
                # In a real implementation, you'd retrieve the salt and encrypted key from your database
                # For this example, we'll assume they're stored in the filename or metadata
                raise NotImplementedError("Password-based decryption requires database integration")
            else:
                raise ValueError("Either key or password must be provided")
            
            # Decrypt the data
            decrypted_data = self._decrypt_data(encrypted_data, decryption_key)
            
            # Save to output path if provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Error downloading file {file_id}: {str(e)}")
            raise
    
    def delete_expired_files(self) -> int:
        """Delete files that have passed their expiration date.
        
        Returns:
            Number of files deleted
        """
        deleted_count = 0
        now = datetime.utcnow()
        
        # Delete expired encrypted files
        for f in self.encrypted_dir.glob('*'):
            if f.is_file():
                # In a real implementation, you'd check the expiration date from metadata
                # For this example, we'll just delete files older than 7 days
                file_age = datetime.utcfromtimestamp(f.stat().st_mtime)
                if (now - file_age).days > 7:
                    try:
                        f.unlink()
                        deleted_count += 1
                    except Exception as e:
                        logger.error(f"Error deleting file {f}: {str(e)}")
        
        return deleted_count

# Example usage
if __name__ == "__main__":
    # Initialize the file service
    file_service = FileService()
    
    # Example file data
    test_data = b"This is a test file.\nIt contains some sample text."
    
    try:
        # Upload a file
        print("Uploading file...")
        result = file_service.upload_file(
            file_data=test_data,
            filename="test.txt",
            password="securepassword123",
            expiration_days=7
        )
        
        print(f"File uploaded successfully. ID: {result['file_id']}")
        print(f"Original size: {result['file_size']} bytes")
        print(f"Encrypted size: {result['encrypted_size']} bytes")
        
        # Download the file
        print("\nDownloading file...")
        decrypted_data = file_service.download_file(
            file_id=result['file_id'],
            password="securepassword123"
        )
        
        print(f"Decrypted content: {decrypted_data.decode('utf-8')}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

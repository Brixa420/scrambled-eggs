"""
Encryption service for handling secure data operations.
"""
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class EncryptionService:
    """Service for handling encryption and decryption operations."""
    
    def __init__(self, secret_key=None):
        """Initialize the encryption service."""
        self.secret_key = secret_key or os.urandom(32)  # 256-bit key by default
        self.fernet = Fernet(self._get_fernet_key())
    
    def _get_fernet_key(self):
        """Generate a Fernet key from the secret key."""
        # Fernet requires a URL-safe base64-encoded 32-byte key
        return base64.urlsafe_b64encode(self.secret_key)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt the provided data."""
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes")
        return self.fernet.encrypt(data)
    
    def decrypt(self, token: bytes) -> bytes:
        """Decrypt the provided token."""
        if not isinstance(token, bytes):
            raise ValueError("Token must be bytes")
        try:
            return self.fernet.decrypt(token)
        except InvalidToken as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError("Invalid or corrupted token") from e
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new encryption key."""
        return Fernet.generate_key()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None, iterations: int = 100000) -> tuple[bytes, bytes]:
        """
        Derive a secure key from a password using PBKDF2.
        
        Args:
            password: The password to derive the key from
            salt: Optional salt (randomly generated if not provided)
            iterations: Number of iterations for the key derivation function
            
        Returns:
            A tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key, salt
    
    def encrypt_file(self, input_file_path: str, output_file_path: str = None) -> str:
        """Encrypt a file."""
        if not output_file_path:
            output_file_path = f"{input_file_path}.enc"
            
        with open(input_file_path, 'rb') as f:
            data = f.read()
            
        encrypted_data = self.encrypt(data)
        
        with open(output_file_path, 'wb') as f:
            f.write(encrypted_data)
            
        return output_file_path
    
    def decrypt_file(self, input_file_path: str, output_file_path: str = None) -> str:
        """Decrypt a file."""
        if not output_file_path:
            if input_file_path.endswith('.enc'):
                output_file_path = input_file_path[:-4]
            else:
                output_file_path = f"{input_file_path}.dec"
                
        with open(input_file_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = self.decrypt(encrypted_data)
        
        with open(output_file_path, 'wb') as f:
            f.write(decrypted_data)
            
        return output_file_path
    
    def generate_secure_token(self, data: str, expires_in: int = 3600) -> str:
        """Generate a secure, time-limited token."""
        timestamp = str(int((datetime.utcnow() + timedelta(seconds=expires_in)).timestamp()))
        payload = f"{data}:{timestamp}".encode('utf-8')
        token = self.encrypt(payload)
        return token.decode('utf-8')
    
    def verify_secure_token(self, token: str) -> str:
        """Verify and decode a secure token."""
        try:
            payload = self.decrypt(token.encode('utf-8')).decode('utf-8')
            data, timestamp = payload.rsplit(':', 1)
            
            # Check if token has expired
            if datetime.utcnow() > datetime.fromtimestamp(int(timestamp)):
                raise ValueError("Token has expired")
                
            return data
        except (ValueError, IndexError, InvalidToken) as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise ValueError("Invalid or expired token") from e

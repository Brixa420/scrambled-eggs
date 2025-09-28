"""
Controller Module
----------------
Handles the business logic and acts as a bridge between the UI and backend components.
"""
import os
import logging
import json
import time
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
from dataclasses import asdict, dataclass

from .core import ScrambledEggs as ScrambledEggsCrypto
from .key_management import KeyManager
from .hsm.enterprise_hsm import EnterpriseHSM
from .pqc import PQCrypto
from .security.gateway import SecurityGateway

logger = logging.getLogger(__name__)

@dataclass
class EncryptionMetadata:
    """Metadata for encrypted files."""
    key_id: str
    algorithm: str
    timestamp: float
    encryption_layers: List[Dict[str, Any]]
    
    def to_json(self) -> str:
        """Convert metadata to JSON string."""
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EncryptionMetadata':
        """Create metadata from JSON string."""
        data = json.loads(json_str)
        return cls(**data)

class ScrambledEggsController:
    """Controller class to manage communication between UI and backend."""
    
    def __init__(self):
        self.encryption_engine: Optional[ScrambledEggsCrypto] = None
        self.key_manager = KeyManager()
        
        # Initialize HSM with default configuration
        hsm_config = {
            'enabled': True,
            'type': 'enterprise',
            'simulate': True,  # Use software simulation for development
            'log_level': 'INFO'
        }
        self.hsm_interface = EnterpriseHSM(hsm_config)
        
        # Initialize PQC engine with HSM
        self.pqc_engine = PQCrypto(self.hsm_interface)
        
        # Initialize security gateway
        self.security_gateway = SecurityGateway()
        
        # Initialize other instance variables
        self.current_user: Optional[Dict[str, Any]] = None
        self.initialized = False
        self._metadata: Dict[str, EncryptionMetadata] = {}
        self._active_sessions: Dict[str, Dict] = {}
        self._default_key_type = 'PQC_HYBRID'
        
    def initialize(self) -> bool:
        """Initialize the encryption engine and other components."""
        try:
            self.encryption_engine = ScrambledEggsCrypto()
            self.initialized = True
            logger.info("Encryption engine initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize encryption engine: {e}")
            self.initialized = False
            return False
            
    def login(self, username: str, password: str) -> bool:
        """
        Authenticate the user with the system.
        
        Args:
            username: The username for authentication
            password: The password for authentication
            
        Returns:
            bool: True if authentication was successful, False otherwise
        """
        try:
            # In a real implementation, this would verify credentials against a secure store
            if not username or not password:
                logger.warning("Login failed: Empty username or password")
                return False
                
            # For demo purposes, accept any non-empty credentials
            self.current_user = {
                'username': username,
                'authenticated': True,
                'last_login': time.time(),
                'permissions': ['encrypt', 'decrypt', 'manage_keys']
            }
            
            # Log the login event
            self.security_gateway.log_activity(
                'authentication',
                'login',
                f'User {username} logged in',
                severity='info'
            )
            
            logger.info(f"User {username} logged in successfully")
            return True
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            self.security_gateway.log_attempt(
                'authentication',
                'login',
                f'Failed login attempt for user {username}',
                success=False,
                metadata={'error': str(e)}
            )
            return False
        
    def encrypt_file(self, input_path: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Encrypt a file using the configured encryption engine.
        
        Args:
            input_path: Path to the file to encrypt
            output_path: Optional output path (defaults to input_path + '.enc')
            
        Returns:
            Tuple[bool, str]: (success, message) indicating the result
        """
        if not self.initialized or not self.encryption_engine:
            return False, "Encryption engine not initialized"
            
        try:
            input_path = Path(input_path)
            if not input_path.exists():
                return False, f"Input file not found: {input_path}"
                
            if output_path is None:
                output_path = str(input_path) + '.enc'
            
            # Generate a unique key for this encryption
            key_id = f"key_{int(time.time())}"
            
            # Create encryption metadata
            metadata = EncryptionMetadata(
                key_id=key_id,
                algorithm=self._default_key_type,
                timestamp=time.time(),
                encryption_layers=[
                    {
                        'type': 'PQC_HYBRID',
                        'key_id': key_id,
                        'timestamp': time.time()
                    }
                ]
            )
            
            # Read the file content
            with open(input_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt the file
            encrypted_data, encryption_metadata = self.encryption_engine.encrypt(
                file_data,
                associated_data=metadata.to_json().encode()
            )
            
            # Save the encrypted file with metadata
            with open(output_path, 'wb') as f:
                # Write metadata as JSON header
                metadata_dict = {
                    'version': '1.0',
                    'metadata': asdict(metadata),
                    'encryption_info': encryption_metadata
                }
                header = json.dumps(metadata_dict).encode()
                f.write(len(header).to_bytes(4, 'big'))  # Header length
                f.write(header)  # Header data
                f.write(encrypted_data)  # Encrypted content
            
            # Store metadata for later reference
            self._metadata[output_path] = metadata
            
            # Log the encryption event
            self.security_gateway.log_activity(
                'encryption',
                'file_encrypted',
                f'File {input_path.name} encrypted to {output_path}',
                metadata={
                    'input_path': str(input_path),
                    'output_path': output_path,
                    'key_id': key_id,
                    'size': os.path.getsize(output_path)
                }
            )
            
            return True, output_path
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return False, f"Encryption failed: {str(e)}"
            
    def decrypt_file(self, input_path: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Decrypt a file that was encrypted by this system.
        
        Args:
            input_path: Path to the encrypted file
            output_path: Optional output path (defaults to input_path without .enc)
            
        Returns:
            Tuple[bool, str]: (success, message) indicating the result
        """
        if not self.initialized or not self.encryption_engine:
            return False, "Encryption engine not initialized"
            
        try:
            input_path = Path(input_path)
            if not input_path.exists():
                return False, f"Input file not found: {input_path}"
            
            # Determine output path if not specified
            if output_path is None:
                if input_path.suffix == '.enc':
                    output_path = str(input_path)[:-4]  # Remove .enc extension
                else:
                    output_path = str(input_path) + '.dec'
            
            # Read the encrypted file
            with open(input_path, 'rb') as f:
                # Read the header length (first 4 bytes)
                header_length = int.from_bytes(f.read(4), 'big')
                
                # Read the header data
                header_data = json.loads(f.read(header_length).decode())
                
                # Read the encrypted content
                encrypted_data = f.read()
            
            # Extract metadata
            metadata = header_data.get('metadata', {})
            encryption_info = header_data.get('encryption_info', {})
            
            # Verify we can handle this version
            if header_data.get('version') != '1.0':
                return False, "Unsupported file format version"
            
            # Decrypt the content
            try:
                decrypted_data = self.encryption_engine.decrypt(
                    encrypted_data,
                    encryption_info['key_handle'],
                    metadata.get('associated_data', b''),
                    encryption_info
                )
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                # Log failed decryption attempt
                self.security_gateway.log_attempt(
                    'decryption',
                    'file_decrypt',
                    f'Failed to decrypt file {input_path.name}',
                    success=False,
                    metadata={'error': str(e), 'key_id': encryption_info.get('key_handle')}
                )
                return False, f"Decryption failed: {str(e)}"
            
            # Write the decrypted data to the output file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Log the successful decryption
            self.security_gateway.log_activity(
                'decryption',
                'file_decrypted',
                f'File {input_path.name} decrypted to {output_path}',
                metadata={
                    'input_path': str(input_path),
                    'output_path': output_path,
                    'key_id': encryption_info.get('key_handle'),
                    'size': os.path.getsize(output_path)
                }
            )
            
            return True, output_path
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return False, f"Decryption failed: {str(e)}"
            
    def generate_key_pair(self, key_type: str = 'PQC_HYBRID') -> Tuple[bool, str]:
        """Generate a new key pair."""
        try:
            # TODO: Implement actual key generation
            key_id = f"key_{len(self.key_manager.list_keys()) + 1}"
            return True, f"Key pair generated successfully with ID: {key_id}"
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            return False, f"Key generation failed: {str(e)}"
            
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get the current system status.
        
        Returns:
            Dict containing system status information
        """
        try:
            hsm_status = self.hsm_interface.get_status()
            key_count = len(self.key_manager.list_keys())
            
            return {
                'initialized': self.initialized,
                'user_authenticated': bool(self.current_user and self.current_user.get('authenticated')),
                'username': self.current_user.get('username') if self.current_user else None,
                'key_count': key_count,
                'hsm_connected': hsm_status.get('connected', False),
                'hsm_status': hsm_status,
                'active_sessions': len(self._active_sessions),
                'security_level': self.security_gateway.get_security_level(),
                'last_error': None,
                'timestamp': time.time()
            }
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {
                'initialized': False,
                'error': str(e),
                'timestamp': time.time()
            }
            
    def get_encryption_metadata(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for an encrypted file.
        
        Args:
            file_path: Path to the encrypted file
            
        Returns:
            Dict containing metadata, or None if not found/invalid
        """
        try:
            with open(file_path, 'rb') as f:
                # Read the header length (first 4 bytes)
                header_length = int.from_bytes(f.read(4), 'big')
                
                # Read and parse the header data
                header_data = json.loads(f.read(header_length).decode())
                
                # Return the metadata
                return {
                    'metadata': header_data.get('metadata', {}),
                    'encryption_info': header_data.get('encryption_info', {})
                }
        except Exception as e:
            logger.error(f"Error reading encryption metadata: {e}")
            return None

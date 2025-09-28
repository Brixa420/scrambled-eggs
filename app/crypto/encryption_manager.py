"""
Encryption manager for handling end-to-end encryption of messages and files.
"""
import os
import json
import logging
import base64
import hashlib
from typing import Dict, Optional, Tuple, Union, List

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Signature import DSS, eddsa
from Cryptodome.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)

# Type aliases
Key = bytes
PublicKey = bytes
PrivateKey = bytes
Signature = bytes
Nonce = bytes
Ciphertext = bytes
MAC = bytes

class EncryptionError(Exception):
    """Exception raised for errors in the encryption process."""
    pass

class KeyPair:
    """Represents a public/private key pair."""
    
    def __init__(self, public_key: bytes, private_key: Optional[bytes] = None):
        """Initialize with public and private keys."""
        self.public_key = public_key
        self.private_key = private_key
    
    @classmethod
    def generate_rsa(cls, key_size: int = 2048) -> 'KeyPair':
        """Generate a new RSA key pair."""
        key = RSA.generate(key_size)
        return cls(
            public_key=key.publickey().export_key(),
            private_key=key.export_key()
        )
    
    @classmethod
    def generate_ecc(cls, curve: str = 'ed25519') -> 'KeyPair':
        """Generate a new ECC key pair."""
        if curve == 'ed25519':
            key = ECC.generate(curve='ed25519')
            return cls(
                public_key=key.public_key().export_key(format='raw'),
                private_key=key.export_key(format='raw')
            )
        else:
            key = ECC.generate(curve='p256')
            return cls(
                public_key=key.public_key().export_key(format='PEM'),
                private_key=key.export_key(format='PEM')
            )
    
    @classmethod
    def from_private_key(cls, private_key: bytes, key_type: str = 'rsa') -> 'KeyPair':
        """Create a key pair from an existing private key."""
        if key_type == 'rsa':
            key = RSA.import_key(private_key)
            return cls(
                public_key=key.publickey().export_key(),
                private_key=private_key
            )
        elif key_type == 'ecc':
            key = ECC.import_key(private_key)
            return cls(
                public_key=key.public_key().export_key(format='PEM'),
                private_key=private_key
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
    
    def get_public_key(self) -> bytes:
        """Get the public key."""
        return self.public_key
    
    def get_private_key(self) -> Optional[bytes]:
        """Get the private key if available."""
        return self.private_key
    
    def has_private_key(self) -> bool:
        """Check if the private key is available."""
        return self.private_key is not None


class EncryptionManager:
    """Manages encryption, decryption, and key exchange."""
    
    def __init__(self, key_pair: Optional[KeyPair] = None):
        """Initialize with an optional key pair."""
        self.key_pair = key_pair or KeyPair.generate_ecc()
        self.ephemeral_keys: Dict[str, Tuple[bytes, float]] = {}  # peer_id -> (key, expiration)
        self.session_keys: Dict[str, bytes] = {}  # peer_id -> session_key
        self.trusted_keys: Dict[str, bytes] = {}  # peer_id -> public_key
        self.signature_keys: Dict[str, bytes] = {}  # peer_id -> signature_public_key
        self.key_expiry = 3600  # 1 hour in seconds
    
    # Key Management
    
    def generate_session_key(self) -> bytes:
        """Generate a random session key for symmetric encryption."""
        return get_random_bytes(32)  # 256-bit key
    
    def generate_nonce(self, size: int = 16) -> bytes:
        """Generate a random nonce."""
        return get_random_bytes(size)
    
    def add_trusted_key(self, peer_id: str, public_key: bytes, signature_public_key: Optional[bytes] = None) -> None:
        """Add a trusted public key for a peer."""
        self.trusted_keys[peer_id] = public_key
        if signature_public_key:
            self.signature_keys[peer_id] = signature_public_key
    
    def remove_trusted_key(self, peer_id: str) -> None:
        """Remove a trusted public key."""
        self.trusted_keys.pop(peer_id, None)
        self.signature_keys.pop(peer_id, None)
    
    def get_public_key(self) -> bytes:
        """Get the local public key."""
        return self.key_pair.get_public_key()
    
    # Encryption/Decryption
    
    def encrypt_with_public_key(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using the recipient's public key."""
        try:
            # For small data, use RSA directly
            if len(data) <= 190:  # RSA-2048 can encrypt up to 190 bytes
                rsa_key = RSA.import_key(public_key)
                cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
                return cipher.encrypt(data)
            
            # For larger data, use hybrid encryption
            # Generate a random session key
            session_key = self.generate_session_key()
            
            # Encrypt the data with the session key
            cipher = AES.new(session_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            # Encrypt the session key with the recipient's public key
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
            enc_session_key = cipher_rsa.encrypt(session_key)
            
            # Return the encrypted data with the encrypted session key and nonce
            return enc_session_key + cipher.nonce + tag + ciphertext
            
        except Exception as e:
            logger.error(f"Error encrypting with public key: {e}")
            raise EncryptionError(f"Encryption failed: {e}")
    
    def decrypt_with_private_key(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the local private key."""
        if not self.key_pair.has_private_key():
            raise EncryptionError("No private key available for decryption")
        
        try:
            # Check if this is a hybrid encrypted message (starts with encrypted session key)
            if len(encrypted_data) > 256:  # RSA-2048 encrypted data is 256 bytes
                # Extract the encrypted session key, nonce, tag, and ciphertext
                enc_session_key = encrypted_data[:256]
                nonce = encrypted_data[256:272]  # 16 bytes for nonce
                tag = encrypted_data[272:288]    # 16 bytes for tag
                ciphertext = encrypted_data[288:]
                
                # Decrypt the session key with the private key
                rsa_key = RSA.import_key(self.key_pair.get_private_key())
                cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
                session_key = cipher_rsa.decrypt(enc_session_key)
                
                # Decrypt the data with the session key
                cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext, tag)
            else:
                # Direct RSA decryption for small data
                rsa_key = RSA.import_key(self.key_pair.get_private_key())
                cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
                return cipher.decrypt(encrypted_data)
                
        except Exception as e:
            logger.error(f"Error decrypting with private key: {e}")
            raise EncryptionError(f"Decryption failed: {e}")
    
    def encrypt_message(self, peer_id: str, message: bytes) -> Tuple[bytes, bytes]:
        """Encrypt a message for a specific peer."""
        if peer_id not in self.trusted_keys:
            raise EncryptionError(f"No trusted key for peer {peer_id}")
        
        # Generate a random nonce
        nonce = self.generate_nonce()
        
        # Derive a session key for this peer if it doesn't exist
        if peer_id not in self.session_keys:
            self.session_keys[peer_id] = self.generate_session_key()
        
        session_key = self.session_keys[peer_id]
        
        # Encrypt the message with the session key
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        # Return the encrypted message with the nonce and tag
        return nonce + tag + ciphertext, session_key
    
    def decrypt_message(self, peer_id: str, encrypted_data: bytes) -> bytes:
        """Decrypt a message from a specific peer."""
        if peer_id not in self.session_keys:
            raise EncryptionError(f"No session key for peer {peer_id}")
        
        session_key = self.session_keys[peer_id]
        
        # Extract the nonce, tag, and ciphertext
        nonce = encrypted_data[:16]  # 16 bytes for nonce
        tag = encrypted_data[16:32]  # 16 bytes for tag
        ciphertext = encrypted_data[32:]
        
        # Decrypt the message with the session key
        try:
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            logger.error(f"Error decrypting message from {peer_id}: {e}")
            raise EncryptionError(f"Decryption failed: {e}")
    
    # Key Exchange
    
    def generate_key_exchange(self, peer_id: str) -> Tuple[bytes, bytes]:
        """Generate a key exchange message for a peer."""
        # Generate an ephemeral key pair for this exchange
        ephemeral_key = self.generate_session_key()
        
        # Store the ephemeral key with expiration
        import time
        self.ephemeral_keys[peer_id] = (ephemeral_key, time.time() + self.key_expiry)
        
        # Encrypt the ephemeral key with the peer's public key
        if peer_id not in self.trusted_keys:
            raise EncryptionError(f"No trusted key for peer {peer_id}")
        
        encrypted_key = self.encrypt_with_public_key(ephemeral_key, self.trusted_keys[peer_id])
        
        # Sign the ephemeral key with our private key
        signature = self.sign_data(ephemeral_key)
        
        return encrypted_key, signature
    
    def complete_key_exchange(self, peer_id: str, encrypted_key: bytes, signature: bytes) -> bool:
        """Complete a key exchange initiated by a peer."""
        try:
            # Verify the signature
            if not self.verify_signature(peer_id, encrypted_key, signature):
                logger.warning(f"Invalid signature from {peer_id}")
                return False
            
            # Decrypt the ephemeral key
            ephemeral_key = self.decrypt_with_private_key(encrypted_key)
            
            # Store the session key
            self.session_keys[peer_id] = ephemeral_key
            
            return True
            
        except Exception as e:
            logger.error(f"Error completing key exchange with {peer_id}: {e}")
            return False
    
    # Signatures
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with the local private key."""
        if not self.key_pair.has_private_key():
            raise EncryptionError("No private key available for signing")
        
        try:
            # Use Ed25519 for signing if available
            key = ECC.import_key(self.key_pair.get_private_key())
            signer = eddsa.new(key, 'rfc8032')
            return signer.sign(data)
        except Exception as e:
            logger.error(f"Error signing data: {e}")
            raise EncryptionError(f"Signing failed: {e}")
    
    def verify_signature(self, peer_id: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature from a peer."""
        if peer_id not in self.signature_keys:
            logger.warning(f"No signature key for peer {peer_id}")
            return False
        
        try:
            key = ECC.import_key(self.signature_keys[peer_id])
            verifier = eddsa.new(key, 'rfc8032')
            verifier.verify(data, signature)
            return True
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid signature from {peer_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error verifying signature from {peer_id}: {e}")
            return False
    
    # File Encryption
    
    def encrypt_file(self, input_path: str, output_path: str, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt a file with a random key.
        
        Args:
            input_path: Path to the input file
            output_path: Path to save the encrypted file
            key: Optional encryption key (if None, a random key will be generated)
            
        Returns:
            A tuple of (key, nonce) used for encryption
        """
        chunk_size = 64 * 1024  # 64KB chunks
        
        # Generate a random key and nonce if not provided
        if key is None:
            key = self.generate_session_key()
        
        nonce = self.generate_nonce()
        
        # Initialize the cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Write the nonce to the output file
            fout.write(nonce)
            
            # Process the file in chunks
            while True:
                chunk = fin.read(chunk_size)
                if len(chunk) == 0:
                    break
                
                # Encrypt the chunk
                if len(chunk) % 16 != 0:
                    # Pad the last chunk if needed
                    chunk = pad(chunk, 16)
                
                encrypted_chunk = cipher.encrypt(chunk)
                fout.write(encrypted_chunk)
            
            # Get the MAC tag
            tag = cipher.digest()
            fout.write(tag)
        
        return key, nonce
    
    def decrypt_file(self, input_path: str, output_path: str, key: bytes) -> bool:
        """Decrypt a file with the given key.
        
        Args:
            input_path: Path to the encrypted file
            output_path: Path to save the decrypted file
            key: The decryption key
            
        Returns:
            True if decryption was successful, False otherwise
        """
        chunk_size = 64 * 1024  # 64KB chunks
        
        try:
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Read the nonce from the input file
                nonce = fin.read(16)
                
                # Get the file size and calculate the total chunks
                file_size = os.path.getsize(input_path)
                total_chunks = (file_size - 16 - 16) // chunk_size  # Subtract nonce and tag
                
                # Initialize the cipher
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                # Process the file in chunks
                for i in range(total_chunks + 1):
                    chunk = fin.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    
                    # On the last chunk, separate the tag from the data
                    if i == total_chunks:
                        chunk, tag = chunk[:-16], chunk[-16:]
                        try:
                            decrypted_chunk = cipher.decrypt_and_verify(chunk, tag)
                            fout.write(decrypted_chunk)
                        except ValueError as e:
                            logger.error(f"Decryption failed: {e}")
                            return False
                    else:
                        decrypted_chunk = cipher.decrypt(chunk)
                        fout.write(decrypted_chunk)
                
            return True
            
        except Exception as e:
            logger.error(f"Error decrypting file: {e}")
            return False

"""
Self-Modifying Encryption

Implements self-modifying encryption that evolves when security is compromised.
"""
import logging
import os
import sys
import time
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from .crypto_engine import CryptoEngine
from .security_policy import SecurityPolicy

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security level for self-modifying encryption."""
    LOW = auto()        # Basic encryption, faster but less secure
    MEDIUM = auto()     # Balanced security and performance
    HIGH = auto()       # Maximum security, may impact performance
    PARANOID = auto()   # Extreme security, significant performance impact

@dataclass
class SecurityProfile:
    """Defines a security profile with specific parameters."""
    level: SecurityLevel
    key_size: int
    iterations: int
    algorithm: str
    mode: str
    kdf_iterations: int
    rekey_interval: int  # in seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security profile to a dictionary."""
        return {
            'level': self.level.name,
            'key_size': self.key_size,
            'iterations': self.iterations,
            'algorithm': self.algorithm,
            'mode': self.mode,
            'kdf_iterations': self.kdf_iterations,
            'rekey_interval': self.rekey_interval
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityProfile':
        """Create a security profile from a dictionary."""
        return cls(
            level=SecurityLevel[data['level']],
            key_size=data['key_size'],
            iterations=data['iterations'],
            algorithm=data['algorithm'],
            mode=data['mode'],
            kdf_iterations=data['kdf_iterations'],
            rekey_interval=data['rekey_interval']
        )

class SelfModifyingEncryption:
    """
    Implements self-modifying encryption that evolves based on security events.
    """
    
    # Default security profiles
    SECURITY_PROFILES = {
        SecurityLevel.LOW: SecurityProfile(
            level=SecurityLevel.LOW,
            key_size=128,          # 128-bit key
            iterations=1000,       # Fewer iterations for better performance
            algorithm='AES',
            mode='CBC',
            kdf_iterations=10000,  # Fewer KDF iterations
            rekey_interval=86400   # 24 hours
        ),
        SecurityLevel.MEDIUM: SecurityProfile(
            level=SecurityLevel.MEDIUM,
            key_size=192,          # 192-bit key
            iterations=10000,      # Balanced iterations
            algorithm='AES',
            mode='GCM',
            kdf_iterations=100000, # Standard KDF iterations
            rekey_interval=43200   # 12 hours
        ),
        SecurityLevel.HIGH: SecurityProfile(
            level=SecurityLevel.HIGH,
            key_size=256,          # 256-bit key
            iterations=100000,     # More iterations for better security
            algorithm='AES',
            mode='GCM',
            kdf_iterations=500000, # More KDF iterations
            rekey_interval=21600   # 6 hours
        ),
        SecurityLevel.PARANOID: SecurityProfile(
            level=SecurityLevel.PARANOID,
            key_size=256,          # 256-bit key
            iterations=1000000,    # Maximum iterations for best security
            algorithm='AES',
            mode='GCM',
            kdf_iterations=1000000, # Maximum KDF iterations
            rekey_interval=3600    # 1 hour
        )
    }
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM, 
                 security_policy: Optional[SecurityPolicy] = None):
        """
        Initialize the self-modifying encryption engine.
        
        Args:
            security_level: Initial security level
            security_policy: Optional security policy override
        """
        self.security_policy = security_policy or SecurityPolicy()
        self.security_level = security_level
        self.current_profile = self.SECURITY_PROFILES[security_level]
        self.crypto_engine = CryptoEngine()
        
        # Track security events and adaptation state
        self.security_events: List[Dict[str, Any]] = []
        self.last_rekey_time = time.time()
        self.rekey_count = 0
        
        # Initialize with default key
        self._current_key = self._generate_key()
        
        logger.info(f"Initialized SelfModifyingEncryption with {security_level.name} security level")
    
    def _generate_key(self) -> bytes:
        """Generate a new encryption key based on the current security profile."""
        # Use a KDF to derive the key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.current_profile.key_size // 8,  # Convert bits to bytes
            salt=os.urandom(16),  # Random salt
            iterations=self.current_profile.kdf_iterations
        )
        
        # Generate a random key
        key = kdf.derive(os.urandom(32))  # 256 bits of entropy
        return key
    
    def _should_rekey(self) -> bool:
        """Determine if it's time to rekey based on the security profile."""
        time_since_rekey = time.time() - self.last_rekey_time
        return time_since_rekey >= self.current_profile.rekey_interval
    
    def _adapt_security_level(self, event: Optional[Dict[str, Any]] = None) -> None:
        """
        Adjust the security level based on recent events.
        
        Args:
            event: Optional security event that triggered the adaptation
        """
        if event:
            self.security_events.append(event)
            
            # Only keep recent events (last hour)
            current_time = time.time()
            self.security_events = [
                e for e in self.security_events
                if current_time - e.get('timestamp', 0) <= 3600
            ]
        
        # Count recent security events
        recent_events = len(self.security_events)
        
        # Simple adaptation logic - can be enhanced based on specific requirements
        if recent_events > 10:
            # Multiple security events detected, increase security
            new_level = min(
                SecurityLevel.PARANOID,
                SecurityLevel(max(self.security_level.value + 1, SecurityLevel.PARANOID.value))
            )
        elif recent_events > 5:
            # Some security events, increase security one level
            new_level = min(
                SecurityLevel.PARANOID,
                SecurityLevel(max(self.security_level.value + 1, SecurityLevel.MEDIUM.value))
            )
        elif recent_events == 0 and self.security_level > SecurityLevel.MEDIUM:
            # No recent events, consider reducing security for better performance
            new_level = SecurityLevel(max(self.security_level.value - 1, SecurityLevel.MEDIUM.value))
        else:
            # No change needed
            return
        
        # Update security level if changed
        if new_level != self.security_level:
            old_level = self.security_level
            self.security_level = new_level
            self.current_profile = self.SECURITY_PROFILES[new_level]
            logger.info(f"Security level changed from {old_level.name} to {new_level.name}")
            
            # Rekey with the new security level
            self._rekey()
    
    def _rekey(self) -> None:
        """Generate a new encryption key and update the key material."""
        self._current_key = self._generate_key()
        self.last_rekey_time = time.time()
        self.rekey_count += 1
        logger.debug(f"Rekeyed encryption (count: {self.rekey_count})")
    
    def encrypt(self, plaintext: bytes, additional_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Encrypt data with the current encryption parameters.
        
        Args:
            plaintext: Data to encrypt
            additional_data: Optional additional authenticated data
            
        Returns:
            Dictionary containing the encrypted data and metadata
        """
        # Check if we need to rekey
        if self._should_rekey():
            self._rekey()
        
        # Generate a random IV/nonce
        iv = os.urandom(16)  # 128 bits for AES
        
        # Set up the cipher based on the current profile
        if self.current_profile.algorithm == 'AES':
            if self.current_profile.mode == 'CBC':
                # For CBC mode, we need to pad the data
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(self._current_key),
                    modes.CBC(iv)
                )
                encryptor = cipher.encryptor()
                
                # Encrypt
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # For CBC, we need to return the IV and ciphertext
                return {
                    'ciphertext': ciphertext,
                    'iv': iv,
                    'security_level': self.security_level.name,
                    'algorithm': f"AES-{self.current_profile.key_size}-CBC",
                    'timestamp': time.time()
                }
                
            elif self.current_profile.mode == 'GCM':
                # For GCM mode, we get built-in authentication
                cipher = Cipher(
                    algorithms.AES(self._current_key),
                    modes.GCM(iv)
                )
                encryptor = cipher.encryptor()
                
                # Add additional authenticated data if provided
                if additional_data:
                    encryptor.authenticate_additional_data(additional_data)
                
                # Encrypt and finalize to get the tag
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                tag = encryptor.tag
                
                return {
                    'ciphertext': ciphertext,
                    'iv': iv,
                    'tag': tag,
                    'security_level': self.security_level.name,
                    'algorithm': f"AES-{self.current_profile.key_size}-GCM",
                    'timestamp': time.time()
                }
        
        # Fallback to the crypto engine if the mode is not directly supported
        return self.crypto_engine.encrypt_message(
            plaintext.decode('utf-8'),
            self.crypto_engine.get_public_key()
        )
    
    def decrypt(self, encrypted_data: Dict[str, Any], additional_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data that was encrypted with this engine.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            additional_data: Optional additional authenticated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If decryption fails or the data is invalid
        """
        try:
            # Extract common fields
            ciphertext = encrypted_data['ciphertext']
            iv = encrypted_data['iv']
            algorithm = encrypted_data.get('algorithm', '')
            
            # Handle different encryption modes
            if 'GCM' in algorithm:
                # GCM mode
                if 'tag' not in encrypted_data:
                    raise ValueError("Missing authentication tag for GCM mode")
                
                tag = encrypted_data['tag']
                cipher = Cipher(
                    algorithms.AES(self._current_key),
                    modes.GCM(iv, tag)
                )
                decryptor = cipher.decryptor()
                
                # Add additional authenticated data if provided
                if additional_data:
                    decryptor.authenticate_additional_data(additional_data)
                
                # Decrypt
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return plaintext
                
            elif 'CBC' in algorithm:
                # CBC mode
                cipher = Cipher(
                    algorithms.AES(self._current_key),
                    modes.CBC(iv)
                )
                decryptor = cipher.decryptor()
                
                # Decrypt
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Unpad
                unpadder = padding.PKCS7(128).unpadder()
                return unpadder.update(padded_plaintext) + unpadder.finalize()
                
            else:
                # Fallback to crypto engine
                return self.crypto_engine.decrypt_message(encrypted_data).encode('utf-8')
                
        except Exception as e:
            # Log the security event
            self._adapt_security_level({
                'type': 'decryption_failure',
                'error': str(e),
                'timestamp': time.time(),
                'algorithm': algorithm
            })
            raise ValueError(f"Decryption failed: {e}")
    
    def get_security_status(self) -> Dict[str, Any]:
        """
        Get the current security status.
        
        Returns:
            Dictionary with security status information
        """
        return {
            'security_level': self.security_level.name,
            'profile': self.current_profile.to_dict(),
            'rekey_count': self.rekey_count,
            'last_rekey': datetime.fromtimestamp(self.last_rekey_time).isoformat(),
            'next_rekey_in': max(0, self.last_rekey_time + self.current_profile.rekey_interval - time.time()),
            'recent_security_events': len(self.security_events)
        }
    
    def handle_security_event(self, event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Handle a security event that might trigger adaptation.
        
        Args:
            event_type: Type of security event (e.g., 'brute_force_attempt')
            details: Additional event details
        """
        event = {
            'type': event_type,
            'timestamp': time.time(),
            'details': details or {}
        }
        
        # Log the event
        logger.warning(f"Security event: {event_type} - {details}")
        
        # Adapt security level based on the event
        self._adapt_security_level(event)
        
        # If this was a serious event, consider rekeying immediately
        if event_type in ['key_compromise', 'suspicious_activity']:
            self._rekey()

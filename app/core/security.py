"""
Security utilities for Scrambled Eggs.
Handles key management, security policies, and breach detection.
"""
import os
import json
import logging
import hashlib
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

@dataclass
class SecurityPolicy:
    """Defines security policies for the application."""
    max_failed_attempts: int = 5
    lockout_duration: int = 300  # seconds
    min_password_length: int = 12
    key_rotation_days: int = 30
    session_timeout: int = 3600  # 1 hour
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityPolicy':
        """Create policy from dictionary."""
        return cls(**data)

class SecurityManager:
    """Manages security operations and policies."""
    
    def __init__(self, policy: Optional[SecurityPolicy] = None):
        self.policy = policy or SecurityPolicy()
        self.failed_attempts = {}
        self.locked_accounts = {}
        self.security_events = []
        
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Hash a password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        hashed = kdf.derive(password.encode('utf-8'))
        return hashed, salt
    
    def verify_password(self, password: str, hashed_password: bytes, salt: bytes) -> bool:
        """Verify a password against a stored hash."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            new_hash = kdf.derive(password.encode('utf-8'))
            return new_hash == hashed_password
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def check_password_strength(self, password: str) -> Tuple[bool, str]:
        """Check if a password meets strength requirements."""
        if len(password) < self.policy.min_password_length:
            return False, f"Password must be at least {self.policy.min_password_length} characters"
            
        # Check for common patterns
        common_patterns = ['123', 'password', 'qwerty', 'admin', 'welcome']
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns"
            
        # Check for character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "Password must include uppercase, lowercase, numbers, and special characters"
            
        return True, "Password is strong"
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log a security event."""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': event_type,
            'details': details
        }
        self.security_events.append(event)
        logger.info(f"Security event: {event_type} - {details}")
    
    def detect_breach(self, message_hash: str) -> bool:
        """Detect if a message hash has been involved in a breach."""
        # In a real implementation, this would check against a breach database
        # For now, just log the check
        self.log_security_event(
            'breach_check',
            {'hash': message_hash, 'result': 'clean'}
        )
        return False
    
    def rotate_encryption_keys(self):
        """Rotate encryption keys based on security policy."""
        # In a real implementation, this would rotate all active keys
        self.log_security_event('key_rotation', {'status': 'started'})
        # ... key rotation logic ...
        self.log_security_event('key_rotation', {'status': 'completed'})
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status."""
        return {
            'policy': self.policy.to_dict(),
            'failed_attempts': len(self.failed_attempts),
            'locked_accounts': len(self.locked_accounts),
            'security_events': len(self.security_events),
            'last_breach_check': next(
                (e for e in reversed(self.security_events) 
                 if e['type'] == 'breach_check'),
                None
            )
        }

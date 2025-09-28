""
Security utility functions.
"""
import os
import re
import hmac
import hashlib
import secrets
import string
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List, Union
from functools import wraps
from flask import request, jsonify, current_app, g

class SecurityUtils:
    """Collection of security utility methods."""
    
    @staticmethod
    def generate_secure_random(length: int = 32) -> str:
        """Generate a secure random string."""
        if length < 1:
            raise ValueError("Length must be at least 1")
        
        # Use secrets module for cryptographic randomness
        alphabet = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a secure password with mixed case, numbers, and special chars."""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest of the password with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Hash a password with a salt."""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Use PBKDF2 with SHA-256 for key derivation
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # Number of iterations
            dklen=128  # Length of the derived key
        )
        
        return key, salt
    
    @staticmethod
    def verify_password(stored_hash: bytes, stored_salt: bytes, provided_password: str) -> bool:
        """Verify a password against a stored hash and salt."""
        new_hash, _ = SecurityUtils.hash_password(provided_password, stored_salt)
        return hmac.compare_digest(stored_hash, new_hash)
    
    @staticmethod
    def is_strong_password(password: str) -> Tuple[bool, List[str]]:
        """Check if a password meets strength requirements."""
        errors = []
        
        # Minimum length
        if len(password) < 12:
            errors.append("Password must be at least 12 characters long")
        
        # Check for common patterns
        common_patterns = [
            '123456', 'password', 'qwerty', 'letmein', 'welcome',
            'admin', 'login', 'abc123', '111111', 'password1'
        ]
        
        if password.lower() in common_patterns:
            errors.append("Password is too common")
        
        # Check for character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not has_upper:
            errors.append("Password must contain at least one uppercase letter")
        if not has_lower:
            errors.append("Password must contain at least one lowercase letter")
        if not has_digit:
            errors.append("Password must contain at least one digit")
        if not has_special:
            errors.append("Password must contain at least one special character")
        
        # Check for sequential characters
        if re.search(r'(.)\1{2,}', password):
            errors.append("Password contains repeated characters")
        
        # Check for common sequences
        sequences = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', 'abcdef',
            'password', 'admin', 'welcome', 'qazwsx', '1q2w3e'
        ]
        
        password_lower = password.lower()
        for seq in sequences:
            if seq in password_lower or seq[::-1] in password_lower:
                errors.append(f"Password contains a common sequence: {seq}")
                break
        
        return len(errors) == 0, errors
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate a CSRF token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_csrf_token(token: str, stored_token: str) -> bool:
        """Validate a CSRF token."""
        return hmac.compare_digest(token, stored_token)
    
    @staticmethod
    def is_safe_redirect_url(target: str) -> bool:
        """Check if a redirect URL is safe."""
        # Check if the URL is relative
        if not target or target.startswith('/'):
            return True
        
        # Check if the URL is an absolute URL to the same host
        from urllib.parse import urlparse
        
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        
        return (
            test_url.scheme in ('http', 'https') and
            test_url.netloc == ref_url.netloc
        )
    
    @staticmethod
    def get_client_ip() -> str:
        """Get the client's IP address, handling proxies."""
        # List of possible headers that might contain the real IP
        ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP'     # Cloudflare and others
        ]
        
        # Check each header
        for header in ip_headers:
            ip = request.headers.get(header)
            if ip:
                # X-Forwarded-For can contain multiple IPs, take the first one
                if ',' in ip:
                    ip = ip.split(',')[0].strip()
                
                # Validate the IP address
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except ValueError:
                    continue
        
        # Fall back to the remote address
        return request.remote_addr or '0.0.0.0'
    
    @staticmethod
    def rate_limit_key() -> str:
        """Generate a key for rate limiting based on the request."""
        # Use the client's IP address by default
        key = SecurityUtils.get_client_ip()
        
        # If the user is authenticated, include their user ID
        if hasattr(g, 'user') and g.user and hasattr(g.user, 'id'):
            key += f":{g.user.id}"
        
        # Include the endpoint in the key
        key += f":{request.endpoint or 'unknown'}

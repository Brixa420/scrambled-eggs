"""Security utilities for the application."""
import re
import string
import random
import hashlib
import hmac
import base64
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, Union, List, Callable
from functools import wraps
import bcrypt
from email_validator import validate_email, EmailNotValidError
from slugify import slugify
import magic
from PIL import Image
from io import BytesIO
import pyotp
import pytz

from flask import request, jsonify, current_app, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

# Import config
from .config import get_config

# Initialize config
config = get_config()

# Constants
PASSWORD_SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?'

class SecurityUtils:
    """Class containing security utility methods."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Generate a salt and hash the password
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def check_password(hashed_password: str, user_password: str) -> bool:
        """Check if the provided password matches the hashed password."""
        if not hashed_password or not user_password:
            return False
        
        try:
            return bcrypt.checkpw(
                user_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_email_address(email: str) -> Tuple[bool, str]:
        """Validate an email address."""
        try:
            # Validate and normalize the email
            valid = validate_email(email)
            return True, valid.email
        except EmailNotValidError as e:
            return False, str(e)
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """Validate password strength."""
        if len(password) < config.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters long"
        
        if config.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
            
        if config.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
            
        if config.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
            
        if config.PASSWORD_REQUIRE_SPECIAL and not any(c in PASSWORD_SPECIAL_CHARS for c in password):
            return False, f"Password must contain at least one special character: {PASSWORD_SPECIAL_CHARS}"
        
        return True, "Password is strong"
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a secure random token."""
        if length < 16:
            raise ValueError("Token length must be at least 16 characters")
            
        # Generate a cryptographically secure random token
        token = os.urandom(length)
        return base64.urlsafe_b64encode(token).decode('utf-8').rstrip('=')
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate a CSRF token."""
        return SecurityUtils.generate_secure_token(32)
    
    @staticmethod
    def secure_filename(filename: str) -> str:
        """Sanitize a filename to be safe for the filesystem."""
        if not filename:
            return ""
            
        # Use slugify to create a safe filename
        base, ext = os.path.splitext(filename)
        safe_base = slugify(base)
        
        # Ensure the extension is safe
        safe_ext = ''.join(c for c in ext if c.isalnum() or c in '._-')
        
        # Combine and ensure the filename isn't empty
        safe_name = f"{safe_base}{safe_ext}"
        if not safe_name:
            safe_name = f"file_{int(datetime.utcnow().timestamp())}"
            
        return safe_name
    
    @staticmethod
    def is_allowed_file(filename: str) -> bool:
        """Check if the file extension is allowed."""
        if not filename:
            return False
            
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS
    
    @staticmethod
    def validate_file_type(file_stream, allowed_mime_types: list = None) -> bool:
        """Validate the file type using magic numbers."""
        if not file_stream:
            return False
            
        # Read the first 2048 bytes to determine the file type
        header = file_stream.read(2048)
        file_stream.seek(0)  # Reset file pointer
        
        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_buffer(header)
            
            if allowed_mime_types:
                return mime_type in allowed_mime_types
                
            # Default to allowed extensions if no MIME types specified
            ext = os.path.splitext(getattr(file_stream, 'filename', ''))[1].lower().lstrip('.')
            return ext in config.ALLOWED_EXTENSIONS
            
        except Exception:
            return False
    
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a TOTP secret for MFA."""
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        """Get the provisioning URI for a TOTP secret."""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=email,
            issuer_name=config.MFA_ISSUER
        )
    
    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """Verify a TOTP token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    @staticmethod
    def sanitize_input(input_str: str, allowed_tags: list = None) -> str:
        """Sanitize user input to prevent XSS."""
        if not input_str:
            return ""
            
        # Remove or escape HTML/JavaScript
        if allowed_tags:
            # If specific tags are allowed, use a more sophisticated sanitizer
            import bleach
            return bleach.clean(input_str, tags=allowed_tags, strip=True)
        else:
            # Basic HTML escaping
            import html
            return html.escape(input_str)
    
    @staticmethod
    def log_security_event(event_type: str, user_id: str = None, 
                          ip_address: str = None, details: str = None) -> None:
        """Log a security event."""
        if not hasattr(current_app, 'logger'):
            return
            
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address or request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'details': details
        }
        
        current_app.logger.info(f"SECURITY_EVENT: {log_entry}")
        
        # You could also send this to a security monitoring system
        # e.g., SIEM, Splunk, etc.


# Create an instance for easy importing
security_utils = SecurityUtils()

""
Security-related utility functions.
"""
import os
import secrets
import string
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable, Union
import jwt
from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_identity, get_jwt,
    create_access_token, create_refresh_token
)
from werkzeug.exceptions import Forbidden, Unauthorized

# Rate limiting storage (in production, use Redis or similar)
_rate_limit_storage = {}

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Length of the token in bytes (before base64 encoding)
        
    Returns:
        A URL-safe base64-encoded token
    """
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2 with HMAC-SHA256.
    
    Args:
        password: The password to hash
        
    Returns:
        A hashed password string in the format: algorithm$iterations$salt$hash
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    # Generate a random salt
    salt = os.urandom(16)
    
    # Use PBKDF2 with HMAC-SHA256
    iterations = 100000
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    
    # Format: algorithm$iterations$salt$hash
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(dk).decode('utf-8')}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        stored_password: The stored hashed password
        provided_password: The password to verify
        
    Returns:
        True if the password matches, False otherwise
    """
    if not stored_password or not provided_password:
        return False
    
    try:
        # Parse the stored password
        algorithm, iterations, salt, stored_hash = stored_password.split('$')
        
        if algorithm != 'pbkdf2_sha256':
            return False
        
        # Decode the salt and hash
        salt_bytes = base64.b64decode(salt)
        stored_hash_bytes = base64.b64decode(stored_hash)
        
        # Hash the provided password with the same parameters
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt_bytes,
            int(iterations)
        )
        
        # Compare the hashes in constant time
        return hmac.compare_digest(dk, stored_hash_bytes)
    
    except (ValueError, TypeError):
        return False

def generate_verification_token(email: str, expires_in: int = 3600) -> str:
    """
    Generate a JWT token for email verification.
    
    Args:
        email: The email to include in the token
        expires_in: Token expiration time in seconds (default: 1 hour)
        
    Returns:
        A JWT token string
    """
    payload = {
        'email': email,
        'purpose': 'email_verification',
        'exp': datetime.utcnow() + timedelta(seconds=expires_in)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_verification_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify a JWT verification token.
    
    Args:
        token: The JWT token to verify
        
    Returns:
        The decoded token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('purpose') != 'email_verification':
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, Exception):
        return None

def rate_limit(limit: int = 10, period: int = 60, by: str = 'ip') -> Callable:
    """
    Decorator to rate limit API endpoints.
    
    Args:
        limit: Maximum number of requests allowed in the period
        period: Time period in seconds
        by: What to rate limit by ('ip' or 'user')
        
    Returns:
        A decorator function
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if by == 'ip':
                identifier = request.remote_addr
            elif by == 'user':
                # Try to get user ID from JWT if available
                try:
                    verify_jwt_in_request(optional=True)
                    identifier = get_jwt_identity() or request.remote_addr
                except:
                    identifier = request.remote_addr
            else:
                identifier = request.remote_addr
            
            # Create a unique key for this endpoint and identifier
            key = f"rate_limit:{request.endpoint}:{identifier}"
            
            # Get current timestamp
            now = datetime.utcnow().timestamp()
            
            # Get or initialize the rate limit data
            if key in _rate_limit_storage:
                timestamps, window_start = _rate_limit_storage[key]
                
                # Remove timestamps outside the current window
                timestamps = [t for t in timestamps if t > now - period]
                
                # Check if we've exceeded the limit
                if len(timestamps) >= limit:
                    # Calculate time until next request is allowed
                    retry_after = int((timestamps[0] + period) - now) + 1
                    response = jsonify({
                        'error': 'Too many requests',
                        'message': f'Rate limit exceeded. Try again in {retry_after} seconds.',
                        'retry_after': retry_after
                    })
                    response.status_code = 429
                    response.headers['Retry-After'] = str(retry_after)
                    return response
                
                # Add current timestamp
                timestamps.append(now)
                _rate_limit_storage[key] = (timestamps, window_start)
            else:
                # Initialize with current timestamp
                _rate_limit_storage[key] = ([now], now)
            
            # Call the original function
            return f(*args, **kwargs)
        return wrapped
    return decorator

def admin_required(f):
    """
    Decorator to require admin privileges.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        
        if not claims.get('is_admin', False):
            raise Forbidden('Admin privileges required')
            
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*required_roles):
    """
    Decorator to require specific user roles.
    
    Args:
        *required_roles: One or more role names that are allowed
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            
            user_roles = set(claims.get('roles', []))
            required = set(required_roles)
            
            if not required.issubset(user_roles):
                raise Forbidden('Insufficient permissions')
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_api_key(user_id: str, name: str = 'default') -> str:
    """
    Generate a new API key for a user.
    
    Args:
        user_id: The ID of the user
        name: A name for the API key
        
    Returns:
        A new API key (only shown once)
    """
    # Generate a random key
    key = f"sk_{secrets.token_urlsafe(32)}"
    
    # Hash the key for storage
    key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
    
    # In a real app, you would store the key_hash in the database
    # along with the user_id and name
    
    return key

def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Verify an API key and return the associated user.
    
    Args:
        api_key: The API key to verify
        
    Returns:
        User information if the key is valid, None otherwise
    """
    if not api_key or not api_key.startswith('sk_'):
        return None
    
    # Hash the provided key
    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    
    # In a real app, you would look up the key_hash in the database
    # and return the associated user
    
    return None

def get_secure_filename(filename: str) -> str:
    """
    Sanitize a filename to be safe for storage.
    
    Args:
        filename: The original filename
        
    Returns:
        A sanitized filename
    """
    # Keep only alphanumeric, dots, underscores, and hyphens
    import re
    filename = re.sub(r'[^\w\-_.]', '_', filename)
    
    # Ensure the filename is not empty
    if not filename:
        filename = 'file'
    
    # Add a timestamp to avoid collisions
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    name, ext = os.path.splitext(filename)
    return f"{name}_{timestamp}{ext}"

def validate_csrf_token(token: str) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: The CSRF token to validate
        
    Returns:
        True if the token is valid, False otherwise
    """
    if not token:
        return False
    
    # In a real app, you would verify the token against the user's session
    # This is a simplified example
    return True

def generate_csrf_token() -> str:
    """
    Generate a CSRF token.
    
    Returns:
        A new CSRF token
    """
    return secrets.token_urlsafe(32)

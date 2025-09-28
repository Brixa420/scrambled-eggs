""
Authentication and authorization utilities.
"""
import os
import jwt
import uuid
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app, g
from flask_login import current_user, login_required as flask_login_required
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Optional, Callable, Dict, Any, List, Union

from ..models import User, db
from .validation import InputValidationError

class AuthError(Exception):
    """Base authentication error."""
    def __init__(self, message: str, status_code: int = 401, payload: Optional[Dict] = None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for JSON response."""
        rv = dict(self.payload or {})
        rv['message'] = self.message
        rv['code'] = self.status_code
        return rv

class AuthenticationManager:
    """Handles user authentication and session management."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app."""
        self.app = app
        app.auth_manager = self
        
        # Register error handler
        @app.errorhandler(AuthError)
        def handle_auth_error(ex):
            response = jsonify(ex.to_dict())
            response.status_code = ex.status_code
            return response
    
    @staticmethod
    def generate_password_hash(password: str) -> str:
        """Generate a secure password hash."""
        # Use a strong hashing method with a high work factor
        return generate_password_hash(
            password,
            method='pbkdf2:sha512',
            salt_length=32
        )
    
    @staticmethod
    def check_password_hash(hashed_password: str, password: str) -> bool:
        """Check if a password matches the hashed password."""
        return check_password_hash(hashed_password, password)
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key."""
        return os.urandom(32).hex()
    
    @staticmethod
    def generate_reset_token(user_id: int, expires_in: int = 3600) -> str:
        """Generate a password reset token."""
        payload = {
            'reset_password': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=expires_in)
        }
        return jwt.encode(
            payload,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    
    @staticmethod
    def verify_reset_token(token: str) -> Optional[User]:
        """Verify a password reset token and return the user if valid."""
        try:
            payload = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            user_id = payload.get('reset_password')
            if not user_id:
                return None
            return User.query.get(user_id)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None
    
    @staticmethod
    def login_user(user: User, remember: bool = False) -> Dict[str, Any]:
        """Log in a user and return an access token."""
        # Generate JWT tokens
        access_token = user.generate_access_token()
        refresh_token = user.generate_refresh_token()
        
        # Update user's last login time
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }

# Decorators for route protection
def login_required(f=None, roles: List[str] = None):
    """Decorator to require authentication and optionally specific roles."""
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            # First, check if the user is authenticated via Flask-Login
            if not current_user.is_authenticated:
                # Check for JWT token if not authenticated via session
                auth_header = request.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                    try:
                        # Verify the token
                        payload = jwt.decode(
                            token,
                            current_app.config['SECRET_KEY'],
                            algorithms=['HS256']
                        )
                        user_id = payload.get('identity')
                        if user_id:
                            user = User.query.get(user_id)
                            if user:
                                # Set the current user
                                g.current_user = user
                                # Check roles if specified
                                if roles and user.role not in roles:
                                    raise AuthError('Insufficient permissions', 403)
                                return func(*args, **kwargs)
                    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                        pass
                
                # If we get here, authentication failed
                raise AuthError('Authentication required', 401)
            
            # Check roles if specified
            if roles and current_user.role not in roles:
                raise AuthError('Insufficient permissions', 403)
                
            return func(*args, **kwargs)
        return decorated_function
    
    # Allow using as @login_required or @login_required(roles=['admin'])
    if f and callable(f):
        return decorator(f)
    return decorator

def api_key_required(f=None, roles: List[str] = None):
    """Decorator to require a valid API key."""
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                raise AuthError('API key required', 401)
            
            # In a real app, you would validate the API key against a database
            # and check the associated user's permissions
            user = User.query.filter_by(api_key=api_key).first()
            if not user or not user.is_active or (roles and user.role not in roles):
                raise AuthError('Invalid or unauthorized API key', 403)
            
            # Store the authenticated user in the request context
            g.current_user = user
            return func(*args, **kwargs)
        return decorated_function
    
    if f and callable(f):
        return decorator(f)
    return decorator

# Rate limiting decorator
class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    def __init__(self, message="Rate limit exceeded", limit=None, remaining=0, reset=None):
        self.message = message
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        super().__init__(self.message)

def rate_limit(limit: int, per: int = 60, key_func=None):
    """Decorator to implement rate limiting."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # In a production app, you would use Redis or Memcached here
            # This is a simplified in-memory implementation
            if not hasattr(rate_limit, 'hits'):
                rate_limit.hits = {}
            
            # Get the key for rate limiting (defaults to remote IP)
            key = key_func() if key_func else request.remote_addr
            now = int(datetime.utcnow().timestamp())
            
            # Initialize or clean up old entries
            if key not in rate_limit.hits:
                rate_limit.hits[key] = {'hits': 0, 'reset': now + per}
            
            # Reset counter if the time window has passed
            if now > rate_limit.hits[key]['reset']:
                rate_limit.hits[key] = {'hits': 0, 'reset': now + per}
            
            # Increment hit count
            rate_limit.hits[key]['hits'] += 1
            
            # Check if rate limit is exceeded
            if rate_limit.hits[key]['hits'] > limit:
                raise RateLimitExceeded(
                    limit=limit,
                    remaining=0,
                    reset=rate_limit.hits[key]['reset']
                )
            
            # Add rate limit headers to the response
            response = f(*args, **kwargs)
            response.headers['X-RateLimit-Limit'] = str(limit)
            response.headers['X-RateLimit-Remaining'] = str(limit - rate_limit.hits[key]['hits'])
            response.headers['X-RateLimit-Reset'] = str(rate_limit.hits[key]['reset'])
            
            return response
        return decorated_function
    return decorator

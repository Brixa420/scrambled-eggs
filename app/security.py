"""
Security and authentication utilities for Scrambled Eggs.
"""
import os
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, request, jsonify, current_app
import jwt
from email_validator import validate_email, EmailNotValidError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# JWT configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# In-memory user store (replace with a database in production)
users = {}

class User:
    """User model for authentication."""
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.is_active = True
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = None
        self.created_at = datetime.utcnow()
    
    def set_password(self, password):
        """Set password hash."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)
    
    def get_auth_token(self):
        """Generate JWT token for the user."""
        payload = {
            'sub': self.username,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRES,
            'type': 'access'
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    
    def get_refresh_token(self):
        """Generate refresh token for the user."""
        payload = {
            'sub': self.username,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + JWT_REFRESH_TOKEN_EXPIRES,
            'type': 'refresh'
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def create_user(username, email, password):
    """Create a new user."""
    if username in users:
        raise ValueError('Username already exists')
    
    try:
        # Validate email
        valid = validate_email(email)
        email = valid.email  # Normalized form of the email
    except EmailNotValidError as e:
        raise ValueError(str(e))
    
    # Password strength validation
    if len(password) < 8:
        raise ValueError('Password must be at least 8 characters long')
    
    user = User(username, email, password)
    users[username] = user
    return user

def get_user(username):
    """Get a user by username."""
    return users.get(username)

def authenticate_user(username, password):
    """Authenticate a user and return the user object if successful."""
    user = get_user(username)
    
    # Check if user exists and is not locked
    if not user or not user.is_active:
        return None
    
    # Check if account is temporarily locked
    if user.locked_until and user.locked_until > datetime.utcnow():
        raise AccountLockedError('Account is temporarily locked. Please try again later.')
    
    # Check password
    if user.check_password(password):
        # Reset failed login attempts on successful login
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        return user
    else:
        # Increment failed login attempts
        user.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts for 15 minutes
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            raise AccountLockedError('Too many failed login attempts. Account locked for 15 minutes.')
        
        return None

def login_required(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for token in Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            # Verify token
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            if payload.get('type') != 'access':
                return jsonify({'error': 'Invalid token type'}), 401
                
            # Add user to request context
            request.current_user = get_user(payload['sub'])
            if not request.current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def refresh_token_required(f):
    """Decorator to require a refresh token for token refresh."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        refresh_token = request.json.get('refresh_token')
        if not refresh_token:
            return jsonify({'error': 'Refresh token is required'}), 400
        
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=['HS256'])
            if payload.get('type') != 'refresh':
                return jsonify({'error': 'Invalid token type'}), 401
                
            user = get_user(payload['sub'])
            if not user:
                return jsonify({'error': 'User not found'}), 401
                
            request.current_user = user
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Refresh token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid refresh token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

class AccountLockedError(Exception):
    """Exception raised when an account is locked."""
    pass

# Create a default admin user on module import
try:
    create_user(
        username='admin',
        email='admin@example.com',
        password=os.getenv('DEFAULT_ADMIN_PASSWORD', 'ChangeMe123!')
    )
    print("Created default admin user")
except ValueError as e:
    print(f"Admin user already exists: {e}")

"""
Authentication routes for user registration and login with enhanced security.
"""

import os
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request

# Rate limiting configuration
from ..security import AccountLockedError, limiter
from ..utils.security import (
    authenticate_user,
    create_user,
    generate_csrf_token,
    get_user,
    hash_password,
    is_secure_password,
)

# JWT configuration
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", os.urandom(32).hex())
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# Failed login attempt tracking
FAILED_LOGIN_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 minutes in seconds


def create_tokens(user_id, username):
    """Generate access and refresh tokens for a user."""
    access_payload = {
        "user_id": str(user_id),
        "username": username,
        "exp": datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRES,
        "iat": datetime.utcnow(),
        "type": "access",
    }

    refresh_payload = {
        "user_id": str(user_id),
        "username": username,
        "exp": datetime.utcnow() + JWT_REFRESH_TOKEN_EXPIRES,
        "iat": datetime.utcnow(),
        "type": "refresh",
    }

    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return access_token, refresh_token


def token_required(f):
    """Decorator to verify JWT tokens."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check for token in Authorization header
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            # Verify token
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            # Check token type
            if data.get("type") != "access":
                return jsonify({"error": "Invalid token type"}), 403

            # Add user info to the request context
            g.user_id = data["user_id"]
            g.username = data["username"]

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated


# Create blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("3 per hour")  # More restrictive rate limiting for registration
def register():
    """Register a new user with enhanced security checks."""
    data = request.get_json()

    # Validate input
    if not data or not all(k in data for k in ["username", "email", "password"]):
        return jsonify({"error": "Missing required fields (username, email, password)"}), 400

    # Validate password strength
    is_secure, message = is_secure_password(data["password"])
    if not is_secure:
        return jsonify({"error": f"Weak password: {message}"}), 400

    # Sanitize inputs
    username = data["username"].strip()
    email = data["email"].strip().lower()

    # Basic input validation
    if not (3 <= len(username) <= 32):
        return jsonify({"error": "Username must be between 3 and 32 characters"}), 400

    if "@" not in email or "." not in email.split("@")[1]:
        return jsonify({"error": "Invalid email address"}), 400

    try:
        # Check if username or email already exists
        if get_user(username=username):
            return jsonify({"error": "Username already exists"}), 409

        if get_user(email=email):
            return jsonify({"error": "Email already registered"}), 409

        # Create new user with hashed password
        hashed_password = hash_password(data["password"])
        user = create_user(username=username, email=email, password=hashed_password)

        # Generate tokens
        access_token, refresh_token = create_tokens(user.id, user.username)

        # Create secure response
        response = jsonify(
            {
                "message": "User registered successfully",
                "user_id": str(user.id),
                "username": user.username,
                "expires_in": int(JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
            }
        )

        # Set secure, HTTP-only cookies
        response.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            secure=not current_app.debug,
            samesite="Strict",
            max_age=int(JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
        )

        response.set_cookie(
            "refresh_token",
            refresh_token,
            httponly=True,
            secure=not current_app.debug,
            samesite="Strict",
            path="/api/auth/refresh",
            max_age=int(JWT_REFRESH_TOKEN_EXPIRES.total_seconds()),
        )

        # Add CSRF token to response
        csrf_token = generate_csrf_token()
        response.set_cookie(
            "csrf_token", csrf_token, secure=not current_app.debug, samesite="Strict"
        )

        # Add CSRF token to response headers for SPA
        response.headers["X-CSRF-Token"] = csrf_token

        return response, 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per hour")
def login():
    """Authenticate a user and return JWT tokens."""
    data = request.get_json()

    # Validate input
    if not all(k in data for k in ["username", "password"]):
        return jsonify({"error": "Missing username or password"}), 400

    try:
        # Authenticate user
        user = authenticate_user(data["username"], data["password"])

        if user:
            # Generate tokens
            access_token = user.get_auth_token()
            refresh_token = user.get_refresh_token()

            return jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": int(JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
                    "token_type": "bearer",
                }
            )
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    except AccountLockedError as e:
        return jsonify({"error": str(e)}), 423  # 423 Locked


@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit("10 per hour")
def refresh():
    """Refresh an access token using a refresh token."""
    data = request.get_json()

    if "refresh_token" not in data:
        return jsonify({"error": "Refresh token is required"}), 400

    try:
        # Verify refresh token
        payload = jwt.decode(data["refresh_token"], JWT_SECRET_KEY, algorithms=["HS256"])

        if payload.get("type") != "refresh":
            return jsonify({"error": "Invalid token type"}), 401

        # Get user
        user = get_user(payload["sub"])
        if not user:
            return jsonify({"error": "User not found"}), 401

        # Generate new access token
        access_token = user.get_auth_token()

        return jsonify(
            {
                "access_token": access_token,
                "expires_in": int(JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
                "token_type": "bearer",
            }
        )

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401


@auth_bp.route("/me", methods=["GET"])
@limiter.limit("60 per hour")
def get_current_user():
    """Get the current authenticated user's information."""
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]

    try:
        # Verify token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "access":
            return jsonify({"error": "Invalid token type"}), 401

        # Get user
        user = get_user(payload["sub"])
        if not user:
            return jsonify({"error": "User not found"}), 401

        return jsonify(
            {
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active,
                "last_login": user.last_login.isoformat() if user.last_login else None,
            }
        )

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

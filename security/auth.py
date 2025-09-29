"""Authentication and authorization module."""

import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, Union

from flask import current_app, g, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    verify_jwt_in_request,
)
from flask_limiter import RateLimitExceeded

from .config import get_config
from .utils import security_utils

# Initialize config
config = get_config()

# JWT Manager
jwt = JWTManager()

# Store failed login attempts (in a real app, use Redis or a database)
failed_login_attempts = {}
account_lockouts = {}


def get_auth_limiter():
    """Get the rate limiter for authentication endpoints."""
    return current_app.extensions.get("limiter")


class AuthManager:
    """Authentication and authorization manager."""

    @staticmethod
    def init_app(app):
        """Initialize the authentication manager with the Flask app."""
        # Configure JWT
        jwt.init_app(app)

        # Register JWT callbacks
        @jwt.user_identity_loader
        def user_identity_lookup(user):
            return user.get("id")

        @jwt.user_lookup_loader
        def user_lookup_callback(_jwt_header, jwt_data):
            from ..models.user import User  # Import here to avoid circular imports

            identity = jwt_data["sub"]
            return User.get_by_id(identity)

        @jwt.token_in_blocklist_loader
        def check_if_token_revoked(jwt_header, jwt_payload):
            from ..models import TokenBlocklist

            jti = jwt_payload["jti"]
            token = TokenBlocklist.query.filter_by(jti=jti).first()
            return token is not None

        @jwt.expired_token_loader
        def expired_token_callback(jwt_header, jwt_payload):
            return (
                jsonify(
                    {"status": "error", "message": "Token has expired", "code": "token_expired"}
                ),
                401,
            )

        @jwt.invalid_token_loader
        def invalid_token_callback(error):
            return (
                jsonify({"status": "error", "message": "Invalid token", "code": "invalid_token"}),
                401,
            )

        @jwt.unauthorized_loader
        def missing_token_callback(error):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Missing authorization token",
                        "code": "authorization_required",
                    }
                ),
                401,
            )

    @staticmethod
    def login_user(user, password: str, request_data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Authenticate a user.

        Args:
            user: The user object
            password: The password to check
            request_data: Additional request data (e.g., MFA token, device info)

        Returns:
            Dict containing tokens and user info if successful, or error details
        """
        if not request_data:
            request_data = {}

        ip_address = request.remote_addr or "unknown"

        # Check if account is locked
        if ip_address in account_lockouts:
            unlock_time = account_lockouts[ip_address]
            if datetime.now(timezone.utc) < unlock_time:
                remaining = (unlock_time - datetime.now(timezone.utc)).seconds // 60
                return {
                    "status": "error",
                    "message": f"Account is locked. Try again in {remaining} minutes.",
                    "code": "account_locked",
                }
            else:
                # Clear the lockout if the time has passed
                account_lockouts.pop(ip_address, None)
                failed_login_attempts.pop(ip_address, 0)

        # Verify password
        if not security_utils.check_password(user.password_hash, password):
            # Increment failed login attempts
            failed_login_attempts[ip_address] = failed_login_attempts.get(ip_address, 0) + 1

            # Check if account should be locked
            if failed_login_attempts[ip_address] >= config.MAX_LOGIN_ATTEMPTS:
                lockout_time = datetime.now(timezone.utc) + timedelta(minutes=config.LOCKOUT_TIME)
                account_lockouts[ip_address] = lockout_time

                # Log the security event
                security_utils.log_security_event(
                    "account_locked",
                    user_id=str(user.id) if user else None,
                    ip_address=ip_address,
                    details=f"Account locked due to {failed_login_attempts[ip_address]} failed login attempts.",
                )

                return {
                    "status": "error",
                    "message": "Too many failed login attempts. Account has been locked.",
                    "code": "account_locked",
                }

            # Log failed login attempt
            security_utils.log_security_event(
                "login_failed",
                user_id=str(user.id) if user else None,
                ip_address=ip_address,
                details=f"Failed login attempt {failed_login_attempts[ip_address]} of {config.MAX_LOGIN_ATTEMPTS}.",
            )

            remaining_attempts = config.MAX_LOGIN_ATTEMPTS - failed_login_attempts[ip_address]
            return {
                "status": "error",
                "message": f"Invalid credentials. {remaining_attempts} attempts remaining.",
                "code": "invalid_credentials",
                "remaining_attempts": remaining_attempts,
            }

        # Check if MFA is required
        if user.mfa_enabled and user.mfa_secret:
            mfa_token = request_data.get("mfa_token")
            if not mfa_token:
                return {
                    "status": "mfa_required",
                    "message": "MFA token required",
                    "code": "mfa_required",
                }

            # Verify MFA token
            if not security_utils.verify_totp(user.mfa_secret, mfa_token):
                security_utils.log_security_event(
                    "mfa_failed",
                    user_id=str(user.id),
                    ip_address=ip_address,
                    details="Invalid MFA token provided.",
                )

                return {
                    "status": "error",
                    "message": "Invalid MFA token",
                    "code": "invalid_mfa_token",
                }

        # Reset failed login attempts on successful login
        if ip_address in failed_login_attempts:
            failed_login_attempts.pop(ip_address, None)

        # Generate tokens
        additional_claims = {
            "roles": [role.name for role in user.roles],
            "permissions": [perm.name for role in user.roles for perm in role.permissions],
        }

        access_token = create_access_token(identity=user, additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=user, additional_claims=additional_claims)

        # Log successful login
        security_utils.log_security_event(
            "login_success",
            user_id=str(user.id),
            ip_address=ip_address,
            details="User logged in successfully.",
        )

        # Update last login time (you would save this to the database)
        user.last_login = datetime.utcnow()
        # user.save()  # Uncomment when you have a user model with save method

        return {
            "status": "success",
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "roles": additional_claims["roles"],
                "permissions": additional_claims["permissions"],
                "mfa_enabled": user.mfa_enabled,
            },
        }

    @staticmethod
    def refresh_access_token() -> Dict[str, Any]:
        """Refresh an access token using a refresh token."""
        current_user = get_jwt_identity()

        # Create new tokens
        access_token = create_access_token(identity=current_user)
        refresh_token = create_refresh_token(identity=current_user)

        return {"status": "success", "access_token": access_token, "refresh_token": refresh_token}

    @staticmethod
    def logout_user() -> Dict[str, str]:
        """Log out the current user by revoking their tokens."""
        jti = get_jwt()["jti"]

        # Add the token to the blocklist
        from ..models import TokenBlocklist

        TokenBlocklist.add_token(jti)

        # Log the logout
        security_utils.log_security_event(
            "logout",
            user_id=str(get_jwt_identity()),
            ip_address=request.remote_addr,
            details="User logged out.",
        )

        return {"status": "success", "message": "Successfully logged out"}


def login_required(f=None, roles=None, permissions=None):
    """
    Decorator to protect routes that require authentication and optionally specific roles or permissions.

    Args:
        f: The view function to decorate
        roles: List of role names required to access the endpoint
        permissions: List of permission names required to access the endpoint
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # This will verify the JWT and set g.current_user
            verify_jwt_in_request()

            # Get the JWT data
            jwt_data = get_jwt()

            # Check roles if specified
            if roles:
                user_roles = set(jwt_data.get("roles", []))
                required_roles = set(roles)

                if not required_roles.intersection(user_roles):
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Insufficient permissions",
                                "code": "insufficient_permissions",
                            }
                        ),
                        403,
                    )

            # Check permissions if specified
            if permissions:
                user_permissions = set(jwt_data.get("permissions", []))
                required_permissions = set(permissions)

                if not required_permissions.issubset(user_permissions):
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Insufficient permissions",
                                "code": "insufficient_permissions",
                            }
                        ),
                        403,
                    )

            # If we get here, the user has the required roles/permissions
            return view_func(*args, **kwargs)

        return wrapper

    # Handle the case where the decorator is used with or without arguments
    if f and callable(f):
        return decorator(f)
    return decorator


def rate_limited(limit: str, key_func=None, error_message: str = "Rate limit exceeded"):
    """
    Decorator to rate limit a route.

    Args:
        limit: Rate limit string (e.g., '100 per day')
        key_func: Function to generate a key for rate limiting (defaults to remote address)
        error_message: Custom error message when rate limit is exceeded
    """
    if not key_func:
        key_func = lambda: request.remote_addr

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # This will raise RateLimitExceeded if the limit is exceeded
                with get_auth_limiter().limit(limit, key_func=key_func):
                    return f(*args, **kwargs)
            except RateLimitExceeded:
                return (
                    jsonify(
                        {"status": "error", "message": error_message, "code": "rate_limit_exceeded"}
                    ),
                    429,
                )

        return wrapper

    return decorator


# Alias for backward compatibility
rate_limit = rate_limited


def exempt_from_rate_limit(f):
    """Decorator to exempt a route from rate limiting."""
    f._rate_limit_exempt = True
    return f


# Create an instance for easy importing
auth_manager = AuthManager()

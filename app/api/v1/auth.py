""
Authentication and user management API endpoints.
"""
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, get_jwt, verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash

from app.models.user import User, UserSession
from app.extensions import db
from app.utils.security import (
    rate_limit, admin_required, generate_verification_token,
    send_verification_email, send_password_reset_email
)

bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')
logger = logging.getLogger(__name__)

@bp.route('/register', methods=['POST'])
@rate_limit(limit=5, period=300)  # 5 requests per 5 minutes
async def register():
    """
    Register a new user account.
    
    Request body (JSON):
    - username: Desired username
    - email: User's email address
    - password: Desired password
    - full_name: User's full name (optional)
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Check if username or email already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"error": "Username already exists"}), 409
            
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Email already registered"}), 409
        
        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            full_name=data.get('full_name'),
            is_active=True,  # Set to False if email verification is required
            is_verified=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Generate verification token
        verification_token = generate_verification_token(user.email)
        
        # Send verification email (in production)
        if current_app.config.get('SEND_EMAILS', False):
            send_verification_email(user.email, verification_token)
        
        # Create access and refresh tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Create session record
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote_addr
        
        session = UserSession(
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=datetime.utcnow() + timedelta(days=30)  # 30-day session
        )
        
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            "message": "User registered successfully. Please check your email to verify your account.",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_verified": user.is_verified,
                "created_at": user.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to register user"}), 500

@bp.route('/login', methods=['POST'])
@rate_limit(limit=5, period=60)  # 5 requests per minute
async def login():
    """
    Authenticate a user and return access and refresh tokens.
    
    Request body (JSON):
    - username: User's username or email
    - password: User's password
    - remember_me: Whether to create a long-lived session (optional)
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({"error": "Username and password are required"}), 400
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == data['username']) | 
            (User.email == data['username'])
        ).first()
        
        # Verify user exists and password is correct
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Check if account is active
        if not user.is_active:
            return jsonify({"error": "Account is deactivated"}), 403
        
        # Check if email is verified (if required)
        if not user.is_verified and current_app.config.get('REQUIRE_EMAIL_VERIFICATION', False):
            return jsonify({"error": "Please verify your email address before logging in"}), 403
        
        # Create access and refresh tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Create session record
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote_addr
        
        # Set session expiration based on remember_me
        expires_days = 30 if data.get('remember_me', False) else 1
        
        session = UserSession(
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=datetime.utcnow() + timedelta(days=expires_days)
        )
        
        # Invalidate old sessions if max sessions exceeded
        max_sessions = current_app.config.get('MAX_USER_SESSIONS', 5)
        active_sessions = UserSession.query.filter_by(
            user_id=user.id,
            is_active=True
        ).order_by(UserSession.created_at.desc()).all()
        
        if len(active_sessions) >= max_sessions:
            # Deactivate oldest sessions
            for old_session in active_sessions[max_sessions-1:]:
                old_session.is_active = False
                old_session.ended_at = datetime.utcnow()
        
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_days * 24 * 3600,  # in seconds
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_verified": user.is_verified,
                "created_at": user.created_at.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Login failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to authenticate user"}), 500

@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@rate_limit(limit=10, period=3600)  # 10 refresh requests per hour
async def refresh():
    """
    Refresh an access token using a refresh token.
    """
    try:
        current_user = get_jwt_identity()
        
        # Get the refresh token from the request
        refresh_token = get_jwt()["jti"]
        
        # Find the active session
        session = UserSession.query.filter_by(
            refresh_token=refresh_token,
            is_active=True
        ).first()
        
        if not session or session.user_id != current_user:
            return jsonify({"error": "Invalid refresh token"}), 401
        
        # Create new access token
        access_token = create_access_token(identity=current_user)
        
        # Update session with new access token
        session.access_token = access_token
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            "access_token": access_token,
            "expires_in": 3600  # 1 hour
        })
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to refresh token"}), 500

@bp.route('/logout', methods=['POST'])
@jwt_required()
async def logout():
    """
    Log out the current user by invalidating the current session.
    """
    try:
        # Get the JWT token from the request
        jti = get_jwt()["jti"]
        
        # Find and deactivate the session
        session = UserSession.query.filter_by(
            access_token=jti,
            is_active=True
        ).first()
        
        if session:
            session.is_active = False
            session.ended_at = datetime.utcnow()
            db.session.commit()
        
        return jsonify({"message": "Successfully logged out"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Logout failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to log out"}), 500

@bp.route('/forgot-password', methods=['POST'])
@rate_limit(limit=5, period=3600)  # 5 requests per hour
async def forgot_password():
    """
    Request a password reset email.
    
    Request body (JSON):
    - email: User's email address
    """
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token (valid for 1 hour)
            reset_token = generate_verification_token(user.email)
            user.reset_token = reset_token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Send password reset email (in production)
            if current_app.config.get('SEND_EMAILS', False):
                send_password_reset_email(user.email, reset_token)
        
        # Always return success to prevent email enumeration
        return jsonify({
            "message": "If an account with that email exists, a password reset link has been sent"
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Password reset request failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to process password reset request"}), 500

@bp.route('/reset-password', methods=['POST'])
@rate_limit(limit=5, period=3600)  # 5 requests per hour
async def reset_password():
    """
    Reset a user's password using a reset token.
    
    Request body (JSON):
    - token: Password reset token
    - new_password: New password
    """
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        if not token or not new_password:
            return jsonify({"error": "Token and new password are required"}), 400
        
        # Find user by reset token
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or user.reset_token_expires < datetime.utcnow():
            return jsonify({"error": "Invalid or expired reset token"}), 400
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expires = None
        
        # Invalidate all active sessions
        UserSession.query.filter_by(user_id=user.id, is_active=True).update({
            'is_active': False,
            'ended_at': datetime.utcnow()
        })
        
        db.session.commit()
        
        return jsonify({"message": "Password has been reset successfully"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Password reset failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to reset password"}), 500

@bp.route('/verify-email/<token>', methods=['GET'])
@rate_limit(limit=10, period=3600)  # 10 requests per hour
async def verify_email(token: str):
    """
    Verify a user's email address using a verification token.
    """
    try:
        # Find user by verification token
        user = User.query.filter_by(verification_token=token).first()
        
        if not user:
            return jsonify({"error": "Invalid or expired verification token"}), 400
        
        if user.is_verified:
            return jsonify({"message": "Email is already verified"})
        
        # Verify the user
        user.is_verified = True
        user.verification_token = None
        user.verified_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({"message": "Email verified successfully"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Email verification failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to verify email"}), 500

@bp.route('/me', methods=['GET'])
@jwt_required()
async def get_current_user():
    """
    Get the current authenticated user's profile.
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch user profile: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch user profile"}), 500

@bp.route('/me', methods=['PUT'])
@jwt_required()
async def update_profile():
    """
    Update the current user's profile.
    
    Request body (JSON):
    - full_name: New full name (optional)
    - email: New email address (optional, requires verification)
    - current_password: Current password (required for sensitive changes)
    - new_password: New password (optional)
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        data = request.get_json() or {}
        
        # Update full name if provided
        if 'full_name' in data:
            user.full_name = data['full_name']
        
        # Handle email change if provided
        if 'email' in data and data['email'] != user.email:
            if not data.get('current_password'):
                return jsonify({"error": "Current password is required to change email"}), 400
                
            if not check_password_hash(user.password_hash, data['current_password']):
                return jsonify({"error": "Incorrect current password"}), 401
            
            # Check if email is already in use
            if User.query.filter(User.email == data['email'], User.id != user.id).first():
                return jsonify({"error": "Email is already in use"}), 409
            
            # Update email and require verification
            user.email = data['email']
            user.is_verified = False
            user.verification_token = generate_verification_token(data['email'])
            
            # Send verification email
            if current_app.config.get('SEND_EMAILS', False):
                send_verification_email(user.email, user.verification_token)
        
        # Handle password change if provided
        if 'new_password' in data:
            if not data.get('current_password'):
                return jsonify({"error": "Current password is required to change password"}), 400
                
            if not check_password_hash(user.password_hash, data['current_password']):
                return jsonify({"error": "Incorrect current password"}), 401
            
            user.password_hash = generate_password_hash(data['new_password'])
            
            # Invalidate all other sessions
            UserSession.query.filter(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.access_token != get_jwt()["jti"]
            ).update({
                'is_active': False,
                'ended_at': datetime.utcnow()
            })
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"message": "Profile updated successfully"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update profile: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to update profile"}), 500

@bp.route('/sessions', methods=['GET'])
@jwt_required()
async def list_sessions():
    """
    Get a list of active sessions for the current user.
    """
    try:
        user_id = get_jwt_identity()
        current_token = get_jwt()["jti"]
        
        sessions = UserSession.query.filter_by(
            user_id=user_id,
            is_active=True
        ).order_by(UserSession.last_activity.desc()).all()
        
        return jsonify([{
            "id": str(session.id),
            "user_agent": session.user_agent,
            "ip_address": session.ip_address,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "is_current": session.access_token == current_token,
            "expires_at": session.expires_at.isoformat() if session.expires_at else None
        } for session in sessions])
        
    except Exception as e:
        logger.error(f"Failed to fetch sessions: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch sessions"}), 500

@bp.route('/sessions/<session_id>', methods=['DELETE'])
@jwt_required()
async def revoke_session(session_id: str):
    """
    Revoke a specific session.
    """
    try:
        user_id = get_jwt_identity()
        current_token = get_jwt()["jti"]
        
        session = UserSession.query.filter_by(
            id=session_id,
            user_id=user_id,
            is_active=True
        ).first()
        
        if not session:
            return jsonify({"error": "Session not found"}), 404
        
        # Don't allow revoking the current session from this endpoint
        if session.access_token == current_token:
            return jsonify({"error": "Cannot revoke current session"}), 400
        
        # Deactivate the session
        session.is_active = False
        session.ended_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({"message": "Session revoked successfully"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to revoke session: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to revoke session"}), 500

@bp.route('/sessions', methods=['DELETE'])
@jwt_required()
async def revoke_all_sessions():
    """
    Revoke all sessions except the current one.
    """
    try:
        user_id = get_jwt_identity()
        current_token = get_jwt()["jti"]
        
        # Revoke all sessions except the current one
        UserSession.query.filter(
            UserSession.user_id == user_id,
            UserSession.access_token != current_token,
            UserSession.is_active == True
        ).update({
            'is_active': False,
            'ended_at': datetime.utcnow()
        })
        
        db.session.commit()
        
        return jsonify({"message": "All other sessions have been revoked"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to revoke sessions: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to revoke sessions"}), 500

"""
Password recovery and reset functionality.
"""
import os
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

from flask import current_app, render_template, url_for
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from ..models import User, PasswordResetToken, db
from ..extensions import mail, limiter
from flask_mail import Message
from ..utils.logging import get_logger

logger = get_logger(__name__)

class PasswordRecoveryManager:
    """Handles password recovery and reset functionality."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app."""
        self.app = app
        self.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        
        # Set default values from app config
        self.password_reset_expiry = app.config.get('PASSWORD_RESET_EXPIRY', 3600)  # 1 hour
        self.max_attempts = app.config.get('PASSWORD_RECOVERY_ATTEMPTS', 5)
        self.lockout_time = app.config.get('PASSWORD_LOCKOUT_TIME', 900)  # 15 minutes
    
    def generate_reset_token(self, user: User) -> str:
        """Generate a secure password reset token for the user."""
        # Create a token that expires in 1 hour by default
        token = self.serializer.dumps(
            {'user_id': user.id, 'email': user.email},
            salt='password-reset-salt'
        )
        
        # Store the token in the database
        reset_token = PasswordResetToken(
            token=token,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(seconds=self.password_reset_expiry)
        )
        
        db.session.add(reset_token)
        db.session.commit()
        
        return token
    
    def validate_reset_token(self, token: str) -> Optional[User]:
        """Validate a password reset token and return the associated user if valid."""
        try:
            # Check if token exists and is not expired
            reset_token = PasswordResetToken.query.filter_by(
                token=token,
                used=False,
                revoked=False
            ).filter(
                PasswordResetToken.expires_at > datetime.utcnow()
            ).first()
            
            if not reset_token:
                return None
                
            # Verify the token signature
            data = self.serializer.loads(
                token,
                salt='password-reset-salt',
                max_age=self.password_reset_expiry
            )
            
            # Get the user
            user = User.query.get(data.get('user_id'))
            if not user or user.email != data.get('email'):
                return None
                
            return user
            
        except (SignatureExpired, BadSignature):
            return None
    
    def send_password_reset_email(self, user: User) -> bool:
        """Send a password reset email to the user."""
        try:
            # Generate a reset token
            token = self.generate_reset_token(user)
            
            # Create reset URL
            reset_url = url_for(
                'auth.reset_password',
                token=token,
                _external=True
            )
            
            # Render email template
            html = render_template(
                'emails/password_reset.html',
                user=user,
                reset_url=reset_url,
                expiry_hours=self.password_reset_expiry // 3600
            )
            
            # Create and send email
            msg = Message(
                subject="Password Reset Request",
                recipients=[user.email],
                html=html,
                sender=current_app.config['MAIL_DEFAULT_SENDER']
            )
            
            mail.send(msg)
            return True
            
        except Exception as e:
            logger.error(f"Error sending password reset email: {e}")
            return False
    
    def reset_password(self, token: str, new_password: str) -> Tuple[bool, Optional[User]]:
        """Reset a user's password using a valid reset token."""
        user = self.validate_reset_token(token)
        if not user:
            return False, None
        
        try:
            # Update user's password
            user.set_password(new_password)
            
            # Mark token as used
            reset_token = PasswordResetToken.query.filter_by(token=token).first()
            if reset_token:
                reset_token.used = True
                reset_token.used_at = datetime.utcnow()
            
            db.session.commit()
            return True, user
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error resetting password: {e}")
            return False, None
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            # Ensure password meets complexity requirements
            if (any(c.islower() for c in password) and 
                any(c.isupper() for c in password) and 
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*" for c in password)):
                return password

# Create a global instance
password_recovery_manager = PasswordRecoveryManager()

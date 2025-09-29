"""
Password reset token model for handling password recovery.
"""
from datetime import datetime
from ..extensions import db

class PasswordResetToken(db.Model):
    """Model for storing password reset tokens."""
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(512), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('password_reset_tokens', lazy=True))
    
    def __init__(self, **kwargs):
        super(PasswordResetToken, self).__init__(**kwargs)
    
    def is_valid(self) -> bool:
        """Check if the token is still valid."""
        now = datetime.utcnow()
        return not (self.used or self.revoked or self.expires_at < now)
    
    def revoke(self) -> None:
        """Revoke this token."""
        self.revoked = True
        db.session.commit()
    
    def mark_as_used(self) -> None:
        """Mark this token as used."""
        self.used = True
        self.used_at = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self) -> str:
        return f"<PasswordResetToken {self.id} for user {self.user_id}>"

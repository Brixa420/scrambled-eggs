from datetime import datetime
from enum import Enum
from app import db

class ContentType(Enum):
    STREAM = 'stream'
    MESSAGE = 'message'
    IMAGE = 'image'
    VIDEO = 'video'

class ModerationStatus(Enum):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    FLAGGED = 'flagged'

class ContentReport(db.Model):
    __tablename__ = 'content_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.String(64), nullable=False)
    content_type = db.Column(db.Enum(ContentType), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum(ModerationStatus), default=ModerationStatus.PENDING)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # AI Analysis Results
    ai_confidence = db.Column(db.Float)
    ai_analysis = db.Column(db.JSON)
    
    # Relationships
    reporter = db.relationship('User', foreign_keys=[reporter_id])
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

class UserVerification(db.Model):
    __tablename__ = 'user_verifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    is_age_verified = db.Column(db.Boolean, default=False)
    verification_method = db.Column(db.String(50))  # 'ai', 'manual', 'third_party'
    verified_at = db.Column(db.DateTime)
    verification_data = db.Column(db.JSON)  # Encrypted data if needed
    
    # For age verification
    verified_age = db.Column(db.Integer)
    verification_expiry = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', back_populates='verification')

# Add verification relationship to User model if it exists
try:
    from app.models.user import User
    User.verification = db.relationship('UserVerification', back_populates='user', uselist=False)
except ImportError:
    pass

from datetime import datetime
from enum import Enum
from app import db

class BanAppealStatus(Enum):
    PENDING = 'pending'
    UNDER_REVIEW = 'under_review'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    FURTHER_REVIEW_NEEDED = 'further_review_needed'

class BanAppeal(db.Model):
    __tablename__ = 'ban_appeals'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ban_reason = db.Column(db.Text, nullable=False)
    appeal_text = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum(BanAppealStatus), default=BanAppealStatus.PENDING)
    ai_analysis = db.Column(db.JSON)  # Store AI analysis results
    reviewer_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id])
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'ban_reason': self.ban_reason,
            'appeal_text': self.appeal_text,
            'status': self.status.value,
            'ai_analysis': self.ai_analysis,
            'reviewer_notes': self.reviewer_notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'reviewed_by': self.reviewed_by
        }

# Add relationship to User model
try:
    from app.models.user import User
    User.ban_appeals = db.relationship('BanAppeal', back_populates='user', foreign_keys=[BanAppeal.user_id])
except ImportError:
    pass

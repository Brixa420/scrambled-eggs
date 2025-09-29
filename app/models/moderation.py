from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean, Enum as SQLEnum, JSON, func, Index
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import expression
from app.db.base_class import Base
from app.models.user import User  # For type hints

class ContentType(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    TEXT = "text"
    STREAM = "stream"
    PROFILE = "profile"
    COMMENT = "comment"

class ViolationType(str, Enum):
    CSAM = "csam"
    BESTIALITY = "bestiality"
    VIOLENCE = "violence"
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    NUDITY = "nudity"
    SELF_HARM = "self_harm"
    SPAM = "spam"
    COPYRIGHT = "copyright"
    OTHER = "other"

class ModerationAction(str, Enum):
    WARNING = "warning"
    TAKEDOWN = "takedown"
    SUSPENSION = "suspension"
    BAN = "ban"
    NO_ACTION = "no_action"
    UNDER_REVIEW = "under_review"

class ModerationStatus(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    RESOLVED = "resolved"
    APPEALED = "appealed"
    REJECTED = "rejected"

class ContentViolation(Base):
    """Tracks violations found in user-uploaded content"""
    __tablename__ = "content_violations"

    id = Column(Integer, primary_key=True, index=True)
    content_id = Column(String(255), nullable=False, index=True)  # Reference to the content in storage
    content_type = Column(SQLEnum(ContentType), nullable=False)
    content_url = Column(String(512), nullable=True)  # URL to the content if available
    content_preview = Column(Text, nullable=True)  # Thumbnail or text preview
    
    # Violation details
    violation_type = Column(SQLEnum(ViolationType), nullable=False)
    confidence_score = Column(Integer, nullable=False)  # 0-100
    detected_objects = Column(JSON, nullable=True)  # Detected objects/entities
    violation_details = Column(JSON, nullable=True)  # Additional details about the violation
    
    # Content owner
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="content_violations")
    
    # Moderation actions
    status = Column(SQLEnum(ModerationStatus), default=ModerationStatus.PENDING, nullable=False)
    action_taken = Column(SQLEnum(ModerationAction), default=ModerationAction.UNDER_REVIEW)
    action_details = Column(Text, nullable=True)
    
    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    reviews = relationship("ModerationReview", back_populates="violation")
    appeals = relationship("ModerationAppeal", back_populates="violation", uselist=False)
    
    def __repr__(self):
        return f"<ContentViolation {self.id} - {self.violation_type} - {self.status}>"


class ModerationReview(Base):
    """Tracks moderator reviews of content violations"""
    __tablename__ = "moderation_reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    violation_id = Column(Integer, ForeignKey("content_violations.id"), nullable=False)
    moderator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Review details
    decision = Column(SQLEnum(ModerationAction), nullable=False)
    notes = Column(Text, nullable=True)
    is_confirmed = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    violation = relationship("ContentViolation", back_populates="reviews")
    moderator = relationship("User")
    
    def __repr__(self):
        return f"<ModerationReview {self.id} - {self.decision} by {self.moderator_id}>"


class ModerationAppeal(Base):
    """Tracks user appeals against moderation actions"""
    __tablename__ = "moderation_appeals"
    
    id = Column(Integer, primary_key=True, index=True)
    violation_id = Column(Integer, ForeignKey("content_violations.id"), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Appeal details
    reason = Column(Text, nullable=False)
    status = Column(SQLEnum(ModerationStatus), default=ModerationStatus.PENDING, nullable=False)
    resolution = Column(Text, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Timestamps
    submitted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    violation = relationship("ContentViolation", back_populates="appeals")
    user = relationship("User", foreign_keys=[user_id])
    resolver = relationship("User", foreign_keys=[resolved_by])
    
    def __repr__(self):
        return f"<ModerationAppeal {self.id} - {self.status}>"


class UserWarning(Base):
    """Tracks warnings issued to users for policy violations"""
    __tablename__ = "user_warnings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    issued_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Warning details
    reason = Column(Text, nullable=False)
    violation_type = Column(SQLEnum(ViolationType), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # None means permanent
    
    # Related content
    content_id = Column(String(255), nullable=True)  # Reference to the content that triggered the warning
    content_type = Column(SQLEnum(ContentType), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="warnings_received")
    issuer = relationship("User", foreign_keys=[issued_by])
    
    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<UserWarning {self.id} - {self.violation_type} - {'Active' if self.is_active else 'Inactive'}>"


class UserSuspension(Base):
    """Tracks user suspensions"""
    __tablename__ = "user_suspensions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True, index=True)
    issued_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Suspension details
    reason = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)  # Required for suspensions
    
    # Related violations
    violation_ids = Column(JSON, default=list, nullable=False)  # List of violation IDs that led to suspension
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    lifted_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="suspensions")
    issuer = relationship("User", foreign_keys=[issued_by])
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    @property
    def days_remaining(self) -> int:
        if not self.is_active or self.is_expired:
            return 0
        return (self.expires_at - datetime.utcnow()).days
    
    def lift(self, lifted_by: int) -> None:
        self.is_active = False
        self.lifted_at = datetime.utcnow()
    
    def __repr__(self):
        status = "Active" if self.is_active else "Lifted"
        return f"<UserSuspension {self.id} - {status} until {self.expires_at}>"


class UserBan(Base):
    """Tracks user bans"""
    __tablename__ = "user_bans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True, index=True)
    issued_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Ban details
    reason = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_permanent = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # None for permanent bans
    
    # Related violations and history
    violation_ids = Column(JSON, default=list, nullable=False)  # List of violation IDs that led to ban
    previous_bans = Column(Integer, default=0, nullable=False)  # Count of previous bans
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    lifted_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="bans")
    issuer = relationship("User", foreign_keys=[issued_by])
    
    @property
    def is_expired(self) -> bool:
        if self.is_permanent or not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def lift(self, lifted_by: int) -> None:
        self.is_active = False
        self.lifted_at = datetime.utcnow()
    
    def __repr__(self):
        ban_type = "Permanent" if self.is_permanent else "Temporary"
        status = "Active" if self.is_active else "Lifted"
        return f"<UserBan {self.id} - {ban_type} - {status}>"


class ContentFilter(Base):
    """User-defined content filters"""
    __tablename__ = "content_filters"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Filter settings
    filter_name = Column(String(100), nullable=False)
    filter_type = Column(String(50), nullable=False)  # e.g., 'keyword', 'hashtag', 'user', 'category'
    filter_value = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="content_filters")
    
    __table_args__ = (
        Index('ix_content_filters_user_type_value', 'user_id', 'filter_type', 'filter_value', unique=True),
    )
    
    def __repr__(self):
        return f"<ContentFilter {self.id} - {self.filter_type}:{self.filter_value}>"


class ModerationSettings(Base):
    """Global moderation settings"""
    __tablename__ = "moderation_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Auto-moderation settings
    auto_mod_enabled = Column(Boolean, default=True, nullable=False)
    auto_remove_csam = Column(Boolean, default=True, nullable=False)
    auto_remove_bestiality = Column(Boolean, default=True, nullable=False)
    auto_remove_violence = Column(Boolean, default=False, nullable=False)
    
    # Warning and suspension thresholds
    warnings_before_suspension = Column(Integer, default=3, nullable=False)
    suspensions_before_ban = Column(Integer, default=3, nullable=False)
    
    # Suspension durations (in days)
    first_suspension_days = Column(Integer, default=1, nullable=False)
    second_suspension_days = Column(Integer, default=7, nullable=False)
    third_suspension_days = Column(Integer, default=30, nullable=False)
    
    # Notification settings
    notify_on_violation = Column(Boolean, default=True, nullable=False)
    notify_on_appeal = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    updated_by_user = relationship("User")
    
    def get_suspension_duration(self, suspension_count: int) -> timedelta:
        """Get suspension duration based on number of previous suspensions"""
        if suspension_count == 1:
            return timedelta(days=self.first_suspension_days)
        elif suspension_count == 2:
            return timedelta(days=self.second_suspension_days)
        else:
            return timedelta(days=self.third_suspension_days)
    
    def __repr__(self):
        return f"<ModerationSettings {self.id}>"

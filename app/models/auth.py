from enum import Enum, IntFlag
from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Table, JSON, Text
from sqlalchemy.orm import relationship
from app.db.base_class import Base

# Association table for user roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow)
)

# Association table for role permissions
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)

class Permission(IntFlag):
    """Bitmask of all possible permissions in the system"""
    # Content permissions
    CREATE_POST = 1
    CREATE_COMMENT = 2
    VOTE = 4
    GIVE_AWARDS = 8
    
    # User permissions
    EDIT_OWN_PROFILE = 16
    DELETE_OWN_CONTENT = 32
    
    # Moderation permissions
    MODERATE_POSTS = 64
    MODERATE_COMMENTS = 128
    MODERATE_USERS = 256
    VIEW_MODERATION_QUEUE = 512
    MANAGE_SUBREDDITS = 1024
    
    # Admin permissions
    MANAGE_ROLES = 2048
    SITE_CONFIG = 4096
    VIEW_AUDIT_LOGS = 8192
    
    # Combine common permission sets
    USER = CREATE_POST | CREATE_COMMENT | VOTE | GIVE_AWARDS | EDIT_OWN_PROFILE | DELETE_OWN_CONTENT
    MODERATOR = (USER | MODERATE_POSTS | MODERATE_COMMENTS | MODERATE_USERS | 
                VIEW_MODERATION_QUEUE | MANAGE_SUBREDDITS)
    ADMIN = MODERATOR | MANAGE_ROLES | SITE_CONFIG | VIEW_AUDIT_LOGS

class Role(Base):
    """User roles with specific permissions"""
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(255))
    is_default = Column(Boolean, default=False, index=True)
    permissions = Column(Integer, default=0, nullable=False)  # Stored as integer bitmask
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')
    
    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0
    
    def has_permission(self, perm):
        """Check if role has a specific permission"""
        return (self.permissions & perm) == perm
    
    def add_permission(self, perm):
        """Add a permission to the role"""
        if not self.has_permission(perm):
            self.permissions += perm
    
    def remove_permission(self, perm):
        """Remove a permission from the role"""
        if self.has_permission(perm):
            self.permissions -= perm
    
    def reset_permissions(self):
        """Remove all permissions"""
        self.permissions = 0

class UserSession(Base):
    """Track user sessions for security and moderation"""
    __tablename__ = 'user_sessions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_id = Column(String(64), unique=True, nullable=False)
    ip_address = Column(String(45))  # IPv6 can be up to 45 chars
    user_agent = Column(String(255))
    device_id = Column(String(64))
    is_active = Column(Boolean, default=True)
    last_activity = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship('User', back_populates='sessions')

class AuditLog(Base):
    """Log of all significant actions for moderation and security"""
    __tablename__ = 'audit_logs'
    
    class ActionType(Enum):
        LOGIN = 'login'
        LOGOUT = 'logout'
        PASSWORD_CHANGE = 'password_change'
        PROFILE_UPDATE = 'profile_update'
        POST_CREATE = 'post_create'
        POST_EDIT = 'post_edit'
        POST_DELETE = 'post_delete'
        COMMENT_CREATE = 'comment_create'
        COMMENT_EDIT = 'comment_edit'
        COMMENT_DELETE = 'comment_delete'
        VOTE = 'vote'
        AWARD_GIVEN = 'award_given'
        USER_WARNED = 'user_warned'
        USER_SUSPENDED = 'user_suspended'
        USER_BANNED = 'user_banned'
        CONTENT_REPORTED = 'content_reported'
        CONTENT_REMOVED = 'content_removed'
        SETTINGS_CHANGED = 'settings_changed'
        ROLE_CHANGED = 'role_changed'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # Null for system actions
    action = Column(String(50), nullable=False)
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship('User', foreign_keys=[user_id])

class Report(Base):
    """User reports for content or other users"""
    __tablename__ = 'reports'
    
    class ReportType(Enum):
        POST = 'post'
        COMMENT = 'comment'
        USER = 'user'
        MESSAGE = 'message'
        OTHER = 'other'
    
    class ReportReason(Enum):
        SPAM = 'spam'
        HARASSMENT = 'harassment'
        HATE_SPEECH = 'hate_speech'
        INAPPROPRIATE = 'inappropriate'
        COPYRIGHT = 'copyright'
        OTHER = 'other'
    
    id = Column(Integer, primary_key=True)
    reporter_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    reported_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    report_type = Column(String(20), nullable=False)  # post, comment, user, etc.
    target_id = Column(Integer, nullable=True)  # ID of the reported item
    reason = Column(String(50), nullable=False)
    details = Column(Text)
    status = Column(String(20), default='pending', index=True)  # pending, in_review, resolved, rejected
    resolved_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    resolved_at = Column(DateTime)
    resolution = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    reporter = relationship('User', foreign_keys=[reporter_id], back_populates='reports_made')
    reported_user = relationship('User', foreign_keys=[reported_user_id], back_populates='reports_received')
    resolver = relationship('User', foreign_keys=[resolved_by])

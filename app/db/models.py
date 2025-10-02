"""
Database models for Brixa application.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Enum as SQLEnum, ForeignKey, Integer, 
    String, Text, JSON, Table, UniqueConstraint, Index, BigInteger, 
    LargeBinary, event, DDL, func, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, scoped_session
from sqlalchemy.sql import expression

from app.core.config import settings
from app.core.security import get_password_hash

# Base class for all models
Base = declarative_base()

# Association tables
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE')),
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE')),
    Column('assigned_at', DateTime, server_default=func.now()),
    Column('assigned_by', Integer, ForeignKey('users.id', ondelete='SET NULL')),
    UniqueConstraint('user_id', 'role_id', name='uq_user_role')
)

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE')),
    Column('permission_id', Integer, ForeignKey('permissions.id', ondelete='CASCADE')),
    Column('granted_at', DateTime, server_default=func.now()),
    Column('granted_by', Integer, ForeignKey('users.id', ondelete='SET NULL')),
    UniqueConstraint('role_id', 'permission_id', name='uq_role_permission')
)

class UserStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    AWAY = "away"
    BUSY = "busy"
    INVISIBLE = "invisible"

class User(Base):
    """User account model."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    display_name = Column(String(64), nullable=True)
    avatar_url = Column(String(512), nullable=True)
    status = Column(SQLEnum(UserStatus), default=UserStatus.OFFLINE, nullable=False)
    bio = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, onupdate=func.now())
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_user_username_ci', func.lower(username), unique=True),
        Index('idx_user_email_ci', func.lower(email), unique=True),
    )
    
    def __repr__(self):
        return f"<User {self.username}>"

class Session(Base):
    """User session model for tracking active sessions."""
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    session_token = Column(String(512), unique=True, index=True, nullable=False)
    refresh_token = Column(String(512), unique=True, index=True, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    last_activity = Column(DateTime, onupdate=func.now(), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    # Indexes
    __table_args__ = (
        Index('idx_session_user', 'user_id', 'is_active'),
    )

class Role(Base):
    """Role model for role-based access control."""
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, onupdate=func.now())
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    
    def __repr__(self):
        return f"<Role {self.name}>"

class Permission(Base):
    """Permission model for fine-grained access control."""
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")
    
    def __repr__(self):
        return f"<Permission {self.name}>"

class PeerNode(Base):
    """P2P network peer node information."""
    __tablename__ = "peer_nodes"
    
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String(64), unique=True, nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)
    address = Column(String(255), nullable=False)  # host:port
    last_seen = Column(DateTime, nullable=False, server_default=func.now())
    is_bootstrap = Column(Boolean, default=False, nullable=False)
    is_banned = Column(Boolean, default=False, nullable=False)
    ban_reason = Column(Text, nullable=True)
    metadata = Column(JSONB, nullable=True, default=dict)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_peer_node_id', 'node_id', unique=True),
        Index('idx_peer_address', 'address'),
        Index('idx_peer_last_seen', 'last_seen'),
    )
    
    def __repr__(self):
        return f"<PeerNode {self.node_id} ({self.address})>"

class Message(Base):
    """Message model for P2P communication."""
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(64), unique=True, nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    recipient_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    recipient_node_id = Column(String(64), nullable=True)  # For P2P messages
    content = Column(Text, nullable=False)
    content_type = Column(String(50), default="text/plain", nullable=False)
    is_encrypted = Column(Boolean, default=True, nullable=False)
    metadata = Column(JSONB, nullable=True, default=dict)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    delivered_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_message_sender', 'sender_id', 'created_at'),
        Index('idx_message_recipient', 'recipient_id', 'created_at'),
        Index('idx_message_node', 'recipient_node_id', 'created_at'),
    )
    
    def __repr__(self):
        return f"<Message {self.id} from {self.sender_id} to {self.recipient_id or self.recipient_node_id}>"

class CacheEntry(Base):
    """Cache entry model for distributed caching."""
    __tablename__ = "cache_entries"
    
    key = Column(String(255), primary_key=True)
    value = Column(JSONB, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index('idx_cache_expires', 'expires_at'),
    )
    
    def __repr__(self):
        return f"<CacheEntry {self.key}>"

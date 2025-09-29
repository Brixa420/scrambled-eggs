"""
Server models for Discord-like server functionality.
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import relationship

from app.db.base import Base


class ServerVisibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    UNLISTED = "unlisted"


class Server(Base):
    """Server model representing a Discord-like server."""

    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    icon_url = Column(String(255), nullable=True)
    banner_url = Column(String(255), nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    visibility = Column(String(20), default=ServerVisibility.PRIVATE, nullable=False)
    invite_code = Column(String(10), unique=True, nullable=True)
    region = Column(String(50), default="us-east", nullable=False)
    max_members = Column(Integer, default=100, nullable=False)
    features = Column(JSONB, default=dict, nullable=False)  # Custom features
    is_nsfw = Column(Boolean, default=False, nullable=False)
    verification_level = Column(Integer, default=0, nullable=False)  # 0-4
    default_notifications = Column(Integer, default=1, nullable=False)  # 0=all, 1=mentions
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    owner = relationship("User", back_populates="owned_servers")
    members = relationship("ServerMember", back_populates="server", cascade="all, delete-orphan")
    channels = relationship("Channel", back_populates="server", cascade="all, delete-orphan")
    roles = relationship("ServerRole", back_populates="server", cascade="all, delete-orphan")
    invites = relationship("ServerInvite", back_populates="server", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon_url": self.icon_url,
            "banner_url": self.banner_url,
            "owner_id": self.owner_id,
            "visibility": self.visibility,
            "member_count": len(self.members),
            "features": self.features,
            "is_nsfw": self.is_nsfw,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class ServerMember(Base):
    """Association table for server members."""

    __tablename__ = "server_members"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    nickname = Column(String(32), nullable=True)
    role_ids = Column(ARRAY(Integer), default=[], nullable=False)
    joined_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_owner = Column(Boolean, default=False, nullable=False)

    # Relationships
    user = relationship("User", back_populates="server_memberships")
    server = relationship("Server", back_populates="members")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "server_id": self.server_id,
            "nickname": self.nickname,
            "role_ids": self.role_ids,
            "is_owner": self.is_owner,
            "joined_at": self.joined_at.isoformat(),
        }


class ServerRole(Base):
    """Roles within a server."""

    __tablename__ = "server_roles"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    name = Column(String(100), nullable=False)
    color = Column(String(7), default="#99aab5", nullable=False)  # Hex color
    permissions = Column(JSONB, default=dict, nullable=False)
    position = Column(Integer, default=0, nullable=False)
    is_mentionable = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="roles")

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "color": self.color,
            "permissions": self.permissions,
            "position": self.position,
            "is_mentionable": self.is_mentionable,
            "created_at": self.created_at.isoformat(),
        }


class ServerInvite(Base):
    """Server invite codes."""

    __tablename__ = "server_invites"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(10), unique=True, nullable=False)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    inviter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    max_uses = Column(Integer, nullable=True)
    uses = Column(Integer, default=0, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="invites")
    inviter = relationship("User")

    def is_valid(self):
        if self.max_uses is not None and self.uses >= self.max_uses:
            return False
        if self.expires_at is not None and datetime.utcnow() > self.expires_at:
            return False
        return True

    def to_dict(self):
        return {
            "code": self.code,
            "server_id": self.server_id,
            "inviter_id": self.inviter_id,
            "max_uses": self.max_uses,
            "uses": self.uses,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }

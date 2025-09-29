"""
Server settings and customization models.
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db.base import Base


class ServerRegion(str, Enum):
    US_EAST = "us-east"
    US_WEST = "us-west"
    EU_WEST = "eu-west"
    EU_EAST = "eu-east"
    ASIA = "asia"
    AUSTRALIA = "australia"
    SOUTH_AMERICA = "south-america"


class ServerVerificationLevel(int, Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4


class ServerNotificationSetting(str, Enum):
    ALL_MESSAGES = "all"
    ONLY_MENTIONS = "mentions"
    MUTE = "mute"


class ServerSettings(Base):
    """Server-specific settings and customizations."""

    __tablename__ = "server_settings"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), unique=True, nullable=False)

    # General Settings
    region = Column(String(50), default=ServerRegion.US_EAST, nullable=False)
    default_channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)
    system_channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)
    rules_channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)

    # Moderation
    verification_level = Column(Integer, default=ServerVerificationLevel.NONE, nullable=False)
    explicit_content_filter = Column(
        Integer, default=0, nullable=False
    )  # 0=disabled, 1=members without roles, 2=all members
    default_message_notifications = Column(Integer, default=1, nullable=False)  # 0=all, 1=mentions

    # Features
    features = Column(JSONB, default=dict, nullable=False)  # Enabled/disabled features
    custom_emojis = Column(JSONB, default=list, nullable=False)  # List of custom emojis
    stickers = Column(JSONB, default=list, nullable=False)  # List of custom stickers

    # Customization
    welcome_message = Column(Text, nullable=True)
    welcome_channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)
    goodbye_message = Column(Text, nullable=True)
    goodbye_channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)

    # Auto-moderation
    auto_moderation = Column(JSONB, default=dict, nullable=False)

    # Integrations
    webhooks = Column(JSONB, default=list, nullable=False)
    integrations = Column(JSONB, default=list, nullable=False)

    # Audit Log
    audit_log_retention_days = Column(Integer, default=90, nullable=False)

    # System Messages
    system_message_channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)

    # Relationships
    server = relationship("Server", back_populates="settings", uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "region": self.region,
            "default_channel_id": self.default_channel_id,
            "system_channel_id": self.system_channel_id,
            "rules_channel_id": self.rules_channel_id,
            "verification_level": self.verification_level,
            "explicit_content_filter": self.explicit_content_filter,
            "default_message_notifications": self.default_message_notifications,
            "features": self.features,
            "custom_emojis": self.custom_emojis,
            "stickers": self.stickers,
            "welcome_message": self.welcome_message,
            "welcome_channel_id": self.welcome_channel_id,
            "goodbye_message": self.goodbye_message,
            "goodbye_channel_id": self.goodbye_channel_id,
            "auto_moderation": self.auto_moderation,
            "audit_log_retention_days": self.audit_log_retention_days,
            "system_message_channel_id": self.system_message_channel_id,
        }


class ServerWidget(Base):
    """Server widget settings for embedding."""

    __tablename__ = "server_widgets"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), unique=True, nullable=False)
    enabled = Column(Boolean, default=False, nullable=False)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=True)
    widget_style = Column(
        String(50), default="default", nullable=False
    )  # e.g., "banner", "compact", "full"
    show_members = Column(Boolean, default=True, nullable=False)
    show_presence = Column(Boolean, default=True, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="widget", uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "enabled": self.enabled,
            "channel_id": self.channel_id,
            "widget_style": self.widget_style,
            "show_members": self.show_members,
            "show_presence": self.show_presence,
        }


class ServerBan(Base):
    """Server bans."""

    __tablename__ = "server_bans"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    moderator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reason = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="bans")
    user = relationship("User", foreign_keys=[user_id])
    moderator = relationship("User", foreign_keys=[moderator_id])

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "user_id": self.user_id,
            "moderator_id": self.moderator_id,
            "reason": self.reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }


class AuditLog(Base):
    """Audit log for server actions."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action_type = Column(String(50), nullable=False)  # e.g., "member_ban", "message_delete"
    target_id = Column(Integer, nullable=True)  # ID of the affected entity
    target_type = Column(String(50), nullable=True)  # Type of the affected entity
    changes = Column(JSONB, default=dict, nullable=False)  # Before/after changes
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    server = relationship("Server", back_populates="audit_logs")
    user = relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "user_id": self.user_id,
            "action_type": self.action_type,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "changes": self.changes,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
        }

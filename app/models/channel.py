"""
Channel and message models for Discord-like communication.
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import relationship

from app.db.base import Base


class ChannelType(str, Enum):
    TEXT = "text"
    VOICE = "voice"
    ANNOUNCEMENT = "announcement"
    FORUM = "forum"
    MEDIA = "media"


class Channel(Base):
    """Channel model for server communication."""

    __tablename__ = "channels"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    type = Column(SQLEnum(ChannelType), default=ChannelType.TEXT, nullable=False)
    position = Column(Integer, default=0, nullable=False)
    is_nsfw = Column(Boolean, default=False, nullable=False)
    is_private = Column(Boolean, default=False, nullable=False)
    allowed_roles = Column(
        ARRAY(Integer), default=[], nullable=True
    )  # Empty array means all roles allowed
    topic = Column(Text, nullable=True)
    rate_limit = Column(Integer, default=0, nullable=False)  # In seconds
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="channels")
    messages = relationship("Message", back_populates="channel", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "server_id": self.server_id,
            "name": self.name,
            "description": self.description,
            "type": self.type.value,
            "position": self.position,
            "is_nsfw": self.is_nsfw,
            "is_private": self.is_private,
            "allowed_roles": self.allowed_roles or [],
            "topic": self.topic,
            "rate_limit": self.rate_limit,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class MessageType(str, Enum):
    DEFAULT = "default"
    SYSTEM = "system"
    GUILD_MEMBER_JOIN = "guild_member_join"
    USER_PREMIUM_GUILD_SUBSCRIPTION = "user_premium_guild_subscription"
    CHANNEL_NAME_CHANGE = "channel_name_change"
    CHANNEL_ICON_CHANGE = "channel_icon_change"
    CHANNEL_PINNED_MESSAGE = "channel_pinned_message"
    USER_JOIN = "user_join"
    GUILD_BOOST = "guild_boost"
    THREAD_CREATED = "thread_created"
    REPLY = "reply"
    CHAT_INPUT_COMMAND = "chat_input_command"


class Message(Base):
    """Message model for channel communication."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    type = Column(SQLEnum(MessageType), default=MessageType.DEFAULT, nullable=False)
    is_pinned = Column(Boolean, default=False, nullable=False)
    is_edited = Column(Boolean, default=False, nullable=False)
    mentions_everyone = Column(Boolean, default=False, nullable=False)
    mention_roles = Column(ARRAY(Integer), default=[], nullable=False)
    mention_channels = Column(ARRAY(Integer), default=[], nullable=False)
    attachments = Column(JSONB, default=[], nullable=False)
    embeds = Column(JSONB, default=[], nullable=False)
    reactions = Column(JSONB, default=[], nullable=False)
    message_reference = Column(JSONB, nullable=True)  # For replies/threads
    flags = Column(Integer, default=0, nullable=False)  # Bitwise flags
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    channel = relationship("Channel", back_populates="messages")
    author = relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "channel_id": self.channel_id,
            "author": self.author.to_public_dict(),
            "content": self.content,
            "type": self.type.value,
            "is_pinned": self.is_pinned,
            "is_edited": self.is_edited,
            "mentions_everyone": self.mentions_everyone,
            "mention_roles": self.mention_roles,
            "mention_channels": self.mention_channels,
            "attachments": self.attachments,
            "embeds": self.embeds,
            "reactions": self.reactions,
            "message_reference": self.message_reference,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class Thread(Base):
    """Thread model for organizing messages."""

    __tablename__ = "threads"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False)
    parent_message_id = Column(Integer, ForeignKey("messages.id"), nullable=True)
    name = Column(String(100), nullable=False)
    is_archived = Column(Boolean, default=False, nullable=False)
    is_locked = Column(Boolean, default=False, nullable=False)
    auto_archive_duration = Column(Integer, default=1440, nullable=False)  # In minutes
    member_count = Column(Integer, default=0, nullable=False)
    message_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    channel = relationship("Channel")
    parent_message = relationship("Message")

    def to_dict(self):
        return {
            "id": self.id,
            "channel_id": self.channel_id,
            "parent_message_id": self.parent_message_id,
            "name": self.name,
            "is_archived": self.is_archived,
            "is_locked": self.is_locked,
            "auto_archive_duration": self.auto_archive_duration,
            "member_count": self.member_count,
            "message_count": self.message_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

"""
Pydantic models for channel-related API endpoints.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class ChannelType(str, Enum):
    TEXT = "text"
    VOICE = "voice"
    ANNOUNCEMENT = "announcement"
    FORUM = "forum"
    MEDIA = "media"


class ChannelCreate(BaseModel):
    """Schema for creating a new channel."""

    name: str = Field(..., min_length=1, max_length=100, regex=r"^[a-z0-9-]+$")
    type: ChannelType = ChannelType.TEXT
    description: Optional[str] = Field(None, max_length=1024)
    is_private: bool = False
    allowed_roles: List[int] = Field(default_factory=list)
    topic: Optional[str] = Field(None, max_length=1024)
    rate_limit: int = Field(0, ge=0, le=21600)  # 6 hours max
    is_nsfw: bool = False

    @validator("name")
    def validate_name(cls, v):
        if "  " in v:
            raise ValueError("Channel name cannot contain multiple spaces in a row")
        if v.lower() in ["general", "welcome", "rules", "announcements"]:
            raise ValueError("Channel name is reserved")
        return v.lower().replace(" ", "-")

    class Config:
        schema_extra = {
            "example": {
                "name": "general",
                "type": "text",
                "description": "General discussion",
                "is_private": False,
                "topic": "Talk about anything here",
            }
        }


class ChannelUpdate(BaseModel):
    """Schema for updating channel details."""

    name: Optional[str] = Field(None, min_length=1, max_length=100, regex=r"^[a-z0-9-]+$")
    description: Optional[str] = Field(None, max_length=1024)
    topic: Optional[str] = Field(None, max_length=1024)
    is_private: Optional[bool] = None
    allowed_roles: Optional[List[int]] = None
    rate_limit: Optional[int] = Field(None, ge=0, le=21600)
    is_nsfw: Optional[bool] = None

    class Config:
        schema_extra = {
            "example": {
                "name": "general-chat",
                "description": "General discussion channel",
                "topic": "Welcome to our general chat!",
            }
        }


class ChannelResponse(BaseModel):
    """Response model for channel data."""

    id: int
    server_id: int
    name: str
    description: Optional[str]
    type: ChannelType
    position: int
    is_private: bool
    is_nsfw: bool
    allowed_roles: List[int]
    topic: Optional[str]
    rate_limit: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "server_id": 1,
                "name": "general",
                "type": "text",
                "position": 0,
                "is_private": False,
                "is_nsfw": False,
                "allowed_roles": [],
                "topic": "Welcome to our general chat!",
                "rate_limit": 0,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            }
        }


class MessageType(str, Enum):
    DEFAULT = "default"
    SYSTEM = "system"
    GUILD_MEMBER_JOIN = "guild_member_join"
    REPLY = "reply"
    THREAD_CREATED = "thread_created"
    THREAD_REPLY = "thread_reply"


class MessageCreate(BaseModel):
    """Schema for creating a new message."""

    content: str = Field(..., min_length=1, max_length=4000)
    reply_to_message_id: Optional[int] = None
    nonce: Optional[str] = None  # For client-side deduplication

    class Config:
        schema_extra = {"example": {"content": "Hello, world!", "reply_to_message_id": 123}}


class MessageUpdate(BaseModel):
    """Schema for updating a message."""

    content: str = Field(..., min_length=1, max_length=4000)

    class Config:
        schema_extra = {"example": {"content": "Updated message content"}}


class AttachmentResponse(BaseModel):
    """Response model for message attachments."""

    id: int
    filename: str
    url: str
    proxy_url: str
    size: int
    width: Optional[int]
    height: Optional[int]
    content_type: Optional[str]

    class Config:
        orm_mode = True


class MessageResponse(BaseModel):
    """Response model for message data."""

    id: int
    channel_id: int
    author_id: int
    content: str
    type: MessageType
    is_pinned: bool
    is_edited: bool
    mentions_everyone: bool
    mention_roles: List[int]
    mention_channels: List[int]
    attachments: List[AttachmentResponse]
    embeds: List[Dict[str, Any]]
    reactions: List[Dict[str, Any]]
    message_reference: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "channel_id": 1,
                "author_id": 1,
                "content": "Hello, world!",
                "type": "default",
                "is_pinned": False,
                "is_edited": False,
                "mentions_everyone": False,
                "mention_roles": [],
                "mention_channels": [],
                "attachments": [],
                "embeds": [],
                "reactions": [],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            }
        }


class ThreadCreate(BaseModel):
    """Schema for creating a new thread."""

    name: str = Field(..., min_length=1, max_length=100)
    auto_archive_duration: int = Field(1440, ge=60, le=10080)  # 1 hour to 7 days in minutes

    class Config:
        schema_extra = {
            "example": {"name": "Off-topic discussion", "auto_archive_duration": 1440}  # 1 day
        }


class ThreadResponse(BaseModel):
    """Response model for thread data."""

    id: int
    channel_id: int
    parent_message_id: Optional[int]
    name: str
    is_archived: bool
    is_locked: bool
    auto_archive_duration: int
    member_count: int
    message_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

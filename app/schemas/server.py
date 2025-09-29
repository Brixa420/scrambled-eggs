"""
Pydantic models for server-related API endpoints.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ServerVisibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    UNLISTED = "unlisted"


class ServerCreate(BaseModel):
    """Schema for creating a new server."""

    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    visibility: ServerVisibility = ServerVisibility.PRIVATE
    icon_url: Optional[HttpUrl] = None
    banner_url: Optional[HttpUrl] = None
    is_nsfw: bool = False
    region: str = "us-east"

    class Config:
        schema_extra = {
            "example": {
                "name": "My Awesome Server",
                "description": "A place for awesome people",
                "visibility": "private",
                "is_nsfw": False,
            }
        }


class ServerUpdate(BaseModel):
    """Schema for updating server details."""

    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    visibility: Optional[ServerVisibility] = None
    icon_url: Optional[HttpUrl] = None
    banner_url: Optional[HttpUrl] = None
    is_nsfw: Optional[bool] = None
    region: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {"name": "Updated Server Name", "description": "Updated description"}
        }


class ServerResponse(BaseModel):
    """Response model for server data."""

    id: int
    name: str
    description: Optional[str]
    icon_url: Optional[str]
    banner_url: Optional[str]
    owner_id: int
    visibility: ServerVisibility
    is_nsfw: bool
    region: str
    member_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "name": "My Awesome Server",
                "description": "A place for awesome people",
                "owner_id": 1,
                "visibility": "private",
                "is_nsfw": False,
                "region": "us-east",
                "member_count": 1,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            }
        }


class ServerMemberResponse(BaseModel):
    """Response model for server member data."""

    id: int
    user_id: int
    server_id: int
    nickname: Optional[str]
    role_ids: List[int]
    is_owner: bool
    joined_at: datetime

    class Config:
        orm_mode = True


class ServerRoleCreate(BaseModel):
    """Schema for creating a server role."""

    name: str = Field(..., min_length=1, max_length=100)
    color: str = Field("#99aab5", regex=r"^#(?:[0-9a-fA-F]{3}){1,2}$")
    permissions: Dict[str, bool] = Field(default_factory=dict)
    is_mentionable: bool = False

    class Config:
        schema_extra = {
            "example": {
                "name": "Moderator",
                "color": "#5865F2",
                "permissions": {"manage_messages": True, "kick_members": True},
                "is_mentionable": True,
            }
        }


class ServerRoleResponse(ServerRoleCreate):
    """Response model for server role data."""

    id: int
    server_id: int
    position: int
    created_at: datetime

    class Config:
        orm_mode = True


class ServerInviteCreate(BaseModel):
    """Schema for creating a server invite."""

    max_uses: Optional[int] = Field(None, ge=1, le=100)
    expires_in: Optional[int] = Field(None, ge=300, le=604800)  # 5 minutes to 7 days in seconds

    class Config:
        schema_extra = {"example": {"max_uses": 10, "expires_in": 86400}}  # 1 day


class ServerInviteResponse(BaseModel):
    """Response model for server invite data."""

    code: str
    server_id: int
    inviter_id: int
    max_uses: Optional[int]
    uses: int
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "code": "abc123",
                "server_id": 1,
                "inviter_id": 1,
                "max_uses": 10,
                "uses": 0,
                "expires_at": "2023-01-08T00:00:00Z",
                "created_at": "2023-01-01T00:00:00Z",
            }
        }


class ServerStatsResponse(BaseModel):
    """Response model for server statistics."""

    total_members: int
    online_members: int
    total_channels: int
    total_roles: int
    created_at: datetime

    class Config:
        orm_mode = True

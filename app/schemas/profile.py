"""
Pydantic models for user profiles.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, validator


class ProfileBase(BaseModel):
    """Base profile schema."""

    display_name: Optional[str] = None
    bio: Optional[str] = None
    status: Optional[str] = None
    custom_status: Optional[str] = None
    theme: Optional[str] = None
    locale: Optional[str] = None
    timezone: Optional[str] = None


class ProfileCreate(ProfileBase):
    """Schema for creating a profile."""


class ProfileUpdate(ProfileBase):
    """Schema for updating a profile."""

    email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None

    @validator("new_password")
    def password_complexity(cls, v, values):
        if v is None:
            return v
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v) or not any(c.islower() for c in v):
            raise ValueError("Password must contain both uppercase and lowercase letters")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class ProfileResponse(ProfileBase):
    """Schema for profile response."""

    id: int
    username: str
    email: Optional[str] = None
    discriminator: str
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    is_verified: bool = False
    is_mfa_enabled: bool = False
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class AvatarUploadResponse(BaseModel):
    """Response model for avatar upload."""

    url: str
    message: str = "Avatar uploaded successfully"


class BannerUploadResponse(BaseModel):
    """Response model for banner upload."""

    url: str
    message: str = "Banner uploaded successfully"

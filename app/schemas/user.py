from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, validator


class UserBase(BaseModel):
    """Base user schema with shared attributes."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, regex="^[a-zA-Z0-9_]+$")


class UserCreate(UserBase):
    """Schema for creating a new user."""

    password: str = Field(..., min_length=8, max_length=128)

    @validator("password")
    def password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isdigit() for char in v):
            raise ValueError("Password must contain at least one number")
        if not any(char.isupper() for char in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(char in "!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?" for char in v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserUpdate(BaseModel):
    """Schema for updating user information."""

    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=64, regex="^[a-zA-Z0-9_]+$")
    password: Optional[str] = Field(None, min_length=8, max_length=128)


class UserInDBBase(UserBase):
    """Base schema for user stored in the database."""

    id: int
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        orm_mode = True


class User(UserInDBBase):
    """Schema for returning user data (without sensitive info)."""


class UserInDB(UserInDBBase):
    """Schema for user data in the database."""

    hashed_password: str


class UserLogin(BaseModel):
    """Schema for user login."""

    email: EmailStr
    password: str


class Token(BaseModel):
    """Schema for JWT token."""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Schema for token data."""

    username: Optional[str] = None

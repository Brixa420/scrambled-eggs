from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field, validator, conint


class UserBase(BaseModel):
    """Base user schema with shared attributes."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, regex="^[a-zA-Z0-9_]+$")
    role_id: Optional[int] = None


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


class RoleBase(BaseModel):
    """Base role schema."""
    id: int
    name: str
    description: Optional[str] = None
    is_default: bool = False

    class Config:
        orm_mode = True

class PermissionBase(BaseModel):
    """Base permission schema."""
    id: int
    name: str
    description: Optional[str] = None
    resource: str
    action: str

    class Config:
        orm_mode = True

class Role(RoleBase):
    """Role schema with permissions."""
    permissions: List[PermissionBase] = []

class UserInDBBase(UserBase):
    """Base schema for user stored in the database."""

    id: int
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    role: Optional[Role] = None

    class Config:
        orm_mode = True


    """Schema for returning user data (without sensitive info)."""


class UserInDB(UserInDBBase):
    """Schema for user data in the database."""
    hashed_password: str


class UserLogin(BaseModel):
    """Schema for user login."""

    email: EmailStr
    password: str


class UserRoleUpdate(BaseModel):
    """Schema for updating a user's role."""
    role_id: int = Field(..., gt=0, description="ID of the role to assign to the user")


class Token(BaseModel):
    """Schema for JWT token."""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Schema for token data."""

    username: Optional[str] = None
    user_id: Optional[int] = None
    is_superuser: bool = False

"""
Pydantic models for file sharing API endpoints.
"""

import re
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, Field, validator


class FileType(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    OTHER = "other"


class FileCreate(BaseModel):
    """Schema for uploading a new file."""

    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str = Field(..., min_length=1, max_length=127)
    size: int = Field(..., gt=0)
    is_public: bool = False
    max_downloads: Optional[int] = Field(None, ge=1)
    expires_in: Optional[int] = Field(None, ge=300, le=2592000)  # 5 minutes to 30 days in seconds

    @validator("filename")
    def validate_filename(cls, v):
        if not re.match(r"^[\w,\s-]+\.[A-Za-z]{2,10}$", v):
            raise ValueError("Invalid filename format")
        return v

    class Config:
        schema_extra = {
            "example": {
                "filename": "example.jpg",
                "content_type": "image/jpeg",
                "size": 1024,
                "is_public": True,
                "max_downloads": 10,
                "expires_in": 86400,  # 1 day
            }
        }


class FileResponse(BaseModel):
    """Response model for file data."""

    id: str
    original_filename: str
    url: str
    size: int
    mime_type: str
    is_public: bool
    download_count: int
    max_downloads: Optional[int]
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "original_filename": "example.jpg",
                "url": "https://example.com/files/550e8400-e29b-41d4-a716-446655440000",
                "size": 1024,
                "mime_type": "image/jpeg",
                "is_public": True,
                "download_count": 0,
                "max_downloads": 10,
                "expires_at": "2023-01-08T00:00:00Z",
                "created_at": "2023-01-01T00:00:00Z",
            }
        }


class FileShareCreate(BaseModel):
    """Schema for sharing a file with another user."""

    user_id: int
    can_edit: bool = False
    expires_in: Optional[int] = Field(None, ge=300, le=2592000)  # 5 minutes to 30 days in seconds

    class Config:
        schema_extra = {"example": {"user_id": 2, "can_edit": True, "expires_in": 86400}}  # 1 day


class FileShareResponse(BaseModel):
    """Response model for file share data."""

    id: str
    file_id: str
    shared_by: int
    shared_with: int
    can_edit: bool
    created_at: datetime
    expires_at: Optional[datetime]

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "660e8400-e29b-41d4-a716-446655440001",
                "file_id": "550e8400-e29b-41d4-a716-446655440000",
                "shared_by": 1,
                "shared_with": 2,
                "can_edit": True,
                "created_at": "2023-01-01T00:00:00Z",
                "expires_at": "2023-01-08T00:00:00Z",
            }
        }


class FileAccessLogResponse(BaseModel):
    """Response model for file access logs."""

    id: int
    file_id: str
    user_id: int
    action: str
    ip_address: str
    user_agent: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


class FileUploadURLResponse(BaseModel):
    """Response model for file upload URL generation."""

    upload_url: str
    file_id: str
    fields: Dict[str, str]
    expires_at: datetime

    class Config:
        schema_extra = {
            "example": {
                "upload_url": "https://storage.example.com/upload",
                "file_id": "550e8400-e29b-41d4-a716-446655440000",
                "fields": {
                    "key": "uploads/550e8400-e29b-41d4-a716-446655440000",
                    "Content-Type": "image/jpeg",
                    "x-amz-credential": "...",
                    "x-amz-algorithm": "AWS4-HMAC-SHA256",
                    "x-amz-date": "20230101T000000Z",
                    "x-amz-signature": "...",
                    "policy": "...",
                },
                "expires_at": "2023-01-01T01:00:00Z",
            }
        }


class FileStorageQuota(BaseModel):
    """Response model for user storage quota information."""

    used_bytes: int
    total_bytes: int
    file_count: int

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "used_bytes": 1073741824,  # 1 GB
                "total_bytes": 5368709120,  # 5 GB
                "file_count": 42,
            }
        }

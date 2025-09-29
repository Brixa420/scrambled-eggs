"""
Contact model for storing user contacts.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class ContactStatus(str, Enum):
    """Status of a contact."""

    ONLINE = "online"
    OFFLINE = "offline"
    AWAY = "away"
    BUSY = "busy"


class Contact(BaseModel):
    """Contact model."""

    id: str = Field(..., description="Unique identifier for the contact")
    user_id: str = Field(..., description="ID of the user who owns this contact")
    name: str = Field(..., description="Display name of the contact")
    email: Optional[EmailStr] = Field(None, description="Email address of the contact")
    public_key: str = Field(..., description="Public key for end-to-end encryption")
    status: ContactStatus = ContactStatus.OFFLINE
    last_seen: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_favorite: bool = False
    metadata: dict = Field(default_factory=dict, description="Additional metadata")

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }
        use_enum_values = True

    def to_dict(self) -> dict:
        """Convert contact to dictionary."""
        return self.dict()

    @classmethod
    def from_dict(cls, data: dict) -> "Contact":
        """Create contact from dictionary."""
        return cls(**data)

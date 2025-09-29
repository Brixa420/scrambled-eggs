"""
Pydantic models for chat functionality.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MessageBase(BaseModel):
    """Base message schema."""

    content: str = Field(..., max_length=2000)
    room_id: str
    sender_id: Optional[str] = None


class MessageCreate(MessageBase):
    """Schema for creating a new message."""


class MessageResponse(MessageBase):
    """Schema for message response."""

    id: str
    timestamp: datetime
    read_by: Dict[str, datetime] = {}

    class Config:
        orm_mode = True


class TypingStatus(BaseModel):
    """Schema for typing status updates."""

    room_id: str
    is_typing: bool


class ReadReceipt(BaseModel):
    """Schema for read receipts."""

    message_id: str
    user_id: str
    read_at: datetime


class ChatRoom(BaseModel):
    """Schema for chat room information."""

    id: str
    name: str
    participants: List[str]
    last_message: Optional[MessageResponse] = None
    unread_count: int = 0


class WsMessage(BaseModel):
    """Base WebSocket message schema."""

    type: str  # 'message', 'typing', 'read_receipt', 'status_update'
    data: Dict[str, Any]


class WsMessageData(BaseModel):
    """Base WebSocket message data."""

    room_id: str
    user_id: str
    timestamp: datetime


class WsTypingData(WsMessageData):
    """WebSocket typing status data."""

    is_typing: bool


class WsReadReceiptData(WsMessageData):
    """WebSocket read receipt data."""

    message_id: str


class WsStatusData(WsMessageData):
    """WebSocket user status data."""

    status: str  # 'online', 'offline', 'away', 'busy'

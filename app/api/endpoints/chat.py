"""
WebSocket endpoints for real-time chat functionality.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from app.core.security import get_current_user
from app.models.user import User
from app.schemas.chat import MessageCreate, MessageResponse, TypingStatus
from app.services.p2p_manager import p2p_manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws/chat/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, token: str):
    """WebSocket endpoint for real-time chat."""
    try:
        # Authenticate user using the token
        user = await get_current_user(token)
        if not user:
            await websocket.close(code=4001)
            return

        await websocket.accept()

        # Register the connection
        await p2p_manager.connect(user.id, websocket, room_id)

        try:
            while True:
                data = await websocket.receive_text()
                try:
                    message_data = json.loads(data)
                    message_type = message_data.get("type")

                    if message_type == "message":
                        # Handle new message
                        message = MessageCreate(
                            content=message_data["content"], room_id=room_id, sender_id=user.id
                        )
                        await p2p_manager.send_message(user.id, room_id, message.content)

                    elif message_type == "typing":
                        # Handle typing status
                        is_typing = message_data.get("is_typing", False)
                        await p2p_manager.set_typing_status(user.id, room_id, is_typing)

                    elif message_type == "read_receipt":
                        # Handle read receipt
                        message_id = message_data.get("message_id")
                        if message_id:
                            await p2p_manager.mark_as_read(user.id, message_id)

                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON received: {data}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")

        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected: {user.id}")

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await p2p_manager.disconnect(user.id, websocket, room_id)


@router.get("/messages/{room_id}", response_model=list[MessageResponse])
async def get_message_history(
    room_id: str, limit: int = 50, current_user: User = Depends(get_current_user)
):
    """Get message history for a room."""
    try:
        messages = await p2p_manager.get_message_history(room_id, limit)
        return [
            MessageResponse(
                id=msg.get("message_id"),
                content=msg.get("content"),
                sender_id=msg.get("sender_id"),
                timestamp=msg.get("timestamp"),
                read_by=await p2p_manager.get_read_receipts(msg.get("message_id")),
            )
            for msg in messages
        ]
    except Exception as e:
        logger.error(f"Error getting message history: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/typing")
async def set_typing_status(
    typing_status: TypingStatus, current_user: User = Depends(get_current_user)
):
    """Update user's typing status."""
    try:
        await p2p_manager.set_typing_status(
            current_user.id, typing_status.room_id, typing_status.is_typing
        )
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error setting typing status: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/messages/{message_id}/read")
async def mark_message_as_read(
    message_id: str, room_id: str, current_user: User = Depends(get_current_user)
):
    """Mark a message as read."""
    try:
        await p2p_manager.mark_as_read(current_user.id, message_id)
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error marking message as read: {e}")
        raise HTTPException(status_code=400, detail=str(e))

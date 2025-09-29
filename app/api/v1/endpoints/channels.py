"""
Channel and message API endpoints.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app import crud, models, schemas
from app.api import deps
from app.core.websocket.connection_manager import ConnectionManager

router = APIRouter()
manager = ConnectionManager()


@router.post("/", response_model=schemas.ChannelResponse, status_code=status.HTTP_201_CREATED)
def create_channel(
    *,
    db: Session = Depends(deps.get_db),
    channel_in: schemas.ChannelCreate,
    server_id: int = Query(..., description="The ID of the server to create the channel in"),
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Create a new channel in a server.
    """
    # Check if user has permission to create channels
    if not crud.server.has_permission(
        db, server_id=server_id, user_id=current_user.id, permission="manage_channels"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to create channels in this server",
        )

    # Check if server exists and user is a member
    server = crud.server.get(db, id=server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    # Check channel name uniqueness in the server
    if crud.channel.get_by_name_and_server(db, name=channel_in.name, server_id=server_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A channel with this name already exists in the server",
        )

    # Create the channel
    return crud.channel.create_with_server(
        db=db, obj_in=channel_in, server_id=server_id, user_id=current_user.id
    )


@router.get("/{channel_id}", response_model=schemas.ChannelResponse)
def read_channel(
    *,
    db: Session = Depends(deps.get_db),
    channel_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Get channel by ID.
    """
    channel = crud.channel.get(db, id=channel_id)
    if not channel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Channel not found",
        )

    # Check if user has access to the channel
    if not crud.channel.has_access(db, channel_id=channel_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this channel",
        )

    return channel


@router.put("/{channel_id}", response_model=schemas.ChannelResponse)
def update_channel(
    *,
    db: Session = Depends(deps.get_db),
    channel_id: int,
    channel_in: schemas.ChannelUpdate,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Update a channel.
    """
    channel = crud.channel.get(db, id=channel_id)
    if not channel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Channel not found",
        )

    # Check if user has permission to update the channel
    if not crud.channel.can_manage(db, channel_id=channel_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to update this channel",
        )

    return crud.channel.update(db, db_obj=channel, obj_in=channel_in)


@router.delete("/{channel_id}", response_model=schemas.ChannelResponse)
def delete_channel(
    *,
    db: Session = Depends(deps.get_db),
    channel_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Delete a channel.
    """
    channel = crud.channel.get(db, id=channel_id)
    if not channel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Channel not found",
        )

    # Check if user has permission to delete the channel
    if not crud.channel.can_manage(db, channel_id=channel_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this channel",
        )

    return crud.channel.remove(db, id=channel_id)


@router.get("/{channel_id}/messages", response_model=List[schemas.MessageResponse])
def get_channel_messages(
    *,
    db: Session = Depends(deps.get_db),
    channel_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
    before: Optional[int] = None,
    after: Optional[int] = None,
    limit: int = 50,
):
    """
    Get messages in a channel with pagination.
    """
    # Check if user has access to the channel
    if not crud.channel.has_access(db, channel_id=channel_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view messages in this channel",
        )

    return crud.message.get_multi_by_channel(
        db, channel_id=channel_id, before=before, after=after, limit=limit
    )


@router.post("/{channel_id}/messages", response_model=schemas.MessageResponse)
def create_message(
    *,
    db: Session = Depends(deps.get_db),
    channel_id: int,
    message_in: schemas.MessageCreate,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Create a new message in a channel.
    """
    # Check if user has access to the channel
    if not crud.channel.has_access(db, channel_id=channel_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to send messages in this channel",
        )

    # Check if replying to a message and if it exists
    if message_in.reply_to_message_id:
        reply_message = crud.message.get(db, id=message_in.reply_to_message_id)
        if not reply_message or reply_message.channel_id != channel_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reply message",
            )

    # Create the message
    message = crud.message.create_with_author(
        db=db, obj_in=message_in, channel_id=channel_id, author_id=current_user.id
    )

    # Notify WebSocket clients
    await manager.broadcast_channel_message(channel_id, message)

    return message


@router.websocket("/{channel_id}/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    channel_id: int,
    token: str,
    db: Session = Depends(deps.get_db),
):
    """
    WebSocket endpoint for real-time chat.
    """
    # Authenticate user
    try:
        current_user = await deps.get_current_user_from_ws(token, db)
        if not current_user or not current_user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception as e:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Check if user has access to the channel
    if not crud.channel.has_access(db, channel_id=channel_id, user_id=current_user.id):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Accept the connection
    await manager.connect(websocket, str(channel_id), str(current_user.id))

    try:
        while True:
            data = await websocket.receive_text()
            try:
                message_data = json.loads(data)

                # Handle different message types
                if message_data.get("type") == "typing":
                    # Broadcast typing indicator
                    await manager.broadcast_typing(
                        channel_id=str(channel_id),
                        user_id=str(current_user.id),
                        username=current_user.username,
                    )
                elif message_data.get("type") == "message":
                    # Create and broadcast message
                    message = crud.message.create_with_author(
                        db=db,
                        obj_in=schemas.MessageCreate(**message_data["data"]),
                        channel_id=channel_id,
                        author_id=current_user.id,
                    )
                    await manager.broadcast_channel_message(str(channel_id), message)

            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON"})
            except Exception as e:
                await websocket.send_json({"error": str(e)})

    except WebSocketDisconnect:
        manager.disconnect(websocket, str(channel_id), str(current_user.id))

    except Exception as e:
        manager.disconnect(websocket, str(channel_id), str(current_user.id))
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)

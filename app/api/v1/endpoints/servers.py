"""
Server-related API endpoints.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import crud, models, schemas
from app.api import deps
from app.core.config import settings

router = APIRouter()


@router.post("/", response_model=schemas.ServerResponse, status_code=status.HTTP_201_CREATED)
def create_server(
    *,
    db: Session = Depends(deps.get_db),
    server_in: schemas.ServerCreate,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Create a new server.
    """
    # Check if user has reached server limit
    if current_user.is_superuser:
        server_count = crud.server.count_by_owner(db, owner_id=current_user.id)
        if server_count >= settings.MAX_SERVERS_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"You have reached the maximum number of servers ({settings.MAX_SERVERS_PER_USER})",
            )

    # Create the server
    server = crud.server.create_with_owner(db=db, obj_in=server_in, owner_id=current_user.id)

    # Create default channels
    default_channels = [
        {"name": "general", "description": "General discussion"},
        {"name": "welcome", "description": "Welcome to the server!"},
    ]

    for channel_data in default_channels:
        crud.channel.create_with_server(
            db=db,
            obj_in=schemas.ChannelCreate(**channel_data),
            server_id=server.id,
            user_id=current_user.id,
        )

    # Create default roles
    default_roles = [
        {"name": "@everyone", "permissions": {"read_messages": True}},
        {"name": "Admin", "permissions": {"administrator": True}, "is_mentionable": True},
    ]

    for role_data in default_roles:
        crud.role.create_with_server(
            db=db, obj_in=schemas.ServerRoleCreate(**role_data), server_id=server.id
        )

    return server


@router.get("/{server_id}", response_model=schemas.ServerResponse)
def read_server(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Get server by ID.
    """
    server = crud.server.get(db, id=server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    # Check if user has access to the server
    if not crud.server.has_member(db, server_id=server_id, user_id=current_user.id):
        if server.visibility != schemas.ServerVisibility.PUBLIC:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this server",
            )

    return server


@router.put("/{server_id}", response_model=schemas.ServerResponse)
def update_server(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    server_in: schemas.ServerUpdate,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Update a server.
    """
    server = crud.server.get(db, id=server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    # Check if user is the owner
    if server.owner_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to update this server",
        )

    return crud.server.update(db, db_obj=server, obj_in=server_in)


@router.delete("/{server_id}", response_model=schemas.ServerResponse)
def delete_server(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Delete a server.
    """
    server = crud.server.get(db, id=server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    # Check if user is the owner
    if server.owner_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this server",
        )

    return crud.server.remove(db, id=server_id)


@router.get("/{server_id}/channels", response_model=List[schemas.ChannelResponse])
def get_server_channels(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Get all channels in a server.
    """
    # Check if user has access to the server
    if not crud.server.has_member(db, server_id=server_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view channels in this server",
        )

    return crud.channel.get_multi_by_server(db, server_id=server_id)


@router.get("/{server_id}/members", response_model=List[schemas.ServerMemberResponse])
def get_server_members(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
    skip: int = 0,
    limit: int = 100,
):
    """
    Get all members in a server with pagination.
    """
    # Check if user has access to the server
    if not crud.server.has_member(db, server_id=server_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view members in this server",
        )

    return crud.member.get_multi_by_server(db, server_id=server_id, skip=skip, limit=limit)


@router.post("/{server_id}/invites", response_model=schemas.ServerInviteResponse)
def create_server_invite(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    invite_in: schemas.ServerInviteCreate,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Create a new server invite.
    """
    # Check if user has permission to create invites
    if not crud.server.has_permission(
        db, server_id=server_id, user_id=current_user.id, permission="create_invite"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to create invites in this server",
        )

    server = crud.server.get(db, id=server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    return crud.invite.create_with_inviter(
        db=db, obj_in=invite_in, server_id=server_id, inviter_id=current_user.id
    )


@router.get("/{server_id}/stats", response_model=schemas.ServerStatsResponse)
def get_server_stats(
    *,
    db: Session = Depends(deps.get_db),
    server_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Get server statistics.
    """
    # Check if user has access to the server
    if not crud.server.has_member(db, server_id=server_id, user_id=current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view stats for this server",
        )

    return crud.server.get_stats(db, server_id=server_id)

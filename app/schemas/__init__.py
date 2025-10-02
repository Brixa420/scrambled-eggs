"""
Pydantic models for the application.

This module exports all the schema models used throughout the application.
"""
from .user import User, UserCreate, UserInDB, UserUpdate, UserResponse, UserInDBBase
from .token import Token, TokenPayload, TokenCreate, TokenResponse
from .message import Message, MessageCreate, MessageUpdate, MessageInDB, MessageResponse
from .conversation import Conversation, ConversationCreate, ConversationUpdate, ConversationInDB, ConversationResponse
from .server import Server, ServerCreate, ServerUpdate, ServerInDB, ServerResponse
from .channel import Channel, ChannelCreate, ChannelUpdate, ChannelInDB, ChannelResponse
from .role import Role, RoleCreate, RoleUpdate, RoleInDB, RoleResponse, RoleDetail
from .permission import Permission, PermissionCreate, PermissionInDB, PermissionResponse
from .rbac import (
    PermissionBase,
    PermissionCreate,
    Permission,
    RoleBase,
    RoleCreate,
    RoleUpdate,
    Role,
    RoleDetail,
    UserRoleUpdate,
    PermissionList,
    RoleList
)

# Make these available at the package level
__all__ = [
    # User
    'User', 'UserCreate', 'UserInDB', 'UserUpdate', 'UserResponse', 'UserInDBBase',
    # Token
    'Token', 'TokenPayload', 'TokenCreate', 'TokenResponse',
    # Message
    'Message', 'MessageCreate', 'MessageUpdate', 'MessageInDB', 'MessageResponse',
    # Conversation
    'Conversation', 'ConversationCreate', 'ConversationUpdate', 'ConversationInDB', 'ConversationResponse',
    # Server
    'Server', 'ServerCreate', 'ServerUpdate', 'ServerInDB', 'ServerResponse',
    # Channel
    'Channel', 'ChannelCreate', 'ChannelUpdate', 'ChannelInDB', 'ChannelResponse',
    # RBAC
    'Role', 'RoleCreate', 'RoleUpdate', 'RoleResponse', 'RoleDetail',
    'Permission', 'PermissionCreate', 'PermissionResponse',
    # RBAC Extended
    'PermissionBase', 'RoleBase', 'UserRoleUpdate', 'PermissionList', 'RoleList'
]

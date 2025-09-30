"""
Pydantic models for Role-Based Access Control (RBAC).
"""
from typing import List, Optional
from pydantic import BaseModel, Field

class PermissionBase(BaseModel):
    """Base permission model."""
    name: str = Field(..., description="Unique name of the permission (e.g., 'user:read')")
    description: Optional[str] = Field(None, description="Description of the permission")
    resource: str = Field(..., description="The resource this permission applies to (e.g., 'user')")
    action: str = Field(..., description="The action this permission allows (e.g., 'read', 'create')")

class PermissionCreate(PermissionBase):
    """Schema for creating a new permission."""
    pass

class Permission(PermissionBase):
    """Permission model with ID and timestamps."""
    id: int
    created_at: str
    updated_at: Optional[str]

    class Config:
        orm_mode = True

class RoleBase(BaseModel):
    """Base role model."""
    name: str = Field(..., description="Unique name of the role")
    description: Optional[str] = Field(None, description="Description of the role")
    is_default: bool = Field(False, description="Whether this is a default role for new users")

class RoleCreate(RoleBase):
    """Schema for creating a new role."""
    permissions: List[str] = Field(
        default_factory=list,
        description="List of permission names to assign to this role"
    )

class RoleUpdate(RoleBase):
    """Schema for updating a role."""
    name: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None
    permissions: Optional[List[str]] = Field(
        None,
        description="List of permission names to assign to this role"
    )

class Role(RoleBase):
    """Role model with ID, permissions, and timestamps."""
    id: int
    permissions: List[Permission] = []
    created_at: str
    updated_at: Optional[str]

    class Config:
        orm_mode = True

class RoleDetail(Role):
    """Extended role model with user count."""
    user_count: int = 0

class UserRoleUpdate(BaseModel):
    """Schema for updating a user's role."""
    role_name: str = Field(..., description="Name of the role to assign to the user")

# Response models for API endpoints
class PermissionList(BaseModel):
    """Response model for listing permissions."""
    items: List[Permission]
    total: int

class RoleList(BaseModel):
    """Response model for listing roles."""
    items: List[Role]
    total: int

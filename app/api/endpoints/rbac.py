"""
Role-Based Access Control (RBAC) API endpoints.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import schemas
from app.db.session import get_db
from app.models.role import Role, Permission
from app.services.rbac_service import RBACService
from app.api.deps.rbac import Permissions, get_rbac_service
from app.api.deps.auth import get_current_user

router = APIRouter()

@router.get("/roles/", response_model=List[schemas.Role])
def list_roles(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(Permissions.ROLE_READ),
    db: Session = Depends(get_db)
):
    """
    List all roles with pagination.
    """
    roles = db.query(Role).offset(skip).limit(limit).all()
    return roles

@router.post("/roles/", response_model=schemas.Role, status_code=status.HTTP_201_CREATED)
def create_role(
    role_in: schemas.RoleCreate,
    current_user: User = Depends(Permissions.ROLE_CREATE),
    rbac_service: RBACService = Depends(get_rbac_service)
):
    """
    Create a new role.
    """
    try:
        role = rbac_service.create_role(
            name=role_in.name,
            description=role_in.description,
            is_default=role_in.is_default,
            permission_names=role_in.permissions
        )
        return role
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/roles/{role_id}", response_model=schemas.RoleDetail)
def get_role(
    role_id: int,
    current_user: User = Depends(Permissions.ROLE_READ),
    db: Session = Depends(get_db)
):
    """
    Get a role by ID.
    """
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    return role

@router.put("/roles/{role_id}", response_model=schemas.Role)
def update_role(
    role_id: int,
    role_in: schemas.RoleUpdate,
    current_user: User = Depends(Permissions.ROLE_UPDATE),
    rbac_service: RBACService = Depends(get_rbac_service)
):
    """
    Update a role.
    """
    try:
        role = rbac_service.update_role(
            role_id=role_id,
            name=role_in.name,
            description=role_in.description,
            is_default=role_in.is_default,
            permission_names=role_in.permissions
        )
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )
        return role
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: int,
    current_user: User = Depends(Permissions.ROLE_DELETE),
    rbac_service: RBACService = Depends(get_rbac_service)
):
    """
    Delete a role.
    """
    try:
        success = rbac_service.delete_role(role_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/users/{user_id}/roles/{role_name}", response_model=schemas.User)
def assign_role_to_user(
    user_id: int,
    role_name: str,
    current_user: User = Depends(Permissions.ROLE_UPDATE),
    rbac_service: RBACService = Depends(get_rbac_service),
    db: Session = Depends(get_db)
):
    """
    Assign a role to a user.
    """
    from app.models.user import User
    
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Assign role
    success = rbac_service.assign_role_to_user(user_id, role_name)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to assign role"
        )
    
    db.refresh(user)
    return user

@router.get("/permissions/", response_model=List[schemas.Permission])
def list_permissions(
    current_user: User = Depends(Permissions.ROLE_READ),
    db: Session = Depends(get_db)
):
    """
    List all available permissions.
    """
    permissions = db.query(Permission).all()
    return permissions

@router.post("/permissions/", response_model=schemas.Permission, status_code=status.HTTP_201_CREATED)
def create_permission(
    permission_in: schemas.PermissionCreate,
    current_user: User = Depends(Permissions.ROLE_CREATE),
    rbac_service: RBACService = Depends(get_rbac_service)
):
    """
    Create a new permission.
    """
    try:
        permission = rbac_service.create_permission(
            name=permission_in.name,
            resource=permission_in.resource,
            action=permission_in.action,
            description=permission_in.description
        )
        return permission
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/me/permissions", response_model=List[str])
def get_my_permissions(
    current_user: User = Depends(Permissions.IS_AUTHENTICATED),
    rbac_service: RBACService = Depends(get_rbac_service)
):
    """
    Get the current user's permissions.
    """
    return rbac_service.get_user_permissions(current_user)

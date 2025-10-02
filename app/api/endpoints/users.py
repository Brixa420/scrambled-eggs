"""
User management endpoints with role-based access control.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.permissions import has_permission, is_admin, is_superadmin
from app.db.session import get_db
from app.models.user import User
from app.models.role import Role
from app.schemas.user import UserCreate, UserUpdate, UserInDB, UserRoleUpdate
from app.crud import user as crud_user
from app.core.security import get_password_hash

router = APIRouter()

@router.get("/", response_model=List[UserInDB])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(is_admin),
    db: Session = Depends(get_db)
):
    """
    Retrieve users (admin only).
    """
    users = crud_user.get_users(db, skip=skip, limit=limit)
    return users

@router.post("/", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    current_user: User = Depends(is_admin),  # Only admins can create users
    db: Session = Depends(get_db)
):
    """
    Create new user (admin only).
    """
    user = crud_user.get_user_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
    
    # Set default role if not provided
    if not user_in.role_id:
        default_role = db.query(Role).filter_by(is_default=True).first()
        if default_role:
            user_in.role_id = default_role.id
    
    user = crud_user.create_user(db, user_in)
    return user

@router.get("/me", response_model=UserInDB)
async def read_user_me(
    current_user: User = Depends(has_permission("user:read")),
    db: Session = Depends(get_db)
):
    """
    Get current user.
    """
    return current_user

@router.get("/{user_id}", response_model=UserInDB)
async def read_user(
    user_id: int,
    current_user: User = Depends(has_permission("user:read")),
    db: Session = Depends(get_db)
):
    """
    Get a specific user by id.
    Users can only read their own profile unless they have user:read_all permission.
    """
    # Users can read their own profile
    if current_user.id == user_id:
        return current_user
    
    # Check if user has permission to read other users
    if not any(perm.name == "user:read_all" for perm in current_user.role.permissions):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to view this user"
        )
    
    user = crud_user.get(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@router.put("/{user_id}", response_model=UserInDB)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    current_user: User = Depends(has_permission("user:update")),
    db: Session = Depends(get_db)
):
    """
    Update a user.
    Users can only update their own profile unless they have user:update_all permission.
    """
    user = crud_user.get(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Users can update their own profile
    if current_user.id != user_id:
        # Check if user has permission to update other users
        if not any(perm.name == "user:update_all" for perm in current_user.role.permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions to update this user"
            )
    
    # Prevent users from promoting themselves to admin/superadmin
    if user_in.role_id and user_id == current_user.id:
        current_role = db.query(Role).filter(Role.id == user_in.role_id).first()
        if current_role and current_role.name in ["admin", "superadmin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot assign admin/superadmin role to yourself"
            )
    
    return crud_user.update(db, db_obj=user, obj_in=user_in)

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    current_user: User = Depends(has_permission("user:delete")),
    db: Session = Depends(get_db)
):
    """
    Delete a user.
    Users cannot delete themselves.
    """
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete yourself"
        )
    
    user = crud_user.get(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent deleting admin/superadmin users unless you're a superadmin
    if user.role and user.role.name in ["admin", "superadmin"] and current_user.role.name != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to delete admin/superadmin users"
        )
    
    crud_user.remove(db, id=user_id)
    return {"status": "success", "message": "User deleted successfully"}

@router.put("/{user_id}/role", response_model=UserInDB)
async def update_user_role(
    user_id: int,
    role_update: UserRoleUpdate,
    current_user: User = Depends(is_admin),  # Only admins can change roles
    db: Session = Depends(get_db)
):
    """
    Update a user's role (admin only).
    Superadmins can assign any role, admins can only assign non-admin roles.
    """
    if current_user.id == user_id and current_user.role.name != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change your own role"
        )
    
    user = crud_user.get(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if the target role exists
    role = db.query(Role).filter(Role.id == role_update.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Prevent admins from assigning admin/superadmin roles
    if current_user.role.name == "admin" and role.name in ["admin", "superadmin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to assign this role"
        )
    
    # Prevent demoting the last superadmin
    if role.name != "superadmin" and user.role.name == "superadmin":
        superadmin_count = db.query(User).filter(User.role.has(name="superadmin")).count()
        if superadmin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot demote the last superadmin"
            )
    
    # Update the user's role
    user.role_id = role.id
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user

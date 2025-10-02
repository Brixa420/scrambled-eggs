"""
Permission utilities for role-based access control (RBAC).
"""
from functools import wraps
from typing import List, Optional, Union

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get the current user from the token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except (JWTError, ValueError):
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    
    return user


def has_permission(required_permission: str):
    ""
    Decorator to check if the current user has the required permission.
    
    Args:
        required_permission: The permission string in 'resource:action' format
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(
            *args,
            current_user: User = Depends(get_current_user),
            db: Session = Depends(get_db),
            **kwargs
        ):
            # Superadmin has all permissions
            if current_user.role and current_user.role.name == 'superadmin':
                return await func(*args, current_user=current_user, db=db, **kwargs)
            
            # Check if the user's role has the required permission
            if not current_user.role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No role assigned to user"
                )
            
            # Check if the permission exists
            permission = (
                db.query(Permission)
                .filter(Permission.name == required_permission)
                .first()
            )
            
            if not permission:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Permission {required_permission} not found"
                )
            
            # Check if the role has the permission
            has_perm = (
                db.query(Permission)
                .join(Role.permissions)
                .filter(
                    Role.id == current_user.role_id,
                    Permission.id == permission.id
                )
                .first()
            )
            
            if not has_perm:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {required_permission}"
                )
            
            return await func(*args, current_user=current_user, db=db, **kwargs)
        
        return wrapper
    return decorator


def has_role(required_roles: Union[str, List[str]]):
    """
    Decorator to check if the current user has one of the required roles.
    
    Args:
        required_roles: Single role name or list of role names
    """
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    def decorator(func):
        @wraps(func)
        async def wrapper(
            *args,
            current_user: User = Depends(get_current_user),
            **kwargs
        ):
            # Superadmin has all roles
            if current_user.role and current_user.role.name == 'superadmin':
                return await func(*args, current_user=current_user, **kwargs)
            
            if not current_user.role or current_user.role.name not in required_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {', '.join(required_roles)}"
                )
            
            return await func(*args, current_user=current_user, **kwargs)
        
        return wrapper
    return decorator


def is_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to check if the current user is an admin."""
    if not current_user.role or current_user.role.name not in ['admin', 'superadmin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


def is_superadmin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to check if the current user is a superadmin."""
    if not current_user.role or current_user.role.name != 'superadmin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin privileges required"
        )
    return current_user

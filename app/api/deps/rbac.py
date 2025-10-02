"""
Dependencies for role-based access control (RBAC).
"""
from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.services.rbac_service import RBACService
from .auth import get_current_user

security = HTTPBearer()

class PermissionChecker:
    """Dependency to check if a user has required permissions."""
    
    def __init__(self, permissions: List[str]):
        self.permissions = permissions
    
    def __call__(
        self,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        rbac_service = RBACService(db)
        
        # Superusers bypass permission checks
        if current_user.is_superuser:
            return current_user
            
        # Check each required permission
        for permission in self.permissions:
            if not rbac_service.has_permission(current_user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {', '.join(self.permissions)}"
                )
        
        return current_user

# Common permission checkers
class Permissions:
    """Common permission checkers for reuse across the application."""
    
    # User permissions
    USER_CREATE = PermissionChecker(["user:create"])
    USER_READ = PermissionChecker(["user:read"])
    USER_UPDATE = PermissionChecker(["user:update"])
    USER_DELETE = PermissionChecker(["user:delete"])
    
    # Role permissions
    ROLE_CREATE = PermissionChecker(["role:create"])
    ROLE_READ = PermissionChecker(["role:read"])
    ROLE_UPDATE = PermissionChecker(["role:update"])
    ROLE_DELETE = PermissionChecker(["role:delete"])
    
    # Admin permissions
    ADMIN_ACCESS = PermissionChecker(["admin:access"])
    ADMIN_SETTINGS = PermissionChecker(["admin:settings"])
    
    # Message permissions
    MESSAGE_SEND = PermissionChecker(["message:send"])
    MESSAGE_DELETE = PermissionChecker(["message:delete"])
    MESSAGE_EDIT = PermissionChecker(["message:edit"])
    
    # Channel permissions
    CHANNEL_CREATE = PermissionChecker(["channel:create"])
    CHANNEL_READ = PermissionChecker(["channel:read"])
    CHANNEL_UPDATE = PermissionChecker(["channel:update"])
    CHANNEL_DELETE = PermissionChecker(["channel:delete"])
    
    # Composite permissions
    IS_ADMIN = PermissionChecker(["admin:access"])
    IS_MODERATOR = PermissionChecker(["message:delete", "message:edit"])
    IS_AUTHENTICATED = PermissionChecker([])  # Just checks if user is authenticated

def get_rbac_service(db: Session = Depends(get_db)) -> RBACService:
    """Get an instance of the RBAC service."""
    return RBACService(db)

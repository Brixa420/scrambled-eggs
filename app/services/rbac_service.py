"""
Role-Based Access Control (RBAC) service for handling permissions and role management.
"""
from typing import List, Optional, Union
from sqlalchemy.orm import Session

from app.models.role import Role
from app.models.permission import Permission
from app.models.user import User
from app.core.config import settings

class RBACService:
    """Service for handling role-based access control operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def has_permission(self, user: User, permission_name: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user: The user to check permissions for
            permission_name: The permission name in 'resource:action' format
            
        Returns:
            bool: True if the user has the permission, False otherwise
        """
        # Superusers have all permissions
        if user.is_superuser:
            return True
            
        # If user has no role, they only have public permissions
        if not user.role:
            return False
            
        # Check if the role has the 'all' permission
        if any(p.name == 'all' for p in user.role.permissions):
            return True
            
        # Check for the specific permission
        return any(p.name == permission_name for p in user.role.permissions)
    
    def get_user_permissions(self, user: User) -> List[str]:
        """
        Get all permissions for a user.
        
        Args:
            user: The user to get permissions for
            
        Returns:
            List[str]: List of permission names
        """
        if user.is_superuser:
            return ['all']
            
        if not user.role:
            return []
            
        return [p.name for p in user.role.permissions]
    
    def create_role(
        self,
        name: str,
        description: str = None,
        is_default: bool = False,
        permission_names: List[str] = None
    ) -> Role:
        """
        Create a new role with the specified permissions.
        
        Args:
            name: Name of the role
            description: Description of the role
            is_default: Whether this is a default role for new users
            permission_names: List of permission names to assign to the role
            
        Returns:
            Role: The created role
        """
        # Check if role already exists
        existing_role = self.db.query(Role).filter(Role.name == name).first()
        if existing_role:
            raise ValueError(f"Role '{name}' already exists")
            
        # Get permissions
        permissions = []
        if permission_names:
            permissions = self.db.query(Permission).filter(
                Permission.name.in_(permission_names)
            ).all()
            
            # Check for invalid permissions
            found_permissions = {p.name for p in permissions}
            missing_permissions = set(permission_names) - found_permissions
            if missing_permissions:
                raise ValueError(f"Invalid permissions: {', '.join(missing_permissions)}")            
        # Create role
        role = Role(
            name=name,
            description=description,
            is_default=is_default,
            permissions=permissions
        )
        
        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)
        
        return role
    
    def update_role(
        self,
        role_id: int,
        name: str = None,
        description: str = None,
        is_default: bool = None,
        permission_names: List[str] = None
    ) -> Optional[Role]:
        """
        Update an existing role.
        
        Args:
            role_id: ID of the role to update
            name: New name for the role
            description: New description for the role
            is_default: Whether this should be a default role
            permission_names: New list of permission names for the role
            
        Returns:
            Optional[Role]: The updated role, or None if not found
        """
        role = self.db.query(Role).get(role_id)
        if not role:
            return None
            
        if name is not None:
            # Check if the new name is already taken by another role
            existing = self.db.query(Role).filter(
                Role.name == name,
                Role.id != role_id
            ).first()
            if existing:
                raise ValueError(f"Role name '{name}' is already taken")
            role.name = name
            
        if description is not None:
            role.description = description
            
        if is_default is not None:
            role.is_default = is_default
            
        if permission_names is not None:
            permissions = self.db.query(Permission).filter(
                Permission.name.in_(permission_names)
            ).all()
            
            # Check for invalid permissions
            found_permissions = {p.name for p in permissions}
            missing_permissions = set(permission_names) - found_permissions
            if missing_permissions:
                raise ValueError(f"Invalid permissions: {', '.join(missing_permissions)}")            
            role.permissions = permissions
            
        self.db.commit()
        self.db.refresh(role)
        return role
    
    def delete_role(self, role_id: int) -> bool:
        """
        Delete a role.
        
        Args:
            role_id: ID of the role to delete
            
        Returns:
            bool: True if the role was deleted, False if not found
        """
        role = self.db.query(Role).get(role_id)
        if not role:
            return False
            
        # Don't allow deleting roles that are assigned to users
        if role.users:
            raise ValueError("Cannot delete a role that is assigned to users")
            
        self.db.delete(role)
        self.db.commit()
        return True
    
    def assign_role_to_user(self, user_id: int, role_name: str) -> bool:
        """
        Assign a role to a user.
        
        Args:
            user_id: ID of the user
            role_name: Name of the role to assign
            
        Returns:
            bool: True if the role was assigned, False if user or role not found
        """
        from app.models.user import User
        
        user = self.db.query(User).get(user_id)
        if not user:
            return False
            
        role = self.db.query(Role).filter(Role.name == role_name).first()
        if not role:
            return False
            
        user.role = role
        self.db.commit()
        return True
    
    def create_permission(
        self,
        name: str,
        resource: str,
        action: str,
        description: str = None
    ) -> Permission:
        """
        Create a new permission.
        
        Args:
            name: Unique name for the permission (e.g., 'user:create')
            resource: The resource this permission applies to (e.g., 'user')
            action: The action this permission allows (e.g., 'create', 'read')
            description: Optional description of the permission
            
        Returns:
            Permission: The created permission
        """
        permission = Permission(
            name=name,
            description=description,
            resource=resource,
            action=action
        )
        
        self.db.add(permission)
        self.db.commit()
        self.db.refresh(permission)
        return permission
    
    def get_default_role(self) -> Optional[Role]:
        """
        Get the default role for new users.
        
        Returns:
            Optional[Role]: The default role, or None if not set
        """
        return self.db.query(Role).filter(Role.is_default == True).first()
    
    def ensure_default_roles_exist(self) -> None:
        """
        Ensure that the default roles exist in the database.
        This should be called during application startup.
        """
        # Check if we already have roles
        if self.db.query(Role).count() > 0:
            return
            
        # Create default permissions if they don't exist
        default_permissions = [
            # User permissions
            {"name": "user:create", "description": "Create new users", "resource": "user", "action": "create"},
            {"name": "user:read", "description": "View user information", "resource": "user", "action": "read"},
            {"name": "user:update", "description": "Update user information", "resource": "user", "action": "update"},
            {"name": "user:delete", "description": "Delete users", "resource": "user", "action": "delete"},
            
            # Role permissions
            {"name": "role:create", "description": "Create roles", "resource": "role", "action": "create"},
            {"name": "role:read", "description": "View roles", "resource": "role", "action": "read"},
            {"name": "role:update", "description": "Update roles", "resource": "role", "action": "update"},
            {"name": "role:delete", "description": "Delete roles", "resource": "role", "action": "delete"},
            
            # Admin permissions
            {"name": "admin:access", "description": "Access admin dashboard", "resource": "admin", "action": "access"},
            {"name": "admin:settings", "description": "Modify system settings", "resource": "admin", "action": "settings"},
            
            # Message permissions
            {"name": "message:send", "description": "Send messages", "resource": "message", "action": "send"},
            {"name": "message:delete", "description": "Delete messages", "resource": "message", "action": "delete"},
            {"name": "message:edit", "description": "Edit messages", "resource": "message", "action": "edit"},
            
            # Channel permissions
            {"name": "channel:create", "description": "Create channels", "resource": "channel", "action": "create"},
            {"name": "channel:read", "description": "View channels", "resource": "channel", "action": "read"},
            {"name": "channel:update", "description": "Update channels", "resource": "channel", "action": "update"},
            {"name": "channel:delete", "description": "Delete channels", "resource": "channel", "action": "delete"},
        ]
        
        # Create permissions
        permissions = {}
        for perm_data in default_permissions:
            perm = Permission(**perm_data)
            self.db.add(perm)
            permissions[perm.name] = perm
        
        self.db.commit()
        
        # Create default roles
        default_roles = [
            {
                "name": "superadmin",
                "description": "Super Administrator with full access",
                "is_default": False,
                "permissions": ["all"]
            },
            {
                "name": "admin",
                "description": "Administrator with most access",
                "is_default": False,
                "permissions": [
                    "user:read", "user:update", "user:delete",
                    "role:read", "role:update",
                    "admin:access", "admin:settings",
                    "message:delete", "message:edit",
                    "channel:create", "channel:read", "channel:update", "channel:delete"
                ]
            },
            {
                "name": "moderator",
                "description": "Moderator with limited administrative access",
                "is_default": False,
                "permissions": [
                    "user:read",
                    "message:delete", "message:edit",
                    "channel:read"
                ]
            },
            {
                "name": "user",
                "description": "Regular user",
                "is_default": True,
                "permissions": [
                    "user:read", "user:update",
                    "message:send", "message:edit",
                    "channel:read"
                ]
            },
            {
                "name": "guest",
                "description": "Guest user with minimal access",
                "is_default": False,
                "permissions": [
                    "user:read",
                    "channel:read"
                ]
            }
        ]
        
        for role_data in default_roles:
            role_perms = []
            for perm_name in role_data.pop('permissions', []):
                if perm_name == 'all':
                    role_perms = list(permissions.values())
                    break
                if perm_name in permissions:
                    role_perms.append(permissions[perm_name])
            
            role = Role(
                **role_data,
                permissions=role_perms
            )
            self.db.add(role)
        
        self.db.commit()


def get_rbac_service(db: Session) -> RBACService:
    """Get an instance of the RBAC service."""
    return RBACService(db)

from sqlalchemy import Column, Integer, String, Text, DateTime, func, ForeignKey
from sqlalchemy.orm import relationship
from app.db.base_class import Base

class Permission(Base):
    """
    Permission model for RBAC system.
    Defines what actions can be performed on resources.
    """
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    resource = Column(String(100), nullable=False, index=True)  # e.g., 'user', 'post', 'settings'
    action = Column(String(50), nullable=False)  # e.g., 'create', 'read', 'update', 'delete'
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission")

    def __repr__(self):
        return f"<Permission {self.resource}:{self.action}>"

    @property
    def permission_name(self):
        """Return a standardized permission name in the format 'resource:action'"""
        return f"{self.resource}:{self.action}"

    @classmethod
    def seed_default_permissions(cls, db):
        """Seed default permissions into the database"""
        from sqlalchemy.exc import IntegrityError
        from sqlalchemy.orm import Session
        
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
            
            # Content permissions
            {"name": "content:create", "description": "Create content", "resource": "content", "action": "create"},
            {"name": "content:read", "description": "View content", "resource": "content", "action": "read"},
            {"name": "content:update", "description": "Update content", "resource": "content", "action": "update"},
            {"name": "content:delete", "description": "Delete content", "resource": "content", "action": "delete"},
        ]
        
        try:
            for perm_data in default_permissions:
                # Check if permission already exists
                existing = db.query(cls).filter_by(name=perm_data["name"]).first()
                if not existing:
                    db.add(cls(**perm_data))
            db.commit()
        except IntegrityError as e:
            db.rollback()
            print(f"Error seeding permissions: {e}")

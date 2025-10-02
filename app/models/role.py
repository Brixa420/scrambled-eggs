from sqlalchemy import Boolean, Column, Integer, String, Text, DateTime, func, Table, ForeignKey
from sqlalchemy.orm import relationship
from app.db.base_class import Base

# Association table for role-permission many-to-many relationship
role_permission = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('created_at', DateTime(timezone=True), server_default=func.now())
)

class Role(Base):
    """
    Role model for RBAC system.
    Roles group permissions together and can be assigned to users.
    """
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    users = relationship("User", back_populates="role")
    permissions = relationship(
        "Permission",
        secondary=role_permission,
        back_populates="roles"
    )

    def __repr__(self):
        return f"<Role {self.name}>"

    @classmethod
    def seed_default_roles(cls, db):
        """Seed default roles into the database"""
        from sqlalchemy.exc import IntegrityError
        from app.models.permission import Permission
        
        default_roles = [
            {
                "name": "superadmin",
                "description": "Super Administrator with full access",
                "is_default": False,
                "permissions": ["all"]  # Special case for superadmin
            },
            {
                "name": "admin",
                "description": "Administrator with most access",
                "is_default": False,
                "permissions": [
                    "user:read", "user:update", "user:create",
                    "role:read", "content:read", "content:update",
                    "content:delete", "admin:access"
                ]
            },
            {
                "name": "moderator",
                "description": "Moderator with content management access",
                "is_default": False,
                "permissions": [
                    "content:read", "content:update", "content:delete",
                    "user:read"
                ]
            },
            {
                "name": "user",
                "description": "Regular authenticated user",
                "is_default": True,
                "permissions": [
                    "content:create", "content:read", "content:update",
                    "user:read", "user:update"
                ]
            },
            {
                "name": "guest",
                "description": "Unauthenticated user",
                "is_default": True,
                "permissions": ["content:read"]
            }
        ]
        
        try:
            for role_data in default_roles:
                # Check if role already exists
                existing = db.query(cls).filter_by(name=role_data["name"]).first()
                if not existing:
                    # Handle superadmin special case
                    if role_data["name"] == "superadmin":
                        # Superadmin gets all permissions
                        role = cls(
                            name=role_data["name"],
                            description=role_data["description"],
                            is_default=role_data["is_default"]
                        )
                        db.add(role)
                        db.flush()  # Get the role ID
                    else:
                        # For other roles, add specific permissions
                        permissions = []
                        for perm_name in role_data["permissions"]:
                            perm = db.query(Permission).filter_by(name=perm_name).first()
                            if perm:
                                permissions.append(perm)
                        
                        role = cls(
                            name=role_data["name"],
                            description=role_data["description"],
                            is_default=role_data["is_default"],
                            permissions=permissions
                        )
                        db.add(role)
                    
                    db.commit()
        except IntegrityError as e:
            db.rollback()
            print(f"Error seeding roles: {e}")

    def has_permission(self, resource, action):
        """Check if role has a specific permission"""
        if self.name == "superadmin":
            return True
            
        permission_name = f"{resource}:{action}"
        return any(perm.name == permission_name for perm in self.permissions)

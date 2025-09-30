"""Script to seed initial RBAC data."""
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.resolve())
sys.path.insert(0, project_root)

from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.permission import Permission
from app.models.role import Role

def seed_permissions(db: Session):
    """Seed default permissions."""
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
    
    for perm_data in default_permissions:
        # Check if permission already exists
        existing = db.query(Permission).filter_by(name=perm_data["name"]).first()
        if not existing:
            db.add(Permission(**perm_data))
    
    db.commit()

def seed_roles(db: Session):
    """Seed default roles and their permissions."""
    # Get all permissions
    permissions = {perm.name: perm for perm in db.query(Permission).all()}
    
    default_roles = [
        {
            "name": "superadmin",
            "description": "Super Administrator with full access",
            "is_default": False,
            "permissions": list(permissions.values())  # All permissions
        },
        {
            "name": "admin",
            "description": "Administrator with most access",
            "is_default": False,
            "permissions": [
                permissions["user:read"], 
                permissions["user:update"], 
                permissions["user:create"],
                permissions["role:read"], 
                permissions["content:read"], 
                permissions["content:update"],
                permissions["content:delete"], 
                permissions["admin:access"]
            ]
        },
        {
            "name": "moderator",
            "description": "Moderator with content management access",
            "is_default": False,
            "permissions": [
                permissions["content:read"], 
                permissions["content:update"], 
                permissions["content:delete"],
                permissions["user:read"]
            ]
        },
        {
            "name": "user",
            "description": "Regular authenticated user",
            "is_default": True,
            "permissions": [
                permissions["content:create"], 
                permissions["content:read"], 
                permissions["content:update"],
                permissions["user:read"], 
                permissions["user:update"]
            ]
        },
        {
            "name": "guest",
            "description": "Unauthenticated user",
            "is_default": True,
            "permissions": [permissions["content:read"]]
        }
    ]
    
    for role_data in default_roles:
        # Check if role already exists
        existing = db.query(Role).filter_by(name=role_data["name"]).first()
        if not existing:
            role = Role(
                name=role_data["name"],
                description=role_data["description"],
                is_default=role_data["is_default"]
            )
            db.add(role)
            db.flush()  # Get the role ID
            
            # Add permissions
            for permission in role_data["permissions"]:
                role.permissions.append(permission)
            
            db.add(role)
    
    db.commit()

def assign_default_roles(db: Session):
    """Assign default role to existing users."""
    from app.models.user import User
    
    default_role = db.query(Role).filter_by(name="user").first()
    if not default_role:
        print("Default role 'user' not found. Please seed roles first.")
        return
    
    # Update users with no role to the default role
    db.execute(
        "UPDATE users SET role_id = :role_id WHERE role_id IS NULL",
        {"role_id": default_role.id}
    )
    db.commit()

def main():
    """Main function to seed RBAC data."""
    db = SessionLocal()
    try:
        print("Seeding permissions...")
        seed_permissions(db)
        
        print("Seeding roles...")
        seed_roles(db)
        
        print("Assigning default roles to existing users...")
        assign_default_roles(db)
        
        print("RBAC data seeded successfully!")
    except Exception as e:
        print(f"Error seeding RBAC data: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    main()

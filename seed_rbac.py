"""
Script to seed initial RBAC data.
Run this script after the database has been initialized.
"""
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.resolve())
sys.path.insert(0, project_root)

from app.db.session import SessionLocal
from app.models.role import Role
from app.models.permission import Permission

def seed_permissions(db):
    """Seed default permissions."""
    print("Seeding permissions...")
    Permission.seed_default_permissions(db)
    print("Permissions seeded successfully!")

def seed_roles(db):
    """Seed default roles and their permissions."""
    print("Seeding roles...")
    Role.seed_default_roles(db)
    print("Roles seeded successfully!")

def assign_default_roles(db):
    """Assign default role to existing users."""
    from app.models.user import User
    
    print("Assigning default roles to users...")
    default_role = db.query(Role).filter_by(name="user").first()
    if not default_role:
        print("Default role 'user' not found. Please seed roles first.")
        return
    
    # Update users with no role to the default role
    users = db.query(User).filter(User.role_id.is_(None)).all()
    for user in users:
        user.role = default_role
    
    db.commit()
    print(f"Assigned default role to {len(users)} users.")

def main():
    """Main function to seed RBAC data."""
    db = SessionLocal()
    try:
        # Seed permissions first
        seed_permissions(db)
        
        # Then seed roles (which depend on permissions)
        seed_roles(db)
        
        # Finally, assign default roles to existing users
        assign_default_roles(db)
        
        print("\nRBAC data seeding completed successfully!")
    except Exception as e:
        print(f"\nError seeding RBAC data: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    main()

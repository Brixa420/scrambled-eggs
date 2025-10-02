"""Initialize the database with tables and initial data."""

import asyncio
import os
import sys
from pathlib import Path

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.base import Base
from app.db.session import async_engine, async_session_factory


async def create_tables() -> None:
    """Create database tables."""
    print("Creating database tables...")
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables created successfully!")


async def run_migrations() -> None:
    """Run database migrations."""
    print("Running database migrations...")
    # For now, we'll just create tables directly
    # In production, you would run: os.system("alembic upgrade head")
    await create_tables()


async def create_initial_data() -> None:
    """Create initial data in the database."""
    print("Creating initial data...")
    async with async_session_factory() as session:
        # Create default roles
        from app.db.models import Role, Permission
        
        # Check if roles already exist
        result = await session.execute(text("SELECT COUNT(*) FROM roles"))
        if result.scalar() == 0:
            # Create default roles
            admin_role = Role(
                name="admin",
                description="Administrator with full access",
                is_default=False
            )
            user_role = Role(
                name="user",
                description="Regular user",
                is_default=True
            )
            session.add_all([admin_role, user_role])
            await session.commit()
            
            # Create some basic permissions
            permissions = [
                Permission(name="users:read", description="View users"),
                Permission(name="users:write", description="Modify users"),
                Permission(name="messages:read", description="Read messages"),
                Permission(name="messages:write", description="Send messages"),
                Permission(name="admin:access", description="Access admin panel"),
            ]
            session.add_all(permissions)
            await session.commit()
            
            # Assign all permissions to admin role
            admin_role = await session.get(Role, admin_role.id)
            for perm in permissions:
                admin_role.permissions.append(perm)
            
            # Assign basic permissions to user role
            user_role = await session.get(Role, user_role.id)
            for perm in permissions:
                if perm.name in ["users:read", "messages:read", "messages:write"]:
                    user_role.permissions.append(perm)
            
            await session.commit()
            print("Created default roles and permissions")
        else:
            print("Roles already exist, skipping...")


async def create_admin_user() -> None:
    """Create an admin user if one doesn't exist."""
    from app.core.security import get_password_hash
    from app.db.models import User, Role
    
    async with async_session_factory() as session:
        # Check if admin user already exists
        result = await session.execute(
            text("SELECT id FROM users WHERE username = 'admin'")
        )
        if result.scalar() is None:
            # Get admin role
            result = await session.execute(
                text("SELECT id FROM roles WHERE name = 'admin'")
            )
            admin_role_id = result.scalar()
            
            if not admin_role_id:
                print("Admin role not found. Please run migrations first.")
                return
            
            # Create admin user
            admin_user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=get_password_hash("admin"),
                is_active=True,
                is_verified=True,
            )
            session.add(admin_user)
            await session.flush()  # To get the user ID
            
            # Assign admin role
            await session.execute(
                text("""
                    INSERT INTO user_roles (user_id, role_id, assigned_at)
                    VALUES (:user_id, :role_id, NOW())
                """),
                {"user_id": admin_user.id, "role_id": admin_role_id}
            )
            
            await session.commit()
            print("Created admin user with username 'admin' and password 'admin'")
            print("IMPORTANT: Change the default password after first login!")
        else:
            print("Admin user already exists")


async def init_db() -> None:
    """Initialize the database."""
    try:
        # Create tables
        await create_tables()
        
        # Run migrations
        await run_migrations()
        
        # Create initial data
        await create_initial_data()
        
        # Create admin user
        await create_admin_user()
        
        print("\nDatabase initialization complete!")
        print("You can now start the application with:")
        print("  python -m uvicorn app.main:app --reload")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise


if __name__ == "__main__":
    print("Initializing database...")
    asyncio.run(init_db())

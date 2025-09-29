"""
Database setup and admin user creation script.
"""
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

# Add the app directory to the Python path
sys.path.append('.')

from app.db.base import Base, engine, SessionLocal
from app.models.user import User

def init_db():
    """Initialize the database and create tables."""
    try:
        print("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
        return True
    except Exception as e:
        print(f"❌ Error creating database tables: {e}")
        return False

def create_admin_user():
    """Create an admin user if one doesn't exist."""
    db = SessionLocal()
    try:
        # Check if admin user already exists
        admin = db.query(User).filter(User.username == 'admin').first()
        if admin:
            print("ℹ️ Admin user already exists")
            return False
            
        # Create admin user
        pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
        admin = User(
            username='admin',
            email='admin@example.com',
            hashed_password=pwd_context.hash('admin123'),
            is_superuser=True,
            is_active=True
        )
        db.add(admin)
        db.commit()
        print("✅ Admin user created successfully!")
        print("   Username: admin")
        print("   Password: admin123")
        print("\n⚠️  IMPORTANT: Change the default password after first login!")
        return True
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error creating admin user: {e}")
        return False
    finally:
        db.close()

if __name__ == "__main__":
    print("=== Scrambled Eggs Database Setup ===\n")
    
    # Initialize database
    if not init_db():
        sys.exit(1)
        
    # Create admin user
    print("\nSetting up admin user...")
    create_admin_user()
    
    print("\nSetup complete! You can now start the application.")
    print("To start the development server, run:")
    print("  python -m uvicorn app.main:app --reload")

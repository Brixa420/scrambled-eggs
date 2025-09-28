"""
Database migration script for Scrambled Eggs.
Run this script to initialize and apply database migrations.
"""
import os
from web_app import create_app
from app.extensions import db, migrate

def init_migrations():
    """Initialize the database migrations."""
    app = create_app()
    
    with app.app_context():
        # Create migrations directory if it doesn't exist
        migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
        if not os.path.exists(migrations_dir):
            print("Initializing database migrations...")
            os.makedirs(migrations_dir, exist_ok=True)
            
            # Initialize the migration repository
            from flask_migrate import init as migrate_init
            migrate_init()
            print("Migration repository initialized.")
        
        # Create a new migration
        print("Creating database migration...")
        from flask_migrate import migrate as migrate_migrate
        migrate_migrate(message="Initial migration")
        
        # Apply the migration
        print("Applying database migration...")
        from flask_migrate import upgrade as migrate_upgrade
        migrate_upgrade()
        
        print("Database migration completed successfully!")

if __name__ == '__main__':
    init_migrations()

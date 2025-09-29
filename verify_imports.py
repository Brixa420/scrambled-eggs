"""
Script to verify that all necessary imports are working correctly.
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("Python path:")
for path in sys.path:
    print(f"  - {path}")

print("\nTesting imports...")

try:
    # Test importing the encryption service
    print("\n1. Testing encryption service import...")
    from app.services.encryption import crypto

    print("✅ Successfully imported encryption service")

    # Test importing Flask and extensions
    print("\n2. Testing Flask and extensions...")
    from flask import Flask
    from flask_migrate import Migrate
    from flask_sqlalchemy import SQLAlchemy

    print("✅ Successfully imported Flask and extensions")

    # Test importing models
    print("\n3. Testing models import...")
    from app.models import AuditLog, Session, User, db

    print("✅ Successfully imported models")

    # Test creating a basic Flask app
    print("\n4. Testing Flask app creation...")
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)

    # Create all tables
    with app.app_context():
        db.create_all()
        print("✅ Successfully created database tables")

    print("\n🎉 All tests passed!")

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\nTroubleshooting steps:")
    print("1. Make sure you're running from the project root")
    print("2. Check that the app package is in your Python path")
    print("3. Verify all dependencies are installed")

except Exception as e:
    print(f"❌ An error occurred: {e}")
    raise

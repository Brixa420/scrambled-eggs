"""
Check that all required imports are working correctly.
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_import(module_name, import_name=None):
    """Test if a module can be imported."""
    try:
        if import_name is None:
            import_name = module_name
        __import__(module_name)
        print(f"✅ Successfully imported {import_name}")
        return True
    except ImportError as e:
        print(f"❌ Failed to import {import_name}: {e}")
        return False
    except Exception as e:
        print(f"❌ Error importing {import_name}: {e}")
        return False


print("=== Testing Core Dependencies ===")
test_import("flask")
test_import("flask_sqlalchemy")
test_import("flask_migrate")
test_import("flask_login")
test_import("cryptography")
test_import("python_dotenv")

print("\n=== Testing Application Imports ===")

# Test importing from our app
try:
    from app import create_app

    print("✅ Successfully imported create_app from app")
except Exception as e:
    print(f"❌ Failed to import create_app from app: {e}")

try:
    from app.models import db

    print("✅ Successfully imported db from app.models")
except Exception as e:
    print(f"❌ Failed to import from app.models: {e}")

try:
    from app.services.encryption import crypto

    print("✅ Successfully imported crypto from app.services.encryption")
except Exception as e:
    print(f"❌ Failed to import from app.services.encryption: {e}")

print("\n=== Testing Database Setup ===")
try:
    from app.extensions import db as ext_db

    print("✅ Successfully imported db from app.extensions")

    # Test creating a minimal Flask app
    from flask import Flask

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize SQLAlchemy
    ext_db.init_app(app)

    # Test creating tables
    with app.app_context():
        ext_db.create_all()
        print("✅ Successfully created database tables")

except Exception as e:
    print(f"❌ Database setup test failed: {e}")

print("\n=== Import Check Complete ===")
print("\nIf you see any ❌ errors above, please install the missing dependencies using:")
print("pip install -r requirements.txt")

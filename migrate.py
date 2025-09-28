"""
Database migration manager for the Scrambled Eggs application.
"""
import os
import sys
import click
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade, migrate as migrate_db, init, stamp

# Create a minimal Flask app
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///app.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.urandom(24).hex()
)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Import models after db initialization to avoid circular imports
from app.models import User, Session, AuditLog

@app.cli.command()
def init():
    """Initialize the database."""
    with app.app_context():
        # Create all database tables
        db.create_all()
        print("✅ Database tables created successfully!")
        print(f"Database location: {os.path.abspath('app.db')}")

@app.cli.command()
@click.argument('message')
def makemigrations(message):
    """Create a new database migration."""
    with app.app_context():
        # Initialize migrations if not already done
        migrations_dir = os.path.join(app.root_path, 'migrations')
        if not os.path.exists(migrations_dir):
            print("Initializing migrations...")
            init()
            stamp()
            print("Migrations initialized.")
        
        # Create new migration
        migrate_db(message=message)
        print(f"✅ Migration created: {message}")

@app.cli.command()
def upgrade_db():
    """Upgrade database to the latest revision."""
    with app.app_context():
        upgrade()
        print("✅ Database upgraded to the latest revision.")

@app.cli.command()
@click.argument('revision')
def downgrade(revision):
    """Downgrade database to a specific revision."""
    with app.app_context():
        from flask_migrate import downgrade as _downgrade
        _downgrade(revision)
        print(f"✅ Database downgraded to revision: {revision}")

if __name__ == '__main__':
    app.cli()

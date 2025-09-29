#!/usr/bin/env python
"""
Management script for the Scrambled Eggs application.
"""
import os
import sys

import click
from flask_migrate import Migrate, init
from flask_migrate import migrate as migrate_db
from flask_migrate import stamp, upgrade

from app.extensions import db
from web_app import create_app

app = create_app()
migrate = Migrate(app, db)

@app.cli.command()
def init_db():
    """Initialize the database."""
    with app.app_context():
        # Create all database tables
        db.create_all()
        print("Database tables created successfully.")

@app.cli.command()
@click.argument('message')
def db_migrate(message):
    ""
    Create a new database migration.
    
    Example:
        flask db_migrate "Add user table"
    """
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
        print(f"Migration created: {message}")

@app.cli.command()
def db_upgrade():
    """Upgrade database to the latest revision."""
    with app.app_context():
        upgrade()
        print("Database upgraded to the latest revision.")

@app.cli.command()
@click.argument('revision')
def db_downgrade(revision):
    """
    Downgrade database to a specific revision.
    
    Example:
        flask db_downgrade <revision>
    """
    with app.app_context():
        from flask_migrate import downgrade as _downgrade
        _downgrade(revision)
        print(f"Database downgraded to revision: {revision}")

if __name__ == '__main__':
    app.cli()

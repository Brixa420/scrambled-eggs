#!/usr/bin/env python3
"""
Scrambled Eggs - Server Setup Script

This script initializes the decentralized server with proper directory structure
and configuration. It should be run after cloning the repository.
"""
import os
import shutil
import secrets
import argparse
from pathlib import Path
from getpass import getpass

# Import config to access settings
from app.config import BASE_DIR

def generate_random_key(length=32):
    """Generate a secure random key."""
    return secrets.token_hex(length)

def setup_directories():
    """Create necessary directories with proper permissions."""
    directories = [
        'data/uploads',
        'data/temp',
        'backups',
        'logs',
        'tor/hidden_service',
        'tor/data',
        'plugins'
    ]
    
    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        print(f"Created directory: {path}")

def create_env_file(env_path='.env'):
    """Create a .env file with secure defaults if it doesn't exist."""
    if Path(env_path).exists():
        print(f"{env_path} already exists. Skipping creation.")
        return
    
    # Generate secure random values
    secret_key = generate_random_key()
    encryption_key = generate_random_key()
    jwt_secret = generate_random_key()
    csrf_secret = generate_random_key()
    tor_password = generate_random_key(16)  # Shorter password for Tor
    
    # Ask for admin credentials
    print("\n=== Admin Account Setup ===")
    admin_username = input("Admin username [admin]: ") or "admin"
    admin_email = input("Admin email [admin@example.com]: ") or "admin@example.com"
    
    while True:
        admin_password = getpass("Admin password (min 12 characters): ")
        if len(admin_password) >= 12:
            break
        print("Password must be at least 12 characters long.")
    
    # Read the example env file
    with open('.env.example', 'r') as f:
        env_content = f.read()
    
    # Replace placeholders
    env_content = env_content.replace('generate_a_secure_random_key_here', secret_key)
    env_content = env_content.replace('generate_a_secure_random_password_here', tor_password)
    env_content = env_content.replace('change_this_password', admin_password)
    
    # Write the new .env file
    with open(env_path, 'w') as f:
        f.write(env_content)
    
    # Set secure permissions
    os.chmod(env_path, 0o600)
    print(f"Created {env_path} with secure settings")

def setup_database():
    """Initialize the database."""
    print("\n=== Database Setup ===")
    try:
        from app.extensions import db
        from app import create_app
        
        app = create_app()
        with app.app_context():
            db.create_all()
            print("Database tables created successfully.")
    except Exception as e:
        print(f"Error setting up database: {e}")
        print("Please make sure the database server is running and the configuration is correct.")

def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description='Setup Scrambled Eggs server')
    parser.add_argument('--skip-db', action='store_true', help='Skip database setup')
    args = parser.parse_args()
    
    print("=== Scrambled Eggs Server Setup ===\n")
    
    # Create necessary directories
    print("Creating directories...")
    setup_directories()
    
    # Create .env file if it doesn't exist
    print("\nSetting up configuration...")
    create_env_file()
    
    # Initialize database
    if not args.skip_db:
        setup_database()
    
    print("\n=== Setup Complete ===")
    print("\nNext steps:")
    print("1. Review the configuration in the .env file")
    print("2. Start the server with: python run.py")
    print("3. Access the web interface at http://localhost:5000")
    print("\nFor production use, make sure to:")
    print("- Set DEBUG=False in .env")
    print("- Configure a proper database (e.g., PostgreSQL)")
    print("- Set up HTTPS with a valid certificate")
    print("- Configure proper firewall rules")

if __name__ == '__main__':
    main()

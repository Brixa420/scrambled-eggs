"""
Scrambled Eggs Production Setup Script

This script helps set up a production environment for Scrambled Eggs.
It performs the following tasks:
1. Environment validation
2. Database setup and migrations
3. Admin user creation
4. SSL certificate setup (if needed)
5. Service configuration
"""

import os
import secrets
import string
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def generate_random_key(length=32):
    """Generate a secure random key."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*(-_=+)"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def check_environment():
    """Check if required environment variables are set."""
    required_vars = [
        'SECRET_KEY', 'ENCRYPTION_KEY', 'JWT_SECRET_KEY',
        'DATABASE_URI', 'MAIL_USERNAME', 'MAIL_PASSWORD'
    ]
    
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        print(f"Error: Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)

def setup_database():
    """Set up the database and run migrations."""
    print("\n=== Setting up database ===")
    try:
        # Run database migrations
        subprocess.run(["flask", "db", "upgrade"], check=True)
        print("✓ Database migrations applied")
    except subprocess.CalledProcessError as e:
        print(f"✗ Database migration failed: {e}")
        sys.exit(1)

def create_admin_user():
    """Create an admin user if one doesn't exist."""
    print("\n=== Setting up admin user ===")
    from app import create_app, db
    from app.models.user import User
    
    app = create_app()
    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            from getpass import getpass
            print("No admin user found. Let's create one.")
            
            username = input("Admin username [admin]: ") or "admin"
            email = input("Admin email: ")
            password = getpass("Admin password: ")
            
            if not email or not password:
                print("✗ Email and password are required")
                sys.exit(1)
                
            admin = User(
                username=username,
                email=email,
                is_admin=True,
                is_active=True
            )
            admin.set_password(password)
            
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created")
        else:
            print("✓ Admin user already exists")

def setup_ssl():
    """Set up SSL certificates using Let's Encrypt if needed."""
    if not os.path.exists("/etc/letsencrypt/live"):
        print("\n=== SSL Certificate Setup ===")
        print("Let's Encrypt SSL certificate setup is recommended for production.")
        setup = input("Would you like to set up SSL now? (y/n): ").lower()
        
        if setup == 'y':
            domain = input("Enter your domain (e.g., example.com): ")
            email = input("Enter your email for Let's Encrypt notifications: ")
            
            try:
                # Stop Nginx if running
                subprocess.run(["systemctl", "stop", "nginx"], check=False)
                
                # Get certificate
                cmd = [
                    "certbot", "certonly", "--standalone",
                    "-d", domain,
                    "-d", f"www.{domain}",
                    "--non-interactive", "--agree-tos",
                    "--email", email
                ]
                subprocess.run(cmd, check=True)
                
                # Set up automatic renewal
                cron_cmd = f"0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q"
                with open("/etc/cron.d/certbot", "w") as f:
                    f.write(f"{cron_cmd}\n")
                
                print("\n✓ SSL certificate installed and auto-renewal configured")
                print(f"Certificate location: /etc/letsencrypt/live/{domain}/")
                
            except subprocess.CalledProcessError as e:
                print(f"✗ SSL certificate setup failed: {e}")
                print("You can set up SSL later by running: certbot --nginx")
        else:
            print("⚠ SSL setup skipped. HTTPS will not be available until SSL is configured.")
    else:
        print("\n✓ SSL certificates are already configured")

def setup_backups():
    """Set up automated database backups."""
    print("\n=== Setting up database backups ===")
    backup_dir = "/var/backups/scrambled-eggs"
    
    # Create backup directory
    os.makedirs(backup_dir, exist_ok=True)
    subprocess.run(["chown", "-R", "www-data:www-data", backup_dir], check=False)
    
    # Create backup script
    backup_script = f"""#!/bin/bash
# Backup script for Scrambled Eggs
# Automatically created on {}

BACKUP_DIR="{}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/scrambled-eggs_$TIMESTAMP.sql"

# Dump database
PGPASSWORD=$DB_PASSWORD pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Keep only the last 7 backups
find $BACKUP_DIR -name "scrambled-eggs_*.sql.gz" -type f | sort -r | tail -n +8 | xargs --no-run-if-empty rm --
""".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), backup_dir)
    
    with open("/usr/local/bin/backup-scrambled-eggs", "w") as f:
        f.write(backup_script)
    
    os.chmod("/usr/local/bin/backup-scrambled-eggs", 0o755)
    
    # Add to crontab
    cron_entry = "0 3 * * * /usr/local/bin/backup-scrambled-eggs"
    with open("/etc/cron.d/scrambled-eggs-backup", "w") as f:
        f.write(f"{cron_entry}\n")
    
    print("✓ Automated backups configured")
    print(f"Backup directory: {backup_dir}")

def setup_systemd():
    """Set up systemd service for the application."""
    print("\n=== Setting up systemd service ===")
    service_content = """[Unit]
Description=Scrambled Eggs Web Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/scrambled-eggs
Environment="PATH=/opt/scrambled-eggs/venv/bin"
ExecStart=/opt/scrambled-eggs/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 "app:create_app()"
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/scrambled-eggs.service", "w") as f:
        f.write(service_content)
    
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "scrambled-eggs"], check=True)
    subprocess.run(["systemctl", "start", "scrambled-eggs"], check=True)
    
    print("✓ Systemd service configured")
    print("  Start: systemctl start scrambled-eggs")
    print("  Stop:  systemctl stop scrambled-eggs")
    print("  Logs:  journalctl -u scrambled-eggs -f")

def main():
    print("""
╔══════════════════════════════════════════╗
║      Scrambled Eggs - Setup Wizard      ║
╚══════════════════════════════════════════╝
""")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root. Please use sudo.")
        sys.exit(1)
    
    # Check for .env file
    if not os.path.exists(".env"):
        print("Error: No .env file found. Please create one from .env.example")
        sys.exit(1)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    try:
        check_environment()
        setup_database()
        create_admin_user()
        setup_ssl()
        setup_backups()
        setup_systemd()
        
        print("\n✅ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Configure your web server (Nginx/Apache) to proxy to 127.0.0.1:5000")
        print("2. Set up monitoring (Prometheus/Grafana)")
        print("3. Test your backup and restore process")
        print("4. Set up log rotation")
        print("\nFor help, see the documentation at https://docs.scrambled-eggs.example.com")
        
    except Exception as e:
        print(f"\n❌ Setup failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

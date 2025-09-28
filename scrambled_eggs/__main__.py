"""
Scrambled Eggs - Secure P2P Messaging with HSM Support
-----------------------------------------------------
Main entry point for the Scrambled Eggs application.
"""
import sys
import asyncio
import argparse
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('scrambled_eggs.log')
    ]
)

logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scrambled Eggs - Secure P2P Messaging')
    
    # Global arguments
    parser.add_argument('--verbose', '-v', action='count', default=0,
                      help='Increase verbosity (can be used multiple times)')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # GUI command
    gui_parser = subparsers.add_parser('gui', help='Start the GUI application')
    
    # HSM command
    hsm_parser = subparsers.add_parser('hsm', help='Hardware Security Module commands')
    hsm_subparsers = hsm_parser.add_subparsers(dest='hsm_command', help='HSM command')
    
    # HSM list command
    hsm_list_parser = hsm_subparsers.add_parser('list', help='List available HSMs')
    
    # HSM connect command
    hsm_connect_parser = hsm_subparsers.add_parser('connect', help='Connect to an HSM')
    hsm_connect_parser.add_argument('hsm_id', help='ID of the HSM to connect to')
    
    # User management commands
    user_parser = subparsers.add_parser('user', help='User management commands')
    user_subparsers = user_parser.add_subparsers(dest='user_command', help='User command')
    
    # User create command
    user_create = user_subparsers.add_parser('create', help='Create a new user')
    user_create.add_argument('username', help='Username for the new user')
    user_create.add_argument('--admin', action='store_true', help='Make the user an admin')
    
    # User list command
    user_list = user_subparsers.add_parser('list', help='List all users')
    
    # User delete command
    user_delete = user_subparsers.add_parser('delete', help='Delete a user')
    user_delete.add_argument('username', help='Username to delete')
    user_delete.add_argument('--admin-username', required=True, help='Admin username')
    
    # User reset-password command
    user_reset = user_subparsers.add_parser('reset-password', help="Reset a user's password")
    user_reset.add_argument('username', help='Username to reset')
    
    return parser.parse_args()

async def run_hsm_cli(args):
    """Run the HSM command line interface."""
    # Import HSM-related functions
    from .hsm import list_hsms, test_hsm_connection
    
    if args.hsm_command == 'list':
        try:
            hsms = await list_hsms()
            if not hsms:
                print("No HSMs found")
                return 0
                
            print("\nAvailable HSMs:")
            print("-" * 80)
            for hsm in hsms:
                print(f"ID: {hsm['id']}")
                print(f"Type: {hsm['type']}")
                print(f"Status: {hsm['status']}")
                print("-" * 80)
            return 0
            
        except Exception as e:
            print(f"Error listing HSMs: {e}", file=sys.stderr)
            return 1
    elif args.hsm_command == 'connect':
        try:
            result = await test_hsm_connection(args.hsm_id)
            if result['success']:
                print(f"✅ Successfully connected to HSM {args.hsm_id}")
                return 0
            else:
                print(f"❌ Failed to connect to HSM {args.hsm_id}")
                print(f"Error: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"Error connecting to HSM: {e}", file=sys.stderr)
            return 1
    
    print("No valid HSM command specified. Use --help for usage.", file=sys.stderr)
    return 1

def run_gui():
    """Run the GUI application."""
    try:
        from PySide6.QtWidgets import QApplication
        from .gui.main_window import MainWindow
        
        app = QApplication(sys.argv)
        window = MainWindow(app)  # Pass the QApplication instance
        window.show()
        return app.exec()
    except ImportError as e:
        logger.error(f"PySide6 is required for the GUI. Error: {e}. Install with: pip install PySide6")
        return 1

def handle_user_command(args):
    """Handle user management commands."""
    from .user_management import UserManager
    import getpass
    
    user_manager = UserManager()
    
    if args.user_command == 'create':
        # Get password securely
        while True:
            password = getpass.getpass('Enter password: ')
            confirm = getpass.getpass('Confirm password: ')
            if password == confirm:
                break
            print("Passwords don't match. Try again.", file=sys.stderr)
        
        try:
            user = user_manager.create_user(
                username=args.username,
                password=password,
                is_admin=args.admin
            )
            print(f"User '{user.username}' created successfully!")
            if args.admin:
                print("  - This user has admin privileges")
            return 0
        except Exception as e:
            print(f"Error creating user: {e}", file=sys.stderr)
            return 1
    
    elif args.user_command == 'list':
        users = user_manager.list_users()
        if not users:
            print("No users found.")
            return 0
            
        # Print user table
        print(f"{'Username':<20} {'Admin':<6} {'Active':<6} {'Last Login':<25} {'Created At'}")
        print("-" * 80)
        for user in users:
            last_login = user.get('last_login', 'Never')
            if last_login and len(last_login) > 20:  # Truncate long timestamps
                last_login = last_login[:20]
            print(f"{user['username']:<20} "
                  f"{'Yes' if user['is_admin'] else 'No':<6} "
                  f"{'Yes' if user.get('is_active', True) else 'No':<6} "
                  f"{last_login:<25} "
                  f"{user['created_at']}")
        return 0
    
    elif args.user_command == 'delete':
        admin_password = getpass.getpass(f"Enter password for {args.admin_username}: ")
        if not user_manager.authenticate(args.admin_username, admin_password):
            print("Authentication failed.", file=sys.stderr)
            return 1
            
        if user_manager.delete_user(args.username, args.admin_username):
            print(f"User '{args.username}' deleted successfully!")
            return 0
        else:
            print(f"Failed to delete user '{args.username}'.", file=sys.stderr)
            return 1
    
    elif args.user_command == 'reset-password':
        admin_password = getpass.getpass(f"Enter password for {args.admin_username}: ")
        if not user_manager.authenticate(args.admin_username, admin_password):
            print("Authentication failed.", file=sys.stderr)
            return 1
        
        while True:
            new_password = getpass.getpass('Enter new password: ')
            confirm = getpass.getpass('Confirm new password: ')
            if new_password == confirm:
                break
            print("Passwords don't match. Try again.", file=sys.stderr)
        
        if user_manager.reset_password(
            args.username,
            new_password,
            args.admin_username
        ):
            print(f"Password for '{args.username}' has been reset.")
            return 0
        else:
            print(f"Failed to reset password for '{args.username}'.", file=sys.stderr)
            return 1
    
    else:
        print("Unknown user command. Use --help for usage.", file=sys.stderr)
        return 1

def main():
    """Main entry point."""
    try:
        args = parse_arguments()
        
        # Set log level based on verbosity
        if args.verbose >= 2:
            logging.getLogger().setLevel(logging.DEBUG)
        elif args.verbose == 1:
            logging.getLogger().setLevel(logging.INFO)
        
        # Execute the appropriate command
        if args.command == 'gui':
            return run_gui()
        elif args.command == 'hsm':
            return asyncio.run(run_hsm_cli(args))
        elif args.command == 'user':
            return handle_user_command(args)
        else:
            print("No command specified. Use --help for usage information.")
            return 1
            
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=args.verbose > 0 if 'args' in locals() else False)
        return 1

if __name__ == "__main__":
    sys.exit(main())
